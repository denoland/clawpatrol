package endpoints

// ssh endpoint: schema, plugin registration, and the wire-protocol
// gateway that terminates SSH on both sides. The gateway acts as an
// SSH server toward the agent (accepting any auth — WireGuard is the
// trust boundary) and an SSH client toward the upstream, replaying
// the credential's user/key/password to authenticate. Channels and
// global requests are spliced both directions, so interactive
// sessions, exec, port forwarding, and SFTP all "just work".
//
// ssh-family rules gate the channel envelope: each agent action
// (exec / shell / subsystem channel-request, direct-tcpip open) is
// run through runtime.MatchRequest against the ssh facet
// (config/plugins/facets/ssh) before it is forwarded upstream, and a
// deny refuses that channel without tearing down the whole session.
// The facet sees the action verb / command / subsystem / forward
// target — not the bytes inside an open channel, so it can block all
// of `git-receive-pack` but cannot single out a force push.
//
// Endpoint shape:
//
//   endpoint "ssh" "build-host" {
//     hosts      = ["build.example.com:2222"]
//     credential = build-host-cred
//   }
//
// SSH carries no SNI / Host header, so we can't disambiguate at TCP
// accept time. The dnsvip package gives every SSH-able hostname a
// virtual IP from a private range and answers agent DNS queries with
// that IP; when the conn lands on the VIP, dispatch consults the
// VIP table to recover the hostname (and thus the endpoint).
//
// The gateway-side host key is per-endpoint, persisted in the host's
// BlobStore under kind="ssh_host_key", name=<endpoint name>
// (lazy-generated ed25519 on first use). Operators add the printed
// fingerprint to their known_hosts so `ssh user@hostname` doesn't
// prompt.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/crypto/ssh"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	sshfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/ssh"
	"github.com/denoland/clawpatrol/internal/config/plugins/sshproto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// SSHEndpoint binds one or more host:port tuples. The credentials
// that authenticate against it live on credential blocks via the
// framework-level `endpoint = X` / `endpoints = [...]` binding. When
// a profile wields more than one SSH credential at the endpoint,
// each ambiguous credential carries a `user = "..."` disambiguator —
// either on its profile-inline entry (`{ credential = X, user = "..." }`)
// or on the credential block itself — and the agent's wire-protocol
// username picks the matching entry. The agent's username is also
// passed through verbatim as the upstream SSH user; credentials
// carry only auth material (key / password / host_pubkey), never a
// username override.
type SSHEndpoint struct {
	// Hosts is the set of SSH host:port pairs this endpoint intercepts.
	Hosts []string `hcl:"hosts"`
}

// EndpointHosts is part of the clawpatrol plugin API.
func (e *SSHEndpoint) EndpointHosts() []string { return e.Hosts }

// ConnRouteHosts implements runtime.ConnRouter — gives the gateway's
// IP-keyed dispatch index a chance to route direct-IP dialers (an
// agent that bypasses DNS) back to the same endpoint. The VIP path
// in dnsvip is the primary route; this is the safety net.
func (e *SSHEndpoint) ConnRouteHosts() []string { return e.Hosts }

// RequiresVIP marks the endpoint as needing a DNS-MitM virtual IP.
// SSH always returns true: the wire protocol can't be disambiguated
// at TCP accept time, so even a single SSH endpoint benefits from a
// dedicated VIP (avoids ambiguity if the operator later adds a
// second one behind the same upstream IP).
func (e *SSHEndpoint) RequiresVIP() bool { return true }

// SSHEndpointRuntime is stateful only in the host-key cache: each
// endpoint's persisted ed25519 key is parsed once and reused for the
// lifetime of the process. The runtime struct itself is shared
// across all SSH endpoints — config dispatch picks the right
// endpoint via ch.Endpoint.
type SSHEndpointRuntime struct {
	keyCache sync.Map // endpoint name → ssh.Signer
}

func init() {
	rt := &SSHEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "ssh",
		Family:   "ssh",
		New:      func() any { return &SSHEndpoint{} },
		Runtime:  rt,
		Validate: hostsValidate,
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*SSHEndpoint)
			if len(e.Hosts) > 0 {
				vals := make([]cty.Value, len(e.Hosts))
				for i, h := range e.Hosts {
					vals[i] = cty.StringVal(h)
				}
				b.SetAttributeValue("hosts", cty.ListVal(vals))
			}
		},
	})
}

// Compile-time interface checks.
var (
	_ runtime.ConnEndpointRuntime = (*SSHEndpointRuntime)(nil)
	_ runtime.ConnRouter          = (*SSHEndpoint)(nil)
)

// ── HandleConn ────────────────────────────────────────────────────────

// HandleConn is part of the clawpatrol plugin API.
func (rt *SSHEndpointRuntime) HandleConn(ctx context.Context, ch *runtime.ConnHandle) error {
	defer func() { _ = ch.Conn.Close() }()
	if ch.Endpoint == nil || ch.Endpoint.Family != "ssh" {
		return fmt.Errorf("ssh runtime invoked on non-ssh endpoint %v", ch.Endpoint)
	}
	if ch.Blobs == nil {
		return fmt.Errorf("ssh runtime needs a BlobStore to persist host keys")
	}
	ep, ok := ch.Endpoint.Body.(*SSHEndpoint)
	if !ok {
		return fmt.Errorf("ssh endpoint %q body is %T, expected *SSHEndpoint", ch.Endpoint.Name, ch.Endpoint.Body)
	}

	// Step 1: load or mint the per-endpoint host key.
	hostKey, err := rt.hostKeyFor(ch.Endpoint.Name, ch.Blobs)
	if err != nil {
		return fmt.Errorf("host key for endpoint %q: %w", ch.Endpoint.Name, err)
	}

	// Step 2: pick the upstream host:port. If the endpoint has a
	// single host that's the easy case; with multiple, prefer the
	// one whose port matches the agent's destination port.
	upstreamAddr := pickUpstream(ep.Hosts, ch.DstPort)
	if upstreamAddr == "" {
		return fmt.Errorf("ssh endpoint %q has no host matching dst port %d", ch.Endpoint.Name, ch.DstPort)
	}

	// Step 3: agent-side server. Accept anything the client offers —
	// WG is the trust boundary, same model postgres uses for its
	// SCRAM-offload. The handshake also gives us the agent's
	// username, which we need before resolving the credential.
	//
	// NoClientAuth advertises the `none` userauth method so a plain
	// `ssh user@host` with no key and no password just works —
	// without it the OpenSSH client falls through to publickey, then
	// password, and ends up prompting for a password it'll then
	// accept anything for, which is gratuitously confusing. The
	// PasswordCallback / PublicKeyCallback below stay in place so
	// clients that DO offer credentials still succeed (they just
	// aren't required to).
	srvCfg := &ssh.ServerConfig{
		NoClientAuth: true,
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
		ServerVersion: "SSH-2.0-clawpatrol",
	}
	srvCfg.AddHostKey(hostKey)

	srvConn, srvChans, srvReqs, err := ssh.NewServerConn(ch.Conn, srvCfg)
	if err != nil {
		return fmt.Errorf("ssh server handshake: %w", err)
	}
	defer func() { _ = srvConn.Close() }()

	agentUser := srvConn.User()
	if agentUser == "" {
		return fmt.Errorf("agent did not specify a username")
	}

	// Step 4: pick the credential for this username and build the
	// upstream SSH client config. Per-username dispatch lives on the
	// endpoint via `credentials = [{user=..., credential=...}, ...]`;
	// the singular `credential = X` form collapses to a one-entry list
	// with empty Placeholder (catchall).
	cc := pickSSHCredential(ch.Policy, ch.Profile, ch.Endpoint, agentUser)
	if cc == nil {
		return fmt.Errorf("ssh endpoint %q has no credential matching agent user %q", ch.Endpoint.Name, agentUser)
	}
	upstreamCfg, err := rt.upstreamClientConfig(ch, cc, agentUser)
	if err != nil {
		return fmt.Errorf("ssh credential %q: %w", cc.Credential.Symbol.Name, err)
	}

	// Step 5: dial upstream and do the client handshake. DialUpstream
	// takes a real hostname:port and resolves it on the gateway's
	// network (NOT inside the WG netstack), so the gateway's normal
	// DNS path applies — the VIP only exists inside the tunnel.
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	upConn, err := ch.DialUpstream(dialCtx, "tcp", upstreamAddr)
	if err != nil {
		return fmt.Errorf("dial upstream %s: %w", upstreamAddr, err)
	}
	defer func() { _ = upConn.Close() }()

	clientConn, clientChans, clientReqs, err := ssh.NewClientConn(upConn, upstreamAddr, upstreamCfg)
	if err != nil {
		return fmt.Errorf("ssh client handshake to %s: %w", upstreamAddr, err)
	}
	defer func() { _ = clientConn.Close() }()

	emit := func(ev runtime.ConnEvent) {
		if ch.Emit != nil {
			ch.Emit(ev)
		}
	}
	emit(runtime.ConnEvent{
		Action:  "allow",
		Verb:    "connect",
		Summary: fmt.Sprintf("%s@%s", agentUser, upstreamAddr),
	})

	// gate evaluates one ssh-family rule decision per channel action
	// (exec / shell / subsystem / direct-tcpip), emitting the verdict
	// event and reporting whether the action must be refused. It
	// mirrors the postgres per-statement path: build a match.Request,
	// run MatchRequest, honor an approve chain through ch.Approve, and
	// default-deny an approve-gated action when HITL isn't wired.
	gate := rt.makeGate(ch, emit, agentUser, cc.Credential.Symbol.Name)
	agentHooks := sshHooks{emit: emit, gate: gate}

	// Step 6: bidirectional pump. Two waitgroups — `dispatch` covers
	// the four conn-level demuxers (channel + global-request feeds);
	// `chans` covers each individual proxyChannel goroutine spawned
	// by the channel demuxers. Tracking the channel proxies separately
	// is what makes graceful close possible: when one SSH conn dies
	// we close the other only after all in-flight channel proxies
	// have drained, so a fast `ssh host echo hi` doesn't lose its
	// final bytes when the upstream half tears down (visible as ~10%
	// blank-output flake when running tests in tight succession).
	//
	// Only the agent→upstream channel pump gets the hooks: we gate
	// and log user intent (exec / shell / subsystem / direct-tcpip
	// target) and log upstream replies (exit-status), but never gate
	// the rare upstream-originated X11 / forwarded-tcpip openings (a
	// zero sshHooks leaves them spliced verbatim).
	var dispatch, chans sync.WaitGroup
	dispatch.Add(4)
	go func() { defer dispatch.Done(); pumpChannels(clientConn, srvChans, &chans, agentHooks) }()
	go func() { defer dispatch.Done(); pumpChannels(srvConn, clientChans, &chans, sshHooks{}) }()
	go func() { defer dispatch.Done(); pumpGlobalReqs(clientConn, srvReqs) }()
	go func() { defer dispatch.Done(); pumpGlobalReqs(srvConn, clientReqs) }()

	// Wait for either half to drop.
	exit := make(chan struct{}, 2)
	go func() { _ = srvConn.Wait(); exit <- struct{}{} }()
	go func() { _ = clientConn.Wait(); exit <- struct{}{} }()
	<-exit
	// Drain in-flight channel proxies — proxyChannel handles its own
	// teardown gracefully (forwards exit-status, then Closes) so by
	// the time chans.Wait() returns every byte that was going to flow
	// has flowed.
	chans.Wait()
	_ = srvConn.Close()
	_ = clientConn.Close()
	dispatch.Wait()
	return nil
}

// ── Credential dispatch + upstream auth ──────────────────────────────

// pickSSHCredential resolves the agent username to a
// CompiledCredential within the dispatching profile. The per-profile
// EndpointCredentials list carries (credential, disambiguator-map)
// entries; for ssh the disambiguator field is "user". Profiles that
// bind a single credential to ep return that entry; profiles that
// bind multiple credentials match the entry whose Disambiguators["user"]
// equals agentUser, with the no-user entry (if any) as the catchall.
//
// Returns nil when the profile binds no credential to ep — the
// caller refuses the connection rather than silently routing through
// a credential not meant for the user.
func pickSSHCredential(policy *config.CompiledPolicy, profile string, ep *config.CompiledEndpoint, agentUser string) *config.CompiledCredential {
	if ep == nil || policy == nil {
		return nil
	}
	prof, ok := policy.Profiles[profile]
	if !ok {
		return nil
	}
	entries := prof.EndpointCredentials[ep.Name]
	if len(entries) == 0 {
		return nil
	}
	if len(entries) == 1 && len(entries[0].Disambiguators) == 0 {
		return entries[0]
	}
	var fallback *config.CompiledCredential
	for _, c := range entries {
		want := c.Disambiguators["user"]
		if want == "" {
			fallback = c
			continue
		}
		if agentUser == want {
			return c
		}
	}
	return fallback
}

func (rt *SSHEndpointRuntime) upstreamClientConfig(ch *runtime.ConnHandle, cc *config.CompiledCredential, agentUser string) (*ssh.ClientConfig, error) {
	auth, ok := cc.Credential.Body.(sshproto.AuthCredential)
	if !ok {
		return nil, fmt.Errorf("does not implement sshproto.AuthCredential (use credential type \"ssh\")")
	}
	sec, err := ch.Secrets.Get(cc.Credential.Symbol.Name)
	if err != nil {
		return nil, fmt.Errorf("fetch secret: %w", err)
	}
	creds, err := auth.SSHAuth(sec)
	if err != nil {
		return nil, err
	}

	var methods []ssh.AuthMethod
	if len(creds.PrivateKey) > 0 {
		var signer ssh.Signer
		if creds.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(creds.PrivateKey, []byte(creds.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(creds.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("parse private_key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if creds.Password != "" {
		methods = append(methods, ssh.Password(creds.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("neither private_key nor password set — paste one via the dashboard")
	}

	hostKeyCb, err := buildHostKeyCallback(creds.HostPubkey, ch.Endpoint.Name)
	if err != nil {
		return nil, fmt.Errorf("parse host_pubkey: %w", err)
	}

	return &ssh.ClientConfig{
		User:            agentUser,
		Auth:            methods,
		HostKeyCallback: hostKeyCb,
		Timeout:         30 * time.Second,
		ClientVersion:   "SSH-2.0-clawpatrol",
	}, nil
}

// buildHostKeyCallback returns a HostKeyCallback that pins to the
// supplied authorized_keys-style line, or — when no pin is set —
// accepts anything with a one-time warning logged per endpoint
// (WG already encrypts the path between agent and gateway, but the
// gateway-to-upstream segment is over the host's internet uplink
// and benefits from a pin).
func buildHostKeyCallback(hostPubkey, endpointName string) (ssh.HostKeyCallback, error) {
	if hostPubkey == "" {
		warnHostKeyOnce(endpointName)
		return ssh.InsecureIgnoreHostKey(), nil
	}
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostPubkey))
	if err != nil {
		return nil, err
	}
	pinned := pubkey.Marshal()
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		if !bytes.Equal(key.Marshal(), pinned) {
			return fmt.Errorf("upstream host key for %s does not match credential's pin", hostname)
		}
		return nil
	}, nil
}

var hostKeyWarnOnce sync.Map // endpoint name → struct{}

func warnHostKeyOnce(endpointName string) {
	if _, loaded := hostKeyWarnOnce.LoadOrStore(endpointName, struct{}{}); loaded {
		return
	}
	log.Printf("ssh: endpoint %q has no host_pubkey pin; trusting upstream host key blindly", endpointName)
}

// ── Channel + request pumps ───────────────────────────────────────────

// sshHooks bundles the per-action logging + gating callbacks the
// agent→upstream pump carries. The upstream→agent pump passes a zero
// sshHooks: those channels (X11 / forwarded-tcpip) are spliced
// verbatim, neither gated nor logged.
//
// gate evaluates an ssh-family rule decision against the action's
// derived Meta and returns (deny, reason); it emits the verdict event
// itself, so a gated action is never double-logged through emit. emit
// remains for the pure-logging path (upstream exit-status).
type sshHooks struct {
	emit func(runtime.ConnEvent)
	gate func(*sshfacet.Meta) (bool, string)
}

// pumpChannels accepts incoming channel-open requests from one side
// and opens the same type on the other. Each successful pair runs
// proxyChannel (tracked via wg so HandleConn can drain in-flight
// channels before closing the SSH conns).
//
// When hooks.gate is set (agent→upstream direction) a direct-tcpip
// open is gated at channel-open time — the only point its forward
// target is known, since it carries no follow-up channel-request —
// and a denied forward is rejected before the upstream channel is
// opened. Session opens carry no gateable metadata themselves; their
// intent rides on the following exec / shell / subsystem request,
// gated inside proxyChannel.
func pumpChannels(target ssh.Conn, source <-chan ssh.NewChannel, wg *sync.WaitGroup, hooks sshHooks) {
	for newCh := range source {
		if hooks.gate != nil {
			if m, ok := metaForChannelOpen(newCh); ok {
				if deny, reason := hooks.gate(m); deny {
					_ = newCh.Reject(ssh.Prohibited, reason)
					continue
				}
			}
		}
		targetCh, targetReqs, err := target.OpenChannel(newCh.ChannelType(), newCh.ExtraData())
		if err != nil {
			var ocErr *ssh.OpenChannelError
			if errors.As(err, &ocErr) {
				_ = newCh.Reject(ocErr.Reason, ocErr.Message)
			} else {
				_ = newCh.Reject(ssh.ConnectionFailed, err.Error())
			}
			continue
		}
		sourceCh, sourceReqs, err := newCh.Accept()
		if err != nil {
			_ = targetCh.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxyChannel(sourceCh, sourceReqs, targetCh, targetReqs, hooks)
		}()
	}
}

// proxyChannel splices two ssh.Channels in both directions
// (stdout/stdin AND stderr) plus their per-channel request streams.
//
// Each "direction" is the pair (data pump, request forwarder) that
// reads from one side and writes to the other. A direction is
// COMPLETE when its source has been fully drained — both the channel
// data buffer (read until EOF) AND the request stream (read until
// closed, which happens only after channel-close, which the peer
// sends AFTER any final exit-status / signal). So when a direction
// completes, we know every byte and every request has been forwarded.
//
// Whichever direction completes first triggers a Close on the OTHER
// side's channel: that unsticks the slower direction's data pump,
// which would otherwise block forever on a peer that left its stdin
// open (notably the OpenSSH client during `ssh host cmd`). Closing
// only the OTHER side keeps the now-finished direction's bytes
// intact — closing too eagerly would cut off in-flight reads on the
// fast side and lose the last few bytes of output (~10% flake rate
// in `ssh host echo X` stress tests).
func proxyChannel(a ssh.Channel, aReqs <-chan *ssh.Request, b ssh.Channel, bReqs <-chan *ssh.Request, hooks sshHooks) {
	// pumpDir copies both stdout and stderr from src to dst, then
	// emits channel-eof. Combining the two before CloseWrite is
	// required: stderr is just extended-data on the same channel,
	// and SSH treats any extended-data after channel-eof as a
	// protocol violation. Without this, OpenSSH disconnects with
	// "Received extended_data after EOF on channel 0" the moment
	// the remote process exits with anything on stderr.
	pumpDir := func(dst, src ssh.Channel, done chan<- struct{}) {
		defer close(done)
		var inner sync.WaitGroup
		inner.Add(2)
		go func() { defer inner.Done(); _, _ = io.Copy(dst, src) }()
		go func() { defer inner.Done(); _, _ = io.Copy(dst.Stderr(), src.Stderr()) }()
		inner.Wait()
		_ = dst.CloseWrite()
	}

	// forwardAgentReqs carries agent→upstream channel requests (exec /
	// shell / subsystem). When hooks.gate denies one it replies
	// failure to the agent and closes BOTH halves to end the session:
	// the request is never forwarded upstream, and since a bare
	// session channel is inert until an exec/shell/subsystem request
	// arrives, nothing runs on the upstream side. The gate emits the
	// deny event itself.
	forwardAgentReqs := func(self, peer ssh.Channel, source <-chan *ssh.Request, done chan<- struct{}) {
		defer close(done)
		for r := range source {
			if hooks.gate != nil {
				if m, ok := metaForChannelReq(r); ok {
					// reason already surfaced via the gate's emitted
					// deny event; the agent just sees request failure.
					if deny, _ := hooks.gate(m); deny {
						if r.WantReply {
							_ = r.Reply(false, nil)
						}
						_ = self.Close()
						_ = peer.Close()
						return
					}
				}
			}
			ok, err := peer.SendRequest(r.Type, r.WantReply, r.Payload)
			if err != nil {
				ok = false
			}
			if r.WantReply {
				_ = r.Reply(ok, nil)
			}
		}
	}

	// forwardUpstreamReqs carries upstream→agent channel requests; the
	// only one surfaced is exit-status — pure logging, never gated.
	forwardUpstreamReqs := func(peer ssh.Channel, source <-chan *ssh.Request, done chan<- struct{}) {
		defer close(done)
		for r := range source {
			if hooks.emit != nil {
				if ev, ok := classifyUpstreamChannelReq(r); ok {
					hooks.emit(ev)
				}
			}
			ok, err := peer.SendRequest(r.Type, r.WantReply, r.Payload)
			if err != nil {
				ok = false
			}
			if r.WantReply {
				_ = r.Reply(ok, nil)
			}
		}
	}

	pumpA := make(chan struct{}) // upstream→agent data finished
	pumpB := make(chan struct{}) // agent→upstream data finished
	reqA := make(chan struct{})  // upstream→agent reqs finished
	reqB := make(chan struct{})  // agent→upstream reqs finished
	go pumpDir(a, b, pumpA)
	go pumpDir(b, a, pumpB)
	go forwardUpstreamReqs(a, bReqs, reqA)
	go forwardAgentReqs(a, b, aReqs, reqB)

	// fromUpstream / fromAgent fire when a full direction
	// (data + reqs) has drained — at that point its source channel
	// is fully closed and every byte/request has been forwarded.
	fromUpstream := make(chan struct{})
	fromAgent := make(chan struct{})
	go func() { <-pumpA; <-reqA; close(fromUpstream) }()
	go func() { <-pumpB; <-reqB; close(fromAgent) }()

	// Whichever direction finishes first closes the OPPOSITE side to
	// unstick its blocked pump. Then wait for the other direction.
	select {
	case <-fromUpstream:
		_ = a.Close()
	case <-fromAgent:
		_ = b.Close()
	}
	<-fromUpstream
	<-fromAgent
}

func pumpGlobalReqs(target ssh.Conn, source <-chan *ssh.Request) {
	for r := range source {
		if isProxyDroppedGlobalReq(r.Type) {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			continue
		}
		ok, payload, err := target.SendRequest(r.Type, r.WantReply, r.Payload)
		if err != nil {
			ok = false
			payload = nil
		}
		if r.WantReply {
			_ = r.Reply(ok, payload)
		}
	}
}

// isProxyDroppedGlobalReq names global requests we deliberately swallow
// at the gateway instead of forwarding. Currently just OpenSSH's
// UpdateHostKeys exchange (RFC draft, names below): the agent sees the
// gateway's per-endpoint host key, not the upstream's, and the
// signed-payload includes the SSH session id — which is necessarily
// different on the agent↔gateway and gateway↔upstream halves of a
// proxied conn. Forwarding the exchange transparently makes the OpenSSH
// client log "client_global_hostkeys_prove_confirm: server gave bad
// signature" because it's verifying upstream's signature against the
// agent-side session id. Dropping the request makes UpdateHostKeys
// silently no-op for proxied SSH — agents can't auto-rotate the
// gateway's known_hosts entry that way, but rotation of an
// MITM gateway's host key is an operator concern anyway, not something
// the upstream can usefully advertise.
func isProxyDroppedGlobalReq(name string) bool {
	switch name {
	case "hostkeys-00@openssh.com", "hostkeys-prove-00@openssh.com":
		return true
	}
	return false
}

// ── Per-channel rule evaluation + classification ─────────────────────

// SSH wire payload shapes we decode to derive an action's rule facets
// (and to log it) — never modify. Field names match the RFC
// declaration order so ssh.Unmarshal walks them correctly (it ignores
// struct tags and reads in order).
type (
	// RFC4254 §6.5.
	execPayload struct{ Command string }
	// RFC4254 §6.5.
	subsystemPayload struct{ Name string }
	// RFC4254 §6.10.
	exitStatusPayload struct{ Status uint32 }
	// RFC4254 §7.2 — payload of a `direct-tcpip` channel's ExtraData.
	directTCPIPPayload struct {
		DestHost   string
		DestPort   uint32
		OriginHost string
		OriginPort uint32
	}
)

// makeGate builds the per-action rule evaluator HandleConn hands to
// the agent→upstream pump. Each call evaluates one ssh-family
// match.Request and returns (deny, reason); it emits the verdict
// event (allow / deny / approved / denied) so callers only act on the
// boolean. Mirrors the postgres per-statement decision path
// (endpoints/postgres.go): MatchRequest, then an approve chain via
// ch.Approve with a default-deny when HITL isn't configured.
func (rt *SSHEndpointRuntime) makeGate(ch *runtime.ConnHandle, emit func(runtime.ConnEvent), agentUser, credName string) func(*sshfacet.Meta) (bool, string) {
	return func(m *sshfacet.Meta) (bool, string) {
		if m.User == "" {
			m.User = agentUser
		}
		req := &match.Request{
			Family:     "ssh",
			PeerIP:     ch.PeerIP,
			Credential: credName,
			User:       agentUser,
			Meta:       m,
		}
		var facets map[string]any
		if f := facet.Lookup("ssh"); f != nil {
			facets = f.Report(req)
		}
		summary := sshSummary(m)

		cr := runtime.MatchRequest(ch.Endpoint, req)
		if cr == nil {
			emit(runtime.ConnEvent{Action: "allow", Verb: m.Verb, Summary: summary, Facets: facets})
			return false, ""
		}
		rule := cr.Name

		if len(cr.Outcome.Approve) > 0 {
			if ch.Approve == nil {
				emit(runtime.ConnEvent{
					Action: "deny", Reason: "HITL not configured",
					Verb: m.Verb, Summary: summary, Facets: facets, Rule: rule,
				})
				return true, "approval required but HITL is not configured"
			}
			v := ch.Approve(runtime.ApproveCallRequest{
				Stages: cr.Outcome.Approve, Verb: m.Verb, Summary: summary, Rule: cr,
			})
			if v.Decision != "allow" {
				reason := v.Reason
				if reason == "" {
					reason = "denied by approver"
				}
				emit(runtime.ConnEvent{
					Action: "denied", Reason: reason,
					Verb: m.Verb, Summary: summary, Facets: facets, Rule: rule,
					Approver: v.ApproverName, ApproverType: v.ApproverType, ApproverBy: v.By,
				})
				return true, reason
			}
			emit(runtime.ConnEvent{
				Action: "approved", Verb: m.Verb, Summary: summary, Facets: facets, Rule: rule,
				Approver: v.ApproverName, ApproverType: v.ApproverType, ApproverBy: v.By,
			})
			return false, ""
		}

		if cr.Outcome.Verdict == "deny" {
			reason := cr.Outcome.Reason
			if reason == "" {
				reason = "denied by policy"
			}
			emit(runtime.ConnEvent{
				Action: "deny", Reason: reason,
				Verb: m.Verb, Summary: summary, Facets: facets, Rule: rule,
			})
			return true, reason
		}
		emit(runtime.ConnEvent{Action: "allow", Verb: m.Verb, Summary: summary, Facets: facets, Rule: rule})
		return false, ""
	}
}

// sshSummary is the human one-liner the dashboard / event log shows
// for an action, keyed off its verb.
func sshSummary(m *sshfacet.Meta) string {
	switch m.Verb {
	case sshfacet.VerbExec:
		return m.Command
	case sshfacet.VerbShell:
		return "interactive shell"
	case sshfacet.VerbSubsystem:
		return m.Subsystem
	case sshfacet.VerbForward:
		return fmt.Sprintf("→ %s:%d", m.ForwardHost, m.ForwardPort)
	}
	return ""
}

// metaForChannelOpen derives the rule facets for an agent-originated
// channel-open. Only `direct-tcpip` (port forwarding) carries a
// gateable target in its ExtraData; `session` opens are inert until
// their following exec / shell / subsystem request (handled by
// metaForChannelReq), so they produce no action here.
func metaForChannelOpen(newCh ssh.NewChannel) (*sshfacet.Meta, bool) {
	if newCh.ChannelType() != "direct-tcpip" {
		return nil, false
	}
	var d directTCPIPPayload
	if err := ssh.Unmarshal(newCh.ExtraData(), &d); err != nil {
		return nil, false
	}
	return &sshfacet.Meta{
		Verb:        sshfacet.VerbForward,
		ForwardHost: d.DestHost,
		ForwardPort: d.DestPort,
	}, true
}

// metaForChannelReq derives the rule facets for an agent→upstream
// channel request. exec carries the full argv as a single string;
// subsystem carries the subsystem name (e.g. "sftp"); shell carries
// no payload (interactive session start). Other request types
// (pty-req, env, window-change, signal, eow@openssh.com, ...) are
// session-keepalive noise — they produce no action and splice through
// ungated.
func metaForChannelReq(r *ssh.Request) (*sshfacet.Meta, bool) {
	switch r.Type {
	case "exec":
		var p execPayload
		if err := ssh.Unmarshal(r.Payload, &p); err != nil {
			return nil, false
		}
		return &sshfacet.Meta{Verb: sshfacet.VerbExec, Command: p.Command}, true
	case "shell":
		return &sshfacet.Meta{Verb: sshfacet.VerbShell}, true
	case "subsystem":
		var p subsystemPayload
		if err := ssh.Unmarshal(r.Payload, &p); err != nil {
			return nil, false
		}
		return &sshfacet.Meta{Verb: sshfacet.VerbSubsystem, Subsystem: p.Name}, true
	}
	return nil, false
}

// classifyUpstreamChannelReq turns an upstream→agent channel request
// into a log event. The interesting one is exit-status — pairs an
// earlier exec/shell event with its return code in the audit log.
// signal / exit-signal are rare and not surfaced for now.
func classifyUpstreamChannelReq(r *ssh.Request) (runtime.ConnEvent, bool) {
	if r.Type != "exit-status" {
		return runtime.ConnEvent{}, false
	}
	var p exitStatusPayload
	if err := ssh.Unmarshal(r.Payload, &p); err != nil {
		return runtime.ConnEvent{}, false
	}
	return runtime.ConnEvent{
		Action:  "allow",
		Verb:    "exit",
		Summary: fmt.Sprintf("exit %d", p.Status),
	}, true
}

// ── Host key persistence ──────────────────────────────────────────────

// SSHHostKeyKind is the BlobStore namespace for SSH endpoint host
// keys. Exported so the gateway's legacy-state importer can address
// the same rows when migrating on-disk <ca_dir>/ssh/<name>.key files
// into sqlite on first boot.
const SSHHostKeyKind = "ssh_host_key"

func (rt *SSHEndpointRuntime) hostKeyFor(endpointName string, blobs runtime.BlobStore) (ssh.Signer, error) {
	if v, ok := rt.keyCache.Load(endpointName); ok {
		return v.(ssh.Signer), nil
	}

	data, found, err := blobs.Get(SSHHostKeyKind, endpointName)
	if err != nil {
		return nil, fmt.Errorf("ssh host key get: %w", err)
	}
	if found {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse host key for %q: %w", endpointName, err)
		}
		rt.keyCache.Store(endpointName, signer)
		return signer, nil
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := blobs.Put(SSHHostKeyKind, endpointName, pemData); err != nil {
		return nil, fmt.Errorf("ssh host key put: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	log.Printf("ssh: minted host key for endpoint %q — fingerprint %s",
		endpointName, ssh.FingerprintSHA256(signer.PublicKey()))
	rt.keyCache.Store(endpointName, signer)
	return signer, nil
}

// pickUpstream picks the host:port from hosts that matches dstPort.
// When dstPort is 0 (direct dispatch with no port hint) or no host
// has a matching port, returns the first non-empty host.
func pickUpstream(hosts []string, dstPort uint16) string {
	if len(hosts) == 0 {
		return ""
	}
	if dstPort != 0 {
		want := fmt.Sprintf(":%d", dstPort)
		for _, h := range hosts {
			if strings.HasSuffix(h, want) {
				return h
			}
			// Bare hostname with default port 22.
			if dstPort == 22 && !strings.Contains(h, ":") {
				return h + ":22"
			}
		}
	}
	first := hosts[0]
	if !strings.Contains(first, ":") {
		first += ":22"
	}
	return first
}
