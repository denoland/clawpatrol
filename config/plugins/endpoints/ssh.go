package endpoints

// ssh endpoint: schema, plugin registration, and the wire-protocol
// gateway that terminates SSH on both sides. The gateway acts as an
// SSH server toward the agent (accepting any auth — WireGuard is the
// trust boundary) and an SSH client toward the upstream, replaying
// the credential's user/key/password to authenticate. Channels and
// global requests are spliced both directions, so interactive
// sessions, exec, port forwarding, and SFTP all "just work" without
// per-channel logic.
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
// The gateway-side host key is per-endpoint, persisted under
// <ca_dir>/ssh/<endpoint>.key (lazy-generated ed25519 on first use).
// Operators add the printed fingerprint to their known_hosts so
// `ssh user@hostname` doesn't prompt.

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/crypto/ssh"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// SSHEndpoint binds one or more host:port tuples to a single SSH
// credential. Multi-credential dispatch isn't supported in v1 — SSH
// has no convenient placeholder slot like postgres' StartupMessage
// password, so adding it would require a UX-affecting decision.
type SSHEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Credential string   `hcl:"credential,optional"`
}

func (e *SSHEndpoint) EndpointHosts() []string { return e.Hosts }
func (e *SSHEndpoint) EndpointCredentials() []config.CredBinding {
	return singleBinding(e.Credential)
}

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
		Kind:    config.KindEndpoint,
		Type:    "ssh",
		Family:  "ssh",
		New:     func() any { return &SSHEndpoint{} },
		Refs:    singularRef,
		Runtime: rt,
		Build:   passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*SSHEndpoint)
			if len(e.Hosts) > 0 {
				vals := make([]cty.Value, len(e.Hosts))
				for i, h := range e.Hosts {
					vals[i] = cty.StringVal(h)
				}
				b.SetAttributeValue("hosts", cty.ListVal(vals))
			}
			emitCredentialBinding(b, e.Credential, nil)
		},
	})
}

// Compile-time interface checks.
var (
	_ runtime.ConnEndpointRuntime = (*SSHEndpointRuntime)(nil)
	_ runtime.ConnRouter          = (*SSHEndpoint)(nil)
)

// ── HandleConn ────────────────────────────────────────────────────────

func (rt *SSHEndpointRuntime) HandleConn(ctx context.Context, ch *runtime.ConnHandle) error {
	defer ch.Conn.Close()
	if ch.Endpoint == nil || ch.Endpoint.Family != "ssh" {
		return fmt.Errorf("ssh runtime invoked on non-ssh endpoint %v", ch.Endpoint)
	}
	if ch.CADir == "" {
		return fmt.Errorf("ssh runtime needs CADir to persist host keys; gateway hasn't set ca_dir")
	}
	ep, ok := ch.Endpoint.Body.(*SSHEndpoint)
	if !ok {
		return fmt.Errorf("ssh endpoint %q body is %T, expected *SSHEndpoint", ch.Endpoint.Name, ch.Endpoint.Body)
	}

	// Step 1: load or mint the per-endpoint host key.
	hostKey, err := rt.hostKeyFor(ch.Endpoint.Name, ch.CADir)
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

	// Step 3: resolve credential and parse the auth material before
	// the SSH handshake, so we can fail loudly on the agent side
	// rather than after a successful client greeting.
	upstreamCfg, err := rt.upstreamClientConfig(ch, ep)
	if err != nil {
		return fmt.Errorf("ssh credential: %w", err)
	}

	// Step 4: agent-side server. Accept anything the client offers —
	// WG is the trust boundary, same model postgres uses for its
	// SCRAM-offload.
	srvCfg := &ssh.ServerConfig{
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
	defer srvConn.Close()

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
	defer upConn.Close()

	clientConn, clientChans, clientReqs, err := ssh.NewClientConn(upConn, upstreamAddr, upstreamCfg)
	if err != nil {
		return fmt.Errorf("ssh client handshake to %s: %w", upstreamAddr, err)
	}
	defer clientConn.Close()

	if ch.Emit != nil {
		ch.Emit(runtime.ConnEvent{
			Action:  "allow",
			Verb:    "ssh",
			Summary: fmt.Sprintf("%s@%s", upstreamCfg.User, upstreamAddr),
		})
	}

	// Step 6: bidirectional pump. Each side has a channel-open feed
	// and a global-request feed; we forward them across.
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); pumpChannels(clientConn, srvChans) }()
	go func() { defer wg.Done(); pumpChannels(srvConn, clientChans) }()
	go func() { defer wg.Done(); pumpGlobalReqs(clientConn, srvReqs) }()
	go func() { defer wg.Done(); pumpGlobalReqs(srvConn, clientReqs) }()

	// Wait for either half to drop.
	exit := make(chan struct{}, 2)
	go func() { _ = srvConn.Wait(); exit <- struct{}{} }()
	go func() { _ = clientConn.Wait(); exit <- struct{}{} }()
	<-exit
	srvConn.Close()
	clientConn.Close()
	wg.Wait()
	return nil
}

// ── Upstream auth ─────────────────────────────────────────────────────

func (rt *SSHEndpointRuntime) upstreamClientConfig(ch *runtime.ConnHandle, ep *SSHEndpoint) (*ssh.ClientConfig, error) {
	cred := ch.Endpoint.Credentials
	if len(cred) == 0 {
		return nil, fmt.Errorf("endpoint %q has no credential bound", ch.Endpoint.Name)
	}
	cc := cred[0]
	auth, ok := cc.Credential.Body.(runtime.SSHAuthCredential)
	if !ok {
		return nil, fmt.Errorf("credential %q does not implement SSHAuth (use credential type \"ssh\")", cc.Credential.Symbol.Name)
	}
	sec, err := ch.Secrets.Get(cc.Credential.Symbol.Name, ch.Profile)
	if err != nil {
		return nil, fmt.Errorf("fetch secret for %q: %w", cc.Credential.Symbol.Name, err)
	}
	creds, err := auth.SSHAuth(sec)
	if err != nil {
		return nil, err
	}
	if creds.User == "" {
		return nil, fmt.Errorf("credential %q has no user — set `user = ...` in HCL", cc.Credential.Symbol.Name)
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
			return nil, fmt.Errorf("parse private_key for credential %q: %w", cc.Credential.Symbol.Name, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if creds.Password != "" {
		methods = append(methods, ssh.Password(creds.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("credential %q has neither private_key nor password — paste one via the dashboard", cc.Credential.Symbol.Name)
	}

	hostKeyCb, err := buildHostKeyCallback(creds.HostPubkey, ch.Endpoint.Name)
	if err != nil {
		return nil, fmt.Errorf("parse host_pubkey for credential %q: %w", cc.Credential.Symbol.Name, err)
	}

	return &ssh.ClientConfig{
		User:            creds.User,
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
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
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

// pumpChannels accepts incoming channel-open requests from one side
// and opens the same type on the other. Each successful pair gets a
// data-copy goroutine in each direction plus a per-channel request
// pump in each direction.
func pumpChannels(target ssh.Conn, source <-chan ssh.NewChannel) {
	for newCh := range source {
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
			targetCh.Close()
			continue
		}
		go pumpChannelReqs(targetCh, sourceReqs)
		go pumpChannelReqs(sourceCh, targetReqs)
		go func(dst, src ssh.Channel) {
			_, _ = io.Copy(dst, src)
			_ = dst.CloseWrite()
		}(targetCh, sourceCh)
		go func(dst, src ssh.Channel) {
			_, _ = io.Copy(dst, src)
			_ = src.CloseWrite()
		}(sourceCh, targetCh)
		// Forward stderr too (channel extended-data type 1).
		go func(dst, src ssh.Channel) {
			_, _ = io.Copy(dst.Stderr(), src.Stderr())
		}(targetCh, sourceCh)
		go func(dst, src ssh.Channel) {
			_, _ = io.Copy(dst.Stderr(), src.Stderr())
		}(sourceCh, targetCh)
	}
}

func pumpChannelReqs(target ssh.Channel, source <-chan *ssh.Request) {
	for r := range source {
		ok, err := target.SendRequest(r.Type, r.WantReply, r.Payload)
		if err != nil {
			ok = false
		}
		if r.WantReply {
			_ = r.Reply(ok, nil)
		}
	}
}

func pumpGlobalReqs(target ssh.Conn, source <-chan *ssh.Request) {
	for r := range source {
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

// ── Host key persistence ──────────────────────────────────────────────

func (rt *SSHEndpointRuntime) hostKeyFor(endpointName, caDir string) (ssh.Signer, error) {
	if v, ok := rt.keyCache.Load(endpointName); ok {
		return v.(ssh.Signer), nil
	}
	dir := filepath.Join(caDir, "ssh")
	path := filepath.Join(dir, safeFileName(endpointName)+".key")

	if data, err := os.ReadFile(path); err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		rt.keyCache.Store(endpointName, signer)
		return signer, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
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
	if err := writeFileAtomic(path, pemData, 0o600); err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	log.Printf("ssh: minted host key for endpoint %q at %s — fingerprint %s",
		endpointName, path, ssh.FingerprintSHA256(signer.PublicKey()))
	rt.keyCache.Store(endpointName, signer)
	return signer, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sshkey-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// safeFileName maps an endpoint name to a filesystem-safe form.
// Endpoint names already follow HCL identifier rules so this is
// belt-and-suspenders against future relaxations.
func safeFileName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, s)
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
