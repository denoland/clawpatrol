package extplugin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"sync"

	pb "github.com/denoland/clawpatrol/config/extplugin/proto"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/runtime"
)

// =====================================================================
// Endpoint adapter
// =====================================================================

// endpointAdapter implements runtime.ConnEndpointRuntime by relaying
// the agent connection to the plugin subprocess via the HandleConn
// bidi gRPC stream. It also implements runtime.ConnRouter and the
// dnsvip RequiresVIP marker so the gateway's existing routing layers
// pick up plugin endpoints without any new wiring.
type endpointAdapter struct {
	client      *Client
	typeName    string
	hosts       []string
	tlsMode     pb.TLSMode
	requiresVIP bool
}

// dynamicEndpointBody is the per-instance Body the adapter stores on
// Entity.Body. It carries the canonical JSON the plugin's Build
// returned + the endpoint instance's hosts (decoded by the loader).
//
// The body satisfies the runtime.ConnRouter and dnsvip.RequiresVIP
// interfaces directly so the gateway's compile / DNS-VIP passes
// route plugin endpoints with zero new code.
type dynamicEndpointBody struct {
	adapter        *endpointAdapter
	instanceName   string
	canonicalJSON  []byte
	hosts          []string
	credentialName string
	tlsTerminate   bool
	wantsVIP       bool
}

// EndpointHosts is consulted by the loader at compile time
// (config/compile.go reads it via reflection) and by the dispatch
// layer for SNI / VIP routing.
func (b *dynamicEndpointBody) EndpointHosts() []string { return b.hosts }

// ConnRouteHosts mirrors EndpointHosts so VIP routing picks the
// endpoint up.
func (b *dynamicEndpointBody) ConnRouteHosts() []string { return b.hosts }

// RequiresVIP opts the endpoint into DNS-MitM allocation when the
// plugin asked for it in its manifest.
func (b *dynamicEndpointBody) RequiresVIP() bool { return b.wantsVIP }

// HandleConn satisfies runtime.ConnEndpointRuntime. The host has
// already routed the agent conn to this endpoint and bundled the
// full per-conn context on ch.
func (a *endpointAdapter) HandleConn(ctx context.Context, ch *runtime.ConnHandle) error {
	body, ok := ch.Endpoint.Body.(*dynamicEndpointBody)
	if !ok {
		return fmt.Errorf("extplugin: endpoint %q has unexpected body type %T", ch.Endpoint.Name, ch.Endpoint.Body)
	}

	// TLS terminate if the plugin asked for it.
	conn := ch.Conn
	if body.tlsTerminate {
		if ch.MintCert == nil {
			return errors.New("extplugin: TLS termination requested but no MintCert on ConnHandle")
		}
		host := ch.UpstreamHost
		tlsCfg := &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := hello.ServerName
				if name == "" {
					name = host
				}
				return ch.MintCert(name)
			},
		}
		tc := tls.Server(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("extplugin: TLS handshake: %w", err)
		}
		conn = tc
	}
	defer conn.Close()

	// Resolve credential secret.
	var (
		credName  string
		credType  string
		credSec   []byte
		credCanon []byte
		credExtra map[string]string
	)
	if len(ch.Endpoint.Credentials) > 0 {
		c := ch.Endpoint.Credentials[0].Credential
		credName = c.Symbol.Name
		credType = c.Symbol.Type
		secret, err := ch.Secrets.Get(credName, ch.Profile)
		if err == nil {
			credSec = secret.Bytes
			credExtra = secret.Extras
		}
		if cb, ok := c.Body.(*dynamicCredentialBody); ok {
			credCanon = cb.canonicalJSON
		}
	}

	// Tunnel binding (informational only — gateway dialing happens
	// via DialUpstream; plugin doesn't get to call back through the
	// tunnel in v1).
	tunType, tunInst := "", ""
	if ch.Endpoint.Tunnel != nil {
		tunType = ch.Endpoint.Tunnel.Plugin.Type
		tunInst = ch.Endpoint.Tunnel.Name
	}

	stream, err := a.client.endpoint.HandleConn(ctx)
	if err != nil {
		return fmt.Errorf("extplugin: open HandleConn stream: %w", err)
	}
	defer stream.CloseSend()

	// Send ConnInit.
	init := &pb.ConnInit{
		EndpointTypeName:        body.adapter.typeName,
		EndpointInstance:        body.instanceName,
		EndpointCanonicalJson:   body.canonicalJSON,
		Profile:                 ch.Profile,
		PeerIp:                  ch.PeerIP,
		UpstreamHost:            ch.UpstreamHost,
		DstPort:                 uint32(ch.DstPort),
		CredentialTypeName:      credType,
		CredentialInstance:      credName,
		CredentialCanonicalJson: credCanon,
		CredentialSecret:        credSec,
		CredentialExtras:        credExtra,
		TunnelTypeName:          tunType,
		TunnelInstance:          tunInst,
	}
	if err := stream.Send(&pb.ConnMessage{Kind: &pb.ConnMessage_Init{Init: init}}); err != nil {
		return fmt.Errorf("extplugin: send ConnInit: %w", err)
	}

	return pumpConn(ctx, conn, stream, ch)
}

// pumpConn runs two goroutines:
//
//	conn -> plugin: read agent bytes, send as ConnData frames.
//	plugin -> conn: receive ConnData / ConnEvent / EvaluateAction /
//	                ConnClose; write data to conn, forward events to
//	                ch.Emit, dispatch evaluations through the
//	                gateway's matcher + approve chain and reply with
//	                an ActionVerdict.
//
// Returns the first non-nil error from either direction.
//
// gRPC client streams aren't safe for concurrent Send, so a single
// sendMu serializes everything that writes to the stream — the data
// pump, async event forwarding, the close on shutdown, and verdict
// replies fired from per-evaluate goroutines.
func pumpConn(ctx context.Context, conn net.Conn, stream pb.Endpoint_HandleConnClient, ch *runtime.ConnHandle) error {
	var sendMu sync.Mutex
	doSend := func(m *pb.ConnMessage) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}

	errCh := make(chan error, 2)

	// agent -> plugin
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if serr := doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Data{
					Data: &pb.ConnData{Payload: append([]byte(nil), buf[:n]...)},
				}}); serr != nil {
					errCh <- serr
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Close{Close: &pb.ConnClose{}}})
					errCh <- nil
				} else {
					errCh <- err
				}
				return
			}
		}
	}()

	// plugin -> agent
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					errCh <- nil
				} else {
					errCh <- err
				}
				return
			}
			switch k := msg.GetKind().(type) {
			case *pb.ConnMessage_Data:
				if _, werr := conn.Write(k.Data.Payload); werr != nil {
					errCh <- werr
					return
				}
			case *pb.ConnMessage_Event:
				if ch.Emit != nil {
					var facets map[string]any
					if len(k.Event.FacetsJson) > 0 {
						_ = json.Unmarshal(k.Event.FacetsJson, &facets)
					}
					ch.Emit(runtime.ConnEvent{
						Action:  k.Event.Action,
						Reason:  k.Event.Reason,
						Verb:    k.Event.Verb,
						Summary: k.Event.Summary,
						Bytes:   k.Event.BytesCount,
						Facets:  facets,
						Rule:    k.Event.Rule,
					})
				}
			case *pb.ConnMessage_Evaluate:
				// Run rule + approve chain off the recv loop so a
				// HITL-blocking call doesn't stall data flow or
				// other concurrent evaluations.
				go handleEvaluate(ctx, ch, k.Evaluate, doSend)
			case *pb.ConnMessage_Close:
				errCh <- nil
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		_ = conn.Close()
		<-errCh
		return err
	case <-ctx.Done():
		_ = conn.Close()
		<-errCh
		<-errCh
		return ctx.Err()
	}
}

// handleEvaluate runs one EvaluateAction call from the plugin
// against the gateway's matcher + approve chain and ships the
// resulting verdict back over the stream. Also emits a runtime
// ConnEvent so the action lands on the dashboard event sink with
// the action map as the facet payload — plugins don't need to
// double-emit via Conn.Emit.
func handleEvaluate(ctx context.Context, ch *runtime.ConnHandle, ev *pb.EvaluateAction, doSend func(*pb.ConnMessage) error) {
	verdict := &pb.ActionVerdict{CallId: ev.CallId}

	// Decode the action payload into a map so it can both feed the
	// CEL activation and ride along on the audit event.
	var action map[string]any
	if len(ev.ActionJson) > 0 {
		if err := json.Unmarshal(ev.ActionJson, &action); err != nil {
			verdict.Action = "error"
			verdict.Reason = fmt.Sprintf("malformed action_json: %v", err)
			emitEvaluation(ch, ev, verdict, action)
			_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Verdict{Verdict: verdict}})
			return
		}
	}

	// Build a match.Request rich enough for the matcher AND for the
	// HITL prompt fields a human approver might render.
	req := &match.Request{
		Family: ch.Endpoint.Family,
		PeerIP: ch.PeerIP,
		Method: stringField(action, "verb"),
		URL:    &url.URL{Host: ch.UpstreamHost, Path: ev.Summary},
		Meta:   action,
	}

	rule := runtime.MatchRequest(ch.Endpoint, req)
	switch {
	case rule == nil:
		// No rule matched — gateway's default-deny.
		verdict.Action = "deny"
		verdict.Reason = "no rule matched"
	case len(rule.Outcome.Approve) > 0:
		if ch.Approve == nil {
			verdict.Action = "deny"
			verdict.Reason = "rule requires approval but host has no approver wired"
			verdict.Rule = rule.Name
			break
		}
		v := ch.Approve(runtime.ApproveCallRequest{
			Stages:  rule.Outcome.Approve,
			Verb:    stringField(action, "verb"),
			Summary: ev.Summary,
			Rule:    rule,
		})
		verdict.Rule = rule.Name
		verdict.Reason = v.Reason
		switch v.Decision {
		case "allow":
			verdict.Action = "hitl_allow"
		case "deny":
			verdict.Action = "hitl_deny"
		default:
			verdict.Action = "hitl_deny"
			if v.Reason == "" {
				verdict.Reason = "approver returned no decision"
			}
		}
	default:
		verdict.Rule = rule.Name
		if rule.Outcome.Verdict == "deny" {
			verdict.Action = "deny"
		} else {
			verdict.Action = "allow"
		}
		verdict.Reason = rule.Outcome.Reason
	}

	emitEvaluation(ch, ev, verdict, action)
	_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Verdict{Verdict: verdict}})
}

// emitEvaluation logs one EvaluateAction onto the gateway event
// sink so the action shows up on the dashboard alongside built-in
// facet events. Verb / Summary are pulled from the action so the
// log line is human-readable; the action map rides as Facets.
func emitEvaluation(ch *runtime.ConnHandle, ev *pb.EvaluateAction, verdict *pb.ActionVerdict, action map[string]any) {
	if ch.Emit == nil {
		return
	}
	ch.Emit(runtime.ConnEvent{
		Action:  verdict.Action,
		Reason:  verdict.Reason,
		Verb:    stringField(action, "verb"),
		Summary: ev.Summary,
		Facets:  action,
		Rule:    verdict.Rule,
	})
}

func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

// =====================================================================
// Tunnel adapter
// =====================================================================

// dynamicTunnelBody is the per-instance Body for tunnels.
type dynamicTunnelBody struct {
	adapter       *tunnelAdapter
	instanceName  string
	canonicalJSON []byte
}

// tunnelAdapter implements runtime.TunnelRuntime via OpenTunnel /
// Dial / CloseTunnel RPCs.
type tunnelAdapter struct {
	client   *Client
	typeName string
}

func (a *tunnelAdapter) Sharing() runtime.TunnelSharing { return runtime.TunnelShareSingleton }

func (a *tunnelAdapter) Open(ctx context.Context, host runtime.TunnelHost, _ runtime.Tunnel) (runtime.Tunnel, error) {
	body, ok := tunnelBodyOf(host)
	if !ok {
		return nil, fmt.Errorf("extplugin: tunnel %q has no dynamic body", host.Name)
	}
	var (
		credSec   []byte
		credExtra map[string]string
	)
	if host.Credential != nil {
		secret, err := host.SecretStore.Get(host.Credential.Name, "")
		if err == nil {
			credSec = secret.Bytes
			credExtra = secret.Extras
		}
	}
	resp, err := a.client.tunnel.OpenTunnel(ctx, &pb.OpenTunnelRequest{
		TunnelTypeName:   a.typeName,
		TunnelInstance:   body.instanceName,
		CanonicalJson:    body.canonicalJSON,
		CredentialSecret: credSec,
		CredentialExtras: credExtra,
	})
	if err != nil {
		return nil, fmt.Errorf("extplugin: OpenTunnel: %w", err)
	}
	return &remoteTunnel{
		client: a.client,
		handle: resp.Handle,
		logger: host.Logger,
	}, nil
}

// tunnelBodyOf finds the dynamicTunnelBody on a TunnelHost. The host
// only carries Name + SecretStore + Credential, so we look the
// adapter up via a process-wide registry populated by register.go.
//
// Implementation note: we keep a tiny side table here (instead of
// adding a Body field to TunnelHost) to avoid touching the
// runtime/tunnel interface.
func tunnelBodyOf(host runtime.TunnelHost) (*dynamicTunnelBody, bool) {
	tunnelBodies.mu.Lock()
	defer tunnelBodies.mu.Unlock()
	b, ok := tunnelBodies.m[host.Name]
	return b, ok
}

// tunnelBodies is the registration-time-populated table the adapter
// consults at runtime. Keys are tunnel instance names (globally
// unique in clawpatrol's flat namespace).
var tunnelBodies = struct {
	mu sync.Mutex
	m  map[string]*dynamicTunnelBody
}{m: map[string]*dynamicTunnelBody{}}

// remoteTunnel is the runtime.Tunnel handle returned from Open. Each
// Dial call opens a fresh bidi stream against the subprocess.
type remoteTunnel struct {
	client *Client
	handle string
	logger *log.Logger
}

func (t *remoteTunnel) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	stream, err := t.client.tunnel.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("extplugin: open Dial stream: %w", err)
	}
	if err := stream.Send(&pb.DialMessage{Kind: &pb.DialMessage_Init{Init: &pb.DialInit{
		TunnelHandle: t.handle,
		Network:      network,
		Addr:         addr,
	}}}); err != nil {
		return nil, fmt.Errorf("extplugin: send DialInit: %w", err)
	}
	return newDialConn(stream, addr), nil
}

func (t *remoteTunnel) Close() error {
	_, err := t.client.tunnel.CloseTunnel(context.Background(), &pb.CloseTunnelRequest{Handle: t.handle})
	return err
}

// =====================================================================
// Credential body (storage only — runtime credential injection
// happens inside the plugin's endpoint code, not via RPC)
// =====================================================================

// dynamicCredentialBody is what gets stored on Entity.Body for
// credentials registered by external plugins. It carries the
// canonical JSON returned by the plugin's Build so endpoint adapters
// can forward it on ConnInit.
type dynamicCredentialBody struct {
	canonicalJSON []byte
}
