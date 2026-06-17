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
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"golang.org/x/net/http/httpguts"
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
	adapter       *endpointAdapter
	instanceName  string
	canonicalJSON []byte
	hosts         []string
	// dialTargets is the operator-written `dial = [...]` allow-list
	// of extra upstream targets brokered dials may open. Gateway
	// decoded, never forwarded to the plugin.
	dialTargets  []string
	tlsTerminate bool
	wantsVIP     bool
}

// dialAllowList returns the endpoint's effective brokered-dial allow-list:
// the operator-written `dial` entries plus the plugin's manifest-approved
// egress set. Both are consumed identically by validateBrokeredDialTarget
// (exact "host:port" or "*.suffix:port"), so a plugin reaches its declared
// destinations without the operator hand-writing them into every
// endpoint's `dial`.
func (b *dynamicEndpointBody) dialAllowList() []string {
	var egress []string
	if b.adapter != nil && b.adapter.client != nil {
		egress = b.adapter.client.egress
	}
	if len(egress) == 0 {
		return b.dialTargets
	}
	out := make([]string, 0, len(b.dialTargets)+len(egress))
	out = append(out, b.dialTargets...)
	out = append(out, egress...)
	return out
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

// TLSTerminates reports whether this plugin endpoint terminates the
// agent's TLS itself (the plugin asked for TLSTerminate). The :443 SNI
// dispatch uses this to route a matched HTTPS plugin endpoint to the
// plugin — and only such endpoints, so built-in wire-protocol conn
// runtimes (postgres / clickhouse / ssh) bound to a host aren't handed a
// raw ClientHello they can't parse.
func (b *dynamicEndpointBody) TLSTerminates() bool { return b.tlsTerminate }

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
	defer func() { _ = conn.Close() }()

	// Resolve credential secrets. Every credential bound to the endpoint is
	// delivered in `allCreds` (declaration order) for plugins that select
	// among several — e.g. the aws plugin picks a base key by target
	// account. The singular cred* fields below mirror the first so plugins
	// that read only one keep working unchanged.
	var (
		credName  string
		credType  string
		credSec   []byte
		credCanon []byte
		credExtra map[string]string
		allCreds  []*pb.BoundCredential
	)
	for _, c := range ch.Endpoint.Credentials {
		bc := &pb.BoundCredential{
			TypeName: c.Symbol.Type,
			Instance: c.Symbol.Name,
		}
		if secret, err := ch.Secrets.Get(c.Symbol.Name); err == nil {
			bc.Secret = secret.Bytes
			bc.Extras = secret.Extras
		}
		if cb, ok := credentialBaseOf(c.Body); ok {
			bc.CanonicalJson = cb.canonicalJSON
		}
		allCreds = append(allCreds, bc)
	}
	if len(allCreds) > 0 {
		first := allCreds[0]
		credType = first.TypeName
		credName = first.Instance
		credSec = first.Secret
		credExtra = first.Extras
		credCanon = first.CanonicalJson
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
	defer func() { _ = stream.CloseSend() }()

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
		Credentials:             allCreds,
		TunnelTypeName:          tunType,
		TunnelInstance:          tunInst,
		SupportsDialUpstream:    true,
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
//	                StreamChunk / ConnClose; write data to conn,
//	                forward events to ch.Emit, dispatch evaluations
//	                through the gateway's matcher + approve chain
//	                and reply with an ActionVerdict, route incoming
//	                stream chunks to in-flight pullStream callers.
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

	// streamReplies routes StreamChunk messages from the plugin to
	// the per-evaluate goroutine that issued the matching
	// StreamRead. One blocked pullStream call sits on the channel
	// per outstanding read; arrivals push the chunk and the caller
	// either accepts it or sends another StreamRead.
	var streamMu sync.Mutex
	streamReplies := map[string]chan *pb.StreamChunk{}
	getStreamCh := func(handle string) chan *pb.StreamChunk {
		streamMu.Lock()
		defer streamMu.Unlock()
		ch, ok := streamReplies[handle]
		if !ok {
			ch = make(chan *pb.StreamChunk, 1)
			streamReplies[handle] = ch
		}
		return ch
	}
	streamReply := func(handle string) <-chan *pb.StreamChunk {
		return getStreamCh(handle)
	}

	// Brokered upstream dials opened on this stream's behalf. Torn
	// down with the stream.
	dials := newDialRegistry()
	defer dials.closeAll()

	// agentDone fires when the agent->plugin copy stops (the agent closed
	// or errored); pluginDone fires when the plugin->agent copy stops (the
	// plugin's HandleConn returned — sending ConnClose — or the stream
	// errored). Tracking them separately lets the teardown half-close the
	// agent connection gracefully when the plugin finishes first, so a
	// one-shot plugin's final response isn't truncated by an immediate hard
	// close before the netstack has flushed it to the agent.
	agentDone := make(chan error, 1)
	pluginDone := make(chan error, 1)

	// agent -> plugin
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if serr := doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Data{
					Data: &pb.ConnData{Payload: append([]byte(nil), buf[:n]...)},
				}}); serr != nil {
					agentDone <- serr
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Close{Close: &pb.ConnClose{}}})
					agentDone <- nil
				} else {
					agentDone <- err
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
					pluginDone <- nil
				} else {
					pluginDone <- err
				}
				return
			}
			switch k := msg.GetKind().(type) {
			case *pb.ConnMessage_Data:
				if _, werr := conn.Write(k.Data.Payload); werr != nil {
					pluginDone <- werr
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
				go handleEvaluate(ctx, ch, k.Evaluate, doSend, streamReply)
			case *pb.ConnMessage_StreamChunk:
				replyCh := getStreamCh(k.StreamChunk.Handle)
				select {
				case replyCh <- k.StreamChunk:
				default:
					// pullStream uses a 1-buffer channel and does
					// one read per StreamRead; a backed-up channel
					// here means the caller already gave up on the
					// stream. Drop the chunk.
				}
			case *pb.ConnMessage_DialRequest:
				// Validate + dial + pump off the recv loop so a slow
				// upstream connect doesn't stall data flow.
				go handleDialRequest(ctx, ch, dials, k.DialRequest, doSend)
			case *pb.ConnMessage_DialData:
				if d := dials.get(k.DialData.DialId); d != nil {
					select {
					case d.writeQ <- k.DialData.Payload:
						// Bounded backpressure: a full queue blocks
						// the recv loop the same way a slow agent
						// conn.Write does for ConnData.
					case <-d.done:
					case <-ctx.Done():
					}
				}
				// Unknown dial_id: frames racing our close. Drop.
			case *pb.ConnMessage_DialClose:
				if d := dials.get(k.DialClose.DialId); d != nil {
					dials.remove(k.DialClose.DialId)
					d.close()
				}
			case *pb.ConnMessage_Close:
				pluginDone <- nil
				return
			}
		}
	}()

	select {
	case err := <-pluginDone:
		// The plugin finished its side (a one-shot endpoint like aws_api
		// returns after writing one response). Half-close the agent's write
		// direction so the buffered response flushes and the agent sees
		// end-of-stream, then wait — bounded — for the agent to read it and
		// close. Hard-closing here instead would discard the response still
		// queued in the netstack send buffer (the agent then hangs, having
		// sent its request but received nothing).
		halfCloseWrite(conn)
		select {
		case <-agentDone:
		case <-time.After(connDrainTimeout):
		}
		_ = conn.Close()
		return err
	case err := <-agentDone:
		// The agent closed/errored first — nothing in flight to protect, so
		// tear down and let the plugin observe the ConnClose.
		_ = conn.Close()
		<-pluginDone
		return err
	case <-ctx.Done():
		_ = conn.Close()
		<-agentDone
		<-pluginDone
		return ctx.Err()
	}
}

// connDrainTimeout bounds how long the gateway waits, after a plugin
// finishes a connection, for the agent to read the final response and
// close. The wait lets the netstack flush the buffered response before the
// hard close; it ends as soon as the agent closes (the common case is a
// few milliseconds), and the timeout is only a backstop for a peer that
// holds the half-closed connection open.
const connDrainTimeout = 30 * time.Second

// halfCloseWrite shuts the write half of c so buffered bytes flush and the
// peer sees end-of-stream, without tearing down the read half. For a TLS
// server conn this sends close_notify; the underlying TCP FIN follows when
// the peer closes its side. A no-op when c can't half-close — the caller
// still performs a full Close afterwards.
func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// streamCapBytesForRule is how many bytes the gateway pulls from a
// stream-typed facet field when at least one rule on the endpoint
// references it. CEL needs the full value to evaluate predicates
// like `body.contains("foo")`, so this is also the upper bound on
// the bytes the matcher sees.
const streamCapBytesForRule = 1 << 20 // 1 MiB

// streamCapBytesForLog is the smaller cap used when no rule
// references the stream — just enough to record a recognisable
// prefix on the dashboard event so an operator can eyeball what
// went past.
const streamCapBytesForLog = 1024

// handleEvaluate runs one EvaluateAction call from the plugin
// against the gateway's matcher + approve chain and ships the
// resulting verdict back over the stream. Also emits a runtime
// ConnEvent so the action lands on the dashboard event sink with
// the action map as the facet payload — plugins don't need to
// double-emit via Conn.Emit.
func handleEvaluate(ctx context.Context, ch *runtime.ConnHandle, ev *pb.EvaluateAction, doSend func(*pb.ConnMessage) error, streamReply func(handle string) <-chan *pb.StreamChunk) {
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
	if action == nil {
		action = map[string]any{}
	}

	// Look up the synthetic facet, if any. nil means the endpoint
	// binds to a built-in facet (http / sql / k8s) — the plugin sent
	// an action shaped to that facet's variables and the adapter
	// maps it onto the typed match.Request fields the built-in
	// matcher reads, instead of stashing the action in Meta.
	pf := facetFor(ch.Endpoint.Family)

	// Stream pulling: for each stream field present in ev.Streams,
	// pull bytes until cap or EOF, then cancel. For plugin facets
	// the cap honours per-rule reference detection; for built-in
	// facets we use the larger cap unconditionally (rules attached
	// to built-in matchers don't expose a SubFieldReferencer yet).
	var truncated bool
	streamBytes := map[string][]byte{}
	if len(ev.Streams) > 0 {
		var needed map[string]bool
		if pf != nil {
			needed = streamFieldsNeeded(ch.Endpoint.Rules, pf.name)
		}
		for fieldName, handle := range ev.Streams {
			if pf != nil && pf.kindByField[fieldName] != pb.FacetKind_FACET_STREAM {
				continue
			}
			limit := streamCapBytesForRule
			if pf != nil && !needed[fieldName] {
				limit = streamCapBytesForLog
			}
			data, hit := pullStream(ctx, doSend, streamReply, handle, limit)
			if hit {
				truncated = true
			}
			// Always cancel after we've taken what we need so the
			// plugin can release its source. Safe even if the stream
			// already eof-ed; the SDK ignores cancels for handles
			// it has already dropped.
			_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_StreamCancel{StreamCancel: &pb.StreamCancel{Handle: handle}}})
			streamBytes[fieldName] = data
			action[fieldName] = string(data)
		}
	}

	// Optional-field zero-fill so rule conditions can reference
	// declared fields without `has()` guards. Plugin facets only —
	// built-in facets have their own contract.
	if pf != nil {
		for field := range pf.optionalFields {
			if _, present := action[field]; present && action[field] != nil {
				continue
			}
			action[field] = zeroForKind(pf.kindByField[field])
		}
	}

	// Build a match.Request rich enough for the matcher AND for the
	// HITL prompt fields a human approver might render. Truncated
	// is set when at least one stream field hit its cap before
	// EOF — the matcher then marks stream-typed fields CEL-unknown
	// and any rule whose outcome depends on one is denied.
	var req *match.Request
	if pf != nil {
		req = &match.Request{
			Family:    ch.Endpoint.Family,
			PeerIP:    ch.PeerIP,
			Method:    stringField(action, "verb"),
			URL:       &url.URL{Host: ch.UpstreamHost, Path: ev.Summary},
			Meta:      action,
			Truncated: truncated,
		}
	} else {
		req = builtinRequestFor(ch.Endpoint.Family, ch.PeerIP, ev.Summary, action, streamBytes)
		req.Truncated = truncated
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

// builtinRequestFor maps an EvaluateAction's action map onto a
// match.Request shaped the way a built-in facet's matcher expects.
// Plugins that bind their endpoint's Family to a built-in facet
// ("http", "sql", "k8s") send the action keyed by that facet's CEL
// variables; the gateway translates here so the same matcher the
// gateway's own pipeline runs sees a familiar Request.
//
// Only "http" is supported in v1. Other families fall back to a
// permissive Meta-bag request — rules will likely not match, which
// surfaces as the gateway's default-deny.
func builtinRequestFor(family, peerIP, summary string, action map[string]any, streams map[string][]byte) *match.Request {
	switch family {
	case "http":
		req := &match.Request{
			Family: family,
			PeerIP: peerIP,
			Method: stringField(action, "method"),
		}
		// URL: prefer a full URL if the plugin sent one; otherwise
		// build a path-only URL (the built-in http facet only reads
		// Path + Query; Host isn't on the CEL surface).
		if u := stringField(action, "url"); u != "" {
			if pu, err := url.Parse(u); err == nil {
				req.URL = pu
			}
		}
		if req.URL == nil {
			req.URL = &url.URL{Path: stringField(action, "path")}
		}
		if h, ok := action["headers"].(map[string]any); ok {
			req.Headers = http.Header{}
			for k, v := range h {
				switch vv := v.(type) {
				case []any:
					for _, item := range vv {
						if s, ok := item.(string); ok {
							req.Headers.Add(k, s)
						}
					}
				case string:
					req.Headers.Set(k, vv)
				}
			}
		}
		if b, ok := streams["body"]; ok {
			req.Body = b
		} else if b, ok := action["body"].(string); ok {
			req.Body = []byte(b)
		}
		return req
	}
	return &match.Request{
		Family: family,
		PeerIP: peerIP,
		URL:    &url.URL{Path: summary},
		Meta:   action,
	}
}

// facetFor looks up the synthesized *pluginFacet by namespaced name.
// Returns nil when the family isn't a plugin facet (e.g. a built-in
// or an endpoint with family=="stream" that didn't bind to a facet).
func facetFor(family string) *pluginFacet {
	if family == "" {
		return nil
	}
	r := facet.Lookup(family)
	if r == nil {
		return nil
	}
	pf, _ := r.(*pluginFacet)
	return pf
}

// streamFieldsNeeded returns the set of facet sub-fields any rule
// on the endpoint will read from the activation. The matchers built
// by newPluginFacetMatcher implement SubFieldReferencer; matchers
// from other origins (an unlikely mix) are treated as referencing
// every field, since we have no visibility into their AST.
func streamFieldsNeeded(rules []*config.CompiledRule, _ string) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		ref, ok := r.Matcher.(SubFieldReferencer)
		if !ok {
			// Conservative: assume every field is read so we don't
			// strip data a rule needs.
			return nil
		}
		for f := range ref.SubFieldRefs() {
			out[f] = true
		}
	}
	return out
}

// pullStream issues StreamRead requests against the plugin until
// either the cap is reached or the stream eofs. Returns the bytes
// collected and a truncated flag set when we stopped because of the
// cap (and not because the stream eof'd). Errors and read failures
// land here as eof, not truncation — we have no way to tell from
// outside whether the plugin had more bytes to give.
func pullStream(ctx context.Context, doSend func(*pb.ConnMessage) error, streamReply func(handle string) <-chan *pb.StreamChunk, handle string, limit int) (data []byte, truncated bool) {
	if limit <= 0 {
		return nil, false
	}
	out := make([]byte, 0, limit)
	for len(out) < limit {
		want := limit - len(out)
		if want > 32*1024 {
			want = 32 * 1024
		}
		ch := streamReply(handle)
		if ch == nil {
			return out, false
		}
		if err := doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_StreamRead{StreamRead: &pb.StreamRead{
			Handle: handle, MaxBytes: uint32(want),
		}}}); err != nil {
			return out, false
		}
		select {
		case chunk, ok := <-ch:
			if !ok || chunk == nil {
				return out, false
			}
			if n := limit - len(out); n < len(chunk.Payload) {
				out = append(out, chunk.Payload[:n]...)
				// We stopped because cap was reached; the plugin
				// might still have had more (`!chunk.Eof`) or
				// might not (`chunk.Eof`). When the chunk itself
				// signalled eof and exactly fit, no truncation —
				// but we capped strictly less, so there's at
				// least one buffered byte we threw away.
				return out, true
			}
			out = append(out, chunk.Payload...)
			if chunk.Eof {
				return out, false
			}
		case <-ctx.Done():
			return out, false
		}
	}
	return out, true
}

// zeroForKind returns the JSON-shaped zero value for a facet field
// kind. Used to fill in optional fields the plugin omitted from the
// action payload.
func zeroForKind(k pb.FacetKind) any {
	switch k {
	case pb.FacetKind_FACET_STRING_LIST:
		return []any{}
	case pb.FacetKind_FACET_STRING_MAP:
		return map[string]any{}
	case pb.FacetKind_FACET_INT:
		return float64(0)
	default:
		// FACET_STRING and FACET_STREAM both materialize as strings
		// (the bytes from a stream are exposed as a string for
		// CEL's built-in size / contains / startsWith / etc).
		return ""
	}
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
		secret, err := host.SecretStore.Get(host.Credential.Name)
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
// Credential adapter
// =====================================================================

type credentialAdapter struct {
	client   *Client
	typeName string
}

type credentialMetadata struct {
	disambiguators []string
	secretSlots    []config.SecretSlot
	envVars        []config.EnvVar
	oauth          *config.OAuthIntegration
	httpInject     bool
	// httpTransform: the credential rewrites method/URL/body via the
	// streaming TransformHTTP RPC (superset of httpInject).
	httpTransform bool
}

// dynamicCredentialBody is the per-instance base Body for credentials
// registered by external plugins. It carries the canonical JSON and
// metadata returned by the plugin's Build so endpoint adapters can
// forward it on ConnInit and dashboard/env/OAuth surfaces can discover
// the credential's capabilities.
type dynamicCredentialBody struct {
	adapter       *credentialAdapter
	instanceName  string
	canonicalJSON []byte
	metadata      credentialMetadata

	redactionsMu sync.Mutex
	redactions   map[*http.Request][]string
}

func (b *dynamicCredentialBody) SecretSlots() []config.SecretSlot {
	if b == nil || len(b.metadata.secretSlots) == 0 {
		return nil
	}
	return append([]config.SecretSlot(nil), b.metadata.secretSlots...)
}

func (b *dynamicCredentialBody) EnvVars() []config.EnvVar {
	if b == nil || len(b.metadata.envVars) == 0 {
		return nil
	}
	return append([]config.EnvVar(nil), b.metadata.envVars...)
}

type dynamicOAuthCredentialBody struct{ *dynamicCredentialBody }

func (b *dynamicOAuthCredentialBody) OAuthFlow() *config.OAuthIntegration {
	if b == nil || b.dynamicCredentialBody == nil {
		return nil
	}
	return cloneOAuthIntegration(b.metadata.oauth)
}

type dynamicHTTPCredentialBody struct{ *dynamicCredentialBody }

type dynamicOAuthHTTPCredentialBody struct{ *dynamicCredentialBody }

func (b *dynamicOAuthHTTPCredentialBody) OAuthFlow() *config.OAuthIntegration {
	if b == nil || b.dynamicCredentialBody == nil {
		return nil
	}
	return cloneOAuthIntegration(b.metadata.oauth)
}

func (b *dynamicHTTPCredentialBody) InjectHTTP(ctx context.Context, req *http.Request, sec runtime.Secret) error {
	if b == nil {
		return nil
	}
	return injectHTTPWithExternalCredential(ctx, b.dynamicCredentialBody, req, sec)
}

func (b *dynamicOAuthHTTPCredentialBody) InjectHTTP(ctx context.Context, req *http.Request, sec runtime.Secret) error {
	if b == nil {
		return nil
	}
	return injectHTTPWithExternalCredential(ctx, b.dynamicCredentialBody, req, sec)
}

// RewritesHTTPRequest reports whether InjectHTTP rewrites more than
// headers (a transform credential). The gateway fails closed on its
// inject error since the request body was streamed to the plugin. The
// method is promoted to the HTTP body wrappers that embed
// *dynamicCredentialBody.
func (b *dynamicCredentialBody) RewritesHTTPRequest() bool {
	return b != nil && b.metadata.httpTransform
}

func (b *dynamicHTTPCredentialBody) ConsumeHTTPRedactions(req *http.Request) []string {
	if b == nil {
		return nil
	}
	return consumeHTTPRedactions(b.dynamicCredentialBody, req)
}

func (b *dynamicOAuthHTTPCredentialBody) ConsumeHTTPRedactions(req *http.Request) []string {
	if b == nil {
		return nil
	}
	return consumeHTTPRedactions(b.dynamicCredentialBody, req)
}

// injectHTTPTimeout bounds the plugin InjectHTTP round trip. Plugins
// may perform network token exchanges at request time, so a hung or
// slow plugin must degrade to a logged inject error instead of
// wedging the proxied request for as long as the agent keeps the
// connection open.
const (
	injectHTTPTimeout          = 30 * time.Second
	maxHTTPRedactionMapEntries = 1024
)

func injectHTTPWithExternalCredential(ctx context.Context, body *dynamicCredentialBody, req *http.Request, sec runtime.Secret) error {
	if body == nil {
		return nil
	}
	// Transform credentials use the streaming TransformHTTP path (the
	// request body flows through the plugin); header-only credentials use
	// the unary InjectHTTP below (the body never leaves the gateway).
	if body.metadata.httpTransform {
		return transformHTTPWithExternalCredential(ctx, body, req, sec)
	}
	if body.adapter == nil || body.adapter.client == nil || body.adapter.client.credential == nil {
		return fmt.Errorf("extplugin: credential %q InjectHTTP unavailable: plugin client is not connected", body.instanceName)
	}
	ctx, cancel := context.WithTimeout(ctx, injectHTTPTimeout)
	defer cancel()
	out, err := body.adapter.client.credential.InjectHTTP(ctx, &pb.InjectHTTPRequest{
		CredentialTypeName:      body.adapter.typeName,
		CredentialInstance:      body.instanceName,
		CredentialCanonicalJson: body.canonicalJSON,
		CredentialSecret:        sec.Bytes,
		CredentialExtras:        sec.Extras,
		Method:                  req.Method,
		Url:                     req.URL.String(),
		Host:                    req.Host,
		Headers:                 headersToProto(req.Header),
	})
	if err != nil {
		return fmt.Errorf("extplugin: credential %s.%s InjectHTTP: %w", body.adapter.typeName, body.instanceName, err)
	}
	body.recordHTTPRedactions(req, out.GetRedactions())
	applyHeaderMutations(req.Header, out.GetHeaders())
	return nil
}

func (b *dynamicCredentialBody) recordHTTPRedactions(req *http.Request, redactions []string) {
	if b == nil || req == nil || len(redactions) == 0 {
		return
	}
	b.redactionsMu.Lock()
	defer b.redactionsMu.Unlock()
	if b.redactions == nil {
		b.redactions = map[*http.Request][]string{}
	}
	if len(b.redactions) >= maxHTTPRedactionMapEntries {
		for stale := range b.redactions {
			delete(b.redactions, stale)
			break
		}
	}
	b.redactions[req] = append([]string(nil), redactions...)
}

func consumeHTTPRedactions(b *dynamicCredentialBody, req *http.Request) []string {
	if b == nil || req == nil {
		return nil
	}
	b.redactionsMu.Lock()
	defer b.redactionsMu.Unlock()
	out := append([]string(nil), b.redactions[req]...)
	delete(b.redactions, req)
	return out
}

func credentialBaseOf(v any) (*dynamicCredentialBody, bool) {
	switch b := v.(type) {
	case *dynamicCredentialBody:
		return b, b != nil
	case *dynamicHTTPCredentialBody:
		if b == nil || b.dynamicCredentialBody == nil {
			return nil, false
		}
		return b.dynamicCredentialBody, true
	case *dynamicOAuthCredentialBody:
		if b == nil || b.dynamicCredentialBody == nil {
			return nil, false
		}
		return b.dynamicCredentialBody, true
	case *dynamicOAuthHTTPCredentialBody:
		if b == nil || b.dynamicCredentialBody == nil {
			return nil, false
		}
		return b.dynamicCredentialBody, true
	default:
		return nil, false
	}
}

func wrapCredentialBody(b *dynamicCredentialBody) any {
	if b == nil {
		return b
	}
	// A transform credential participates in HTTP injection too (it is the
	// superset), so it gets the same HTTP-capable wrapper.
	httpCapable := b.metadata.httpInject || b.metadata.httpTransform
	switch {
	case b.metadata.oauth != nil && httpCapable:
		return &dynamicOAuthHTTPCredentialBody{dynamicCredentialBody: b}
	case b.metadata.oauth != nil:
		return &dynamicOAuthCredentialBody{dynamicCredentialBody: b}
	case httpCapable:
		return &dynamicHTTPCredentialBody{dynamicCredentialBody: b}
	default:
		return b
	}
}

func headersToProto(in http.Header) map[string]*pb.HTTPHeaderValues {
	out := make(map[string]*pb.HTTPHeaderValues, len(in))
	for k, vals := range in {
		out[k] = &pb.HTTPHeaderValues{Values: append([]string(nil), vals...)}
	}
	return out
}

func applyHeaderMutations(h http.Header, mutations []*pb.HeaderMutation) {
	for _, m := range mutations {
		if !validHeaderMutation(m) {
			continue
		}
		switch m.Op {
		case pb.HeaderMutation_SET:
			h.Del(m.Name)
			for _, v := range m.Values {
				h.Add(m.Name, v)
			}
		case pb.HeaderMutation_ADD:
			for _, v := range m.Values {
				h.Add(m.Name, v)
			}
		case pb.HeaderMutation_DEL:
			h.Del(m.Name)
		default:
			// Ops this gateway build doesn't know (a newer plugin
			// proto) are skipped rather than guessed at as SET.
		}
	}
}

func validHeaderMutation(m *pb.HeaderMutation) bool {
	if m == nil || !httpguts.ValidHeaderFieldName(m.Name) {
		return false
	}
	if m.Op == pb.HeaderMutation_DEL {
		return true
	}
	for _, v := range m.Values {
		if !httpguts.ValidHeaderFieldValue(v) {
			return false
		}
	}
	return true
}

func cloneOAuthIntegration(in *config.OAuthIntegration) *config.OAuthIntegration {
	if in == nil {
		return nil
	}
	out := *in
	out.OAuth.Scopes = append([]string(nil), in.OAuth.Scopes...)
	out.OptionalScopes = make([]config.OptionalScopeGroup, len(in.OptionalScopes))
	for i, g := range in.OptionalScopes {
		out.OptionalScopes[i] = config.OptionalScopeGroup{
			Title:  g.Title,
			Scopes: append([]config.OptionalScope(nil), g.Scopes...),
		}
	}
	return &out
}
