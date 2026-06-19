package extplugin

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
	"github.com/denoland/clawpatrol/internal/config/plugins/facets/sql"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"github.com/google/uuid"
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

	// Register this connection's evaluation context under a fresh,
	// unforgeable session token and hand the token to the plugin in
	// ConnInit. The plugin echoes it back as HostControl metadata to run an
	// Evaluate over the broker (no EvaluateAction frame / call_id) — the
	// session closure runs the same evaluateDecoded core the frame handler
	// does. Removed when the connection ends so no context dangles.
	// rs carries the start→end lifecycle for this conn's actions, shared by
	// the inline (HostControl) and frame evaluate paths and the ActionResult
	// handler in pumpConn.
	rs := newResultState(ch)
	var sessionToken string
	if a.client != nil && a.client.sessions != nil {
		tok, remove := a.client.sessions.register(&session{
			evaluate: func(_ context.Context, _ string, actionJSON []byte, summary string) (Verdict, error) {
				return evaluateInline(ch, rs, summary, actionJSON), nil
			},
		})
		sessionToken = tok
		defer remove()
	}

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
		SessionToken:            sessionToken,
	}
	if err := stream.Send(&pb.ConnMessage{Kind: &pb.ConnMessage_Init{Init: init}}); err != nil {
		return fmt.Errorf("extplugin: send ConnInit: %w", err)
	}

	return pumpConn(ctx, conn, stream, ch, rs)
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
func pumpConn(ctx context.Context, conn net.Conn, stream pb.Endpoint_HandleConnClient, ch *runtime.ConnHandle, rs *resultState) error {
	// Guarantee an end event for every started action: a plugin that
	// doesn't report (or a dropped conn) still persists its in-flight
	// action with an empty status rather than leaving an orphaned start.
	defer rs.flush()
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

	// streamDead is the recv-loop-scoped abort signal for in-flight stream
	// pulls. The recv loop is the ONLY goroutine that routes StreamChunk
	// frames to a parked pullStream; once it exits — for ANY reason, clean
	// ConnClose or recv/write error or plugin crash — no chunk can reach a
	// pull, so a pull waiting on its reply channel would hang until ctx
	// cancellation (which only fires after HandleConn returns, but HandleConn
	// can't return because its deferred flush awaits that very pull: a
	// deadlock). The recv loop closes this via defer on every exit, releasing
	// any parked pull with its partial body so the end event still emits and
	// flush unblocks. On a clean ConnClose the loop first drainBodyPulls to
	// completion (capturing the full capped body), THEN returns and closes
	// streamDead — by then the pull is already done, so the close is a no-op
	// for it; the abort only bites on abnormal exits.
	streamDead := make(chan struct{})

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
		// Release any in-flight body pull on EVERY exit from this loop, not
		// just the ConnClose case: a recv error, an agent conn.Write failure,
		// EOF, or a plugin crash would otherwise leave a pull parked on a
		// StreamChunk that can never arrive (this loop is the only router for
		// it), which deadlocks flush → HandleConn → ctx cancellation.
		defer close(streamDead)
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
				go handleEvaluate(ctx, ch, rs, k.Evaluate, doSend, streamReply, streamDead)
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
			case *pb.ConnMessage_Result:
				// The plugin reports an action's outcome after the response;
				// finalize the conn's in-flight action (emit its end event
				// carrying the status). When the result carries a FACET_STREAM
				// body the gateway pulls it (up to the body cap) before
				// emitting the end — and that pull issues StreamRead and waits
				// for StreamChunk, which arrive HERE on this same recv loop. So
				// the pull MUST run off this goroutine or it deadlocks: finish
				// spawns it and the end event is emitted from that goroutine.
				rs.finish(ctx, k.Result, doSend, streamReply, streamDead)
			case *pb.ConnMessage_Close:
				// A response-body pull spawned by finish needs this recv loop
				// to keep routing its StreamChunk frames. The plugin may queue
				// ConnClose (HandleConn returned) before the pull reaches the
				// cap/EOF, so don't tear down yet: keep reading and routing
				// StreamChunks until the pull completes. The pull bounds itself
				// (cap or EOF, then StreamCancel). On a clean close drainBodyPull
				// runs it to completion (full capped body); if the stream dies
				// mid-drain, the deferred close(streamDead) below releases the
				// pull with whatever it captured.
				if done := rs.pullInFlight(); done != nil {
					drainBodyPull(stream, done, getStreamCh)
				}
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

// bodyTruncatedMarker is appended to a persisted response-body sample when
// the body exceeded the gateway's body-storage cap. It is byte-for-byte the
// marker the built-in HTTP sampler emits (cmd/clawpatrol/web.go's
// bodyTruncatedMarker), so the dashboard's BODY_TRUNCATED_MARKER handling
// renders a plugin response body's "truncated" badge with no extra wiring.
const bodyTruncatedMarker = "\n[clawpatrol:body-truncated]"

// bodySampler caps a plugin-streamed response body to the gateway's
// body-storage limit and hashes the bytes it captured, mirroring the
// built-in HTTP path's sampler so plugin and built-in response samples look
// identical on the dashboard. The gateway pulls at most cap+1 bytes (the
// extra byte distinguishes a body that exactly fills the cap from one that
// overran it) and cancels the stream, so the SHA covers the captured sample
// rather than the full upstream body — the gateway never sees more than the
// cap by design.
type bodySampler struct {
	cap int
	buf []byte
}

func newBodySampler(capBytes int) *bodySampler {
	if capBytes < 0 {
		capBytes = 0
	}
	return &bodySampler{cap: capBytes}
}

func (b *bodySampler) write(p []byte) { b.buf = append(b.buf, p...) }

// truncated reports whether more bytes were pulled than the cap keeps — the
// caller pulls cap+1 bytes precisely so this is detectable.
func (b *bodySampler) truncated() bool { return len(b.buf) > b.cap }

// sample returns the capped body preview: the first cap bytes, with the
// truncation marker appended when the body overran the cap. Binary bodies
// are rendered as a hex prefix, matching the built-in sampler.
func (b *bodySampler) sample() string {
	if len(b.buf) == 0 {
		return ""
	}
	keep := b.buf
	if len(keep) > b.cap {
		keep = keep[:b.cap]
	}
	var out string
	if isPrintable(keep) {
		out = string(keep)
	} else {
		out = "binary:" + hex.EncodeToString(keep[:min(64, len(keep))])
	}
	if b.truncated() {
		out += bodyTruncatedMarker
	}
	return out
}

// sha is the hex SHA-256 of the captured sample bytes (at most cap+1). Empty
// when nothing was captured.
func (b *bodySampler) sha() string {
	if len(b.buf) == 0 {
		return ""
	}
	sum := sha256.Sum256(b.buf)
	return hex.EncodeToString(sum[:])
}

// isPrintable mirrors the built-in sampler's predicate (web.go) so a binary
// plugin response body is rendered as a hex prefix here too, not as garbled
// text on the dashboard.
func isPrintable(b []byte) bool {
	for _, x := range b {
		if x == 0 || (x < 0x20 && x != '\n' && x != '\r' && x != '\t') {
			return false
		}
	}
	return true
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
func handleEvaluate(ctx context.Context, ch *runtime.ConnHandle, rs *resultState, ev *pb.EvaluateAction, doSend func(*pb.ConnMessage) error, streamReply func(handle string) <-chan *pb.StreamChunk, streamDead <-chan struct{}) {
	action, derr := decodeAction(ev.ActionJson)
	if derr != nil {
		v := Verdict{Action: "error", Reason: fmt.Sprintf("malformed action_json: %v", derr)}
		emitEvaluation(ch, rs, ev.Summary, action, v)
		_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Verdict{Verdict: actionVerdict(ev.CallId, v)}})
		return
	}

	// Stream pulling (frame path only — the HostControl path carries the
	// action inline): for each stream field present in ev.Streams, pull
	// bytes until cap or EOF, cancel, and fold the bytes into the action
	// map. For plugin facets the cap honours per-rule reference detection;
	// for built-in facets we use the larger cap unconditionally.
	pf := facetFor(ch.Endpoint.Family)
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
			data, hit := pullStream(ctx, doSend, streamReply, streamDead, handle, limit)
			if hit {
				truncated = true
			}
			// Always cancel after we've taken what we need so the plugin can
			// release its source. Safe even if the stream already eof-ed.
			_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_StreamCancel{StreamCancel: &pb.StreamCancel{Handle: handle}}})
			streamBytes[fieldName] = data
			action[fieldName] = string(data)
		}
	}

	v := evaluateDecoded(ch, ev.Summary, action, streamBytes, truncated)
	emitEvaluation(ch, rs, ev.Summary, action, v)
	_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Verdict{Verdict: actionVerdict(ev.CallId, v)}})
}

// decodeAction unmarshals an action payload into a map. An empty payload is
// an empty map; malformed JSON is an error the caller reports as a verdict.
func decodeAction(b []byte) (map[string]any, error) {
	action := map[string]any{}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &action); err != nil {
			return map[string]any{}, err
		}
	}
	return action, nil
}

func actionVerdict(callID string, v Verdict) *pb.ActionVerdict {
	return &pb.ActionVerdict{CallId: callID, Action: v.Action, Reason: v.Reason, Rule: v.Rule}
}

// evaluateDecoded runs one decoded action through the connection's matcher
// and approve chain and returns the verdict. It is the single source of
// truth shared by the EvaluateAction frame handler and the HostControl
// session closure, so both produce identical verdicts. streamBytes carries
// any FACET_STREAM bytes the frame pulled (nil for the inline HostControl
// path); truncated marks a capped stream so stream-typed facet fields fail
// closed.
func evaluateDecoded(ch *runtime.ConnHandle, summary string, action map[string]any, streamBytes map[string][]byte, truncated bool) Verdict {
	// Look up the synthetic facet, if any. nil means the endpoint binds to
	// a built-in facet (http / sql / k8s) — the action is shaped to that
	// facet's variables and builtinRequestFor maps it onto the typed
	// match.Request the built-in matcher reads instead of stashing it in
	// Meta.
	pf := facetFor(ch.Endpoint.Family)

	// Optional-field zero-fill so rule conditions can reference declared
	// fields without has() guards. Plugin facets only — built-in facets
	// have their own contract.
	if pf != nil {
		for field := range pf.optionalFields {
			if _, present := action[field]; present && action[field] != nil {
				continue
			}
			action[field] = zeroForKind(pf.kindByField[field])
		}
	}

	var req *match.Request
	if pf != nil {
		req = &match.Request{
			Family:    ch.Endpoint.Family,
			PeerIP:    ch.PeerIP,
			Method:    stringField(action, "verb"),
			URL:       &url.URL{Host: ch.UpstreamHost, Path: summary},
			Meta:      action,
			Truncated: truncated,
		}
	} else {
		req = builtinRequestFor(ch.Endpoint.Family, ch.PeerIP, summary, action, streamBytes)
		req.Truncated = truncated
	}

	rule := runtime.MatchRequest(ch.Endpoint, req)
	var v Verdict
	switch {
	case rule == nil:
		v.Action, v.Reason = "deny", "no rule matched"
	case len(rule.Outcome.Approve) > 0:
		if ch.Approve == nil {
			v.Action, v.Reason, v.Rule = "deny", "rule requires approval but host has no approver wired", rule.Name
			break
		}
		av := ch.Approve(runtime.ApproveCallRequest{
			Stages:  rule.Outcome.Approve,
			Verb:    stringField(action, "verb"),
			Summary: summary,
			Rule:    rule,
		})
		v.Rule, v.Reason = rule.Name, av.Reason
		switch av.Decision {
		case "allow":
			v.Action = "hitl_allow"
		case "deny":
			v.Action = "hitl_deny"
		default:
			v.Action = "hitl_deny"
			if av.Reason == "" {
				v.Reason = "approver returned no decision"
			}
		}
	default:
		v.Rule = rule.Name
		if rule.Outcome.Verdict == "deny" {
			v.Action = "deny"
		} else {
			v.Action = "allow"
		}
		v.Reason = rule.Outcome.Reason
	}
	return v
}

// evaluateInline runs one inline action (no stream-valued fields, the
// HostControl path) through the connection's matcher, emits the audit
// event, and returns the verdict. The frame analogue is handleEvaluate; a
// malformed payload becomes an "error" verdict here too, not a transport
// error.
func evaluateInline(ch *runtime.ConnHandle, rs *resultState, summary string, actionJSON []byte) Verdict {
	action, err := decodeAction(actionJSON)
	if err != nil {
		v := Verdict{Action: "error", Reason: fmt.Sprintf("malformed action_json: %v", err)}
		emitEvaluation(ch, rs, summary, action, v)
		return v
	}
	v := evaluateDecoded(ch, summary, action, nil, false)
	emitEvaluation(ch, rs, summary, action, v)
	return v
}

// emitEvaluation logs one EvaluateAction onto the gateway event sink so the
// action shows up on the dashboard alongside built-in facet events. Verb /
// Summary are pulled from the action so the log line is human-readable; the
// action map rides as Facets.
//
// When rs is non-nil and the verdict allows the request through, the action
// is emitted as an in-flight "start" and the lifecycle is handed to rs,
// which emits the "end" (carrying the plugin-reported Status) once an
// ActionResult arrives or the connection closes. Terminal verdicts (deny /
// error — no response is coming) emit a single complete event.
func emitEvaluation(ch *runtime.ConnHandle, rs *resultState, summary string, action map[string]any, v Verdict) {
	if ch.Emit == nil {
		return
	}
	ev := runtime.ConnEvent{
		Action:  v.Action,
		Reason:  v.Reason,
		Verb:    stringField(action, "verb"),
		Summary: summary,
		Facets:  action,
		Rule:    v.Rule,
	}
	if rs != nil && (v.Action == "allow" || v.Action == "hitl_allow") {
		ev.ID = uuid.Must(uuid.NewV7()).String()
		ev.Phase = "start"
		rs.begin(ev)
		return
	}
	ch.Emit(ev)
}

// resultState gives a plugin endpoint's action the same start→end lifecycle
// the built-in HTTP path uses. emitEvaluation calls begin() with the
// in-flight "start" event when a request is allowed through; the plugin
// later reports the outcome via an ActionResult frame (finish), or the
// connection closes (flush) — either way the action persists exactly once
// as the "end" event, and the dashboard merges start→end by ID.
//
// Conn-scoped, not call_id-scoped: Conn.Evaluate's common no-stream path
// runs inline over HostControl with no call_id, so the result finalizes the
// connection's current action. Sequential request/response only — begin()
// flushes any prior unfinished action so it can't be orphaned.
type resultState struct {
	mu        sync.Mutex
	ch        *runtime.ConnHandle
	title     string // result-schema title field name → Status
	bodyField string // result-schema FACET_STREAM field name → RespBody
	bodyCap   int    // gateway body-storage cap for the response sample
	pending   *runtime.ConnEvent
	ended     bool
	// pulling, when non-nil, signals an in-flight response-body pull
	// spawned by finish: it is closed once the pull completes and the end
	// event has been emitted. flush (deferred on pumpConn return) and the
	// recv loop's ConnClose handler wait on it so the body pull isn't cut
	// short and the end event isn't double-emitted. Held under mu.
	pulling chan struct{}
}

func newResultState(ch *runtime.ConnHandle) *resultState {
	rs := &resultState{ch: ch}
	if ch != nil {
		rs.bodyCap = ch.BodyStorageCap
		if ch.Endpoint != nil {
			if pf := facetFor(ch.Endpoint.Family); pf != nil {
				rs.title = pf.resultTitle
				rs.bodyField = pf.resultBodyField
			}
		}
	}
	if rs.bodyCap <= 0 {
		rs.bodyCap = int(config.DefaultBodyStorageLimit)
	}
	return rs
}

func (rs *resultState) begin(ev runtime.ConnEvent) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.flushLocked() // end any prior unfinished action so it isn't orphaned
	cp := ev
	rs.pending = &cp
	rs.ended = false
	// Clear any stale pull handle from a prior action. flushLocked above
	// can't reach this case (it no-ops when the prior action already ended,
	// which a body pull always does), but a defensive clear keeps a second
	// begin() from leaving pullInFlight pointing at a closed channel that a
	// later flush/ConnClose would treat as still in flight.
	rs.pulling = nil
	if rs.ch.Emit != nil {
		rs.ch.Emit(ev)
	}
}

// finish finalizes the conn's in-flight action from a plugin ActionResult.
// It lifts the plugin-reported status from the result schema's title field,
// then:
//
//   - With no FACET_STREAM body stream, it emits the end event synchronously
//     — identical to the status-only path before response bodies existed.
//   - With a body stream, the gateway must pull it (up to the body cap) and
//     fold the sample onto the end event. The pull issues StreamRead and
//     waits for StreamChunk, both of which travel the recv loop that calls
//     finish; pulling here would deadlock. So finish spawns the pull on its
//     own goroutine, records rs.pulling, and that goroutine emits the end
//     event when the pull completes. flush and the ConnClose handler wait on
//     rs.pulling so the body isn't truncated and the end isn't double-emitted.
//
// streamDead is the recv-loop abort signal threaded into the pull: the recv
// loop closes it on EVERY exit, so a pull parked waiting for a StreamChunk
// that can never arrive (the loop is gone — recv error, agent write failure,
// plugin crash) is released with its partial body instead of hanging. The end
// event is still emitted exactly once (here, from the pull goroutine) so the
// action persists even on an abnormal teardown.
func (rs *resultState) finish(ctx context.Context, result *pb.ActionResult, doSend func(*pb.ConnMessage) error, streamReply func(handle string) <-chan *pb.StreamChunk, streamDead <-chan struct{}) {
	rs.mu.Lock()
	if rs.pending == nil || rs.ended {
		rs.mu.Unlock()
		return
	}
	end := *rs.pending
	end.Phase = "end"
	if rs.title != "" && len(result.GetResultJson()) > 0 {
		var rj map[string]any
		if json.Unmarshal(result.GetResultJson(), &rj) == nil {
			if val, ok := rj[rs.title]; ok && val != nil {
				end.Status = fmt.Sprint(val)
			}
		}
	}

	// Identify the response-body stream handle, if the result offers one.
	handle := ""
	if rs.bodyField != "" {
		handle = result.GetStreams()[rs.bodyField]
	}
	if handle == "" {
		// Status-only path: emit now, no pull. Unchanged from before.
		rs.ended = true
		emit := rs.ch.Emit
		rs.mu.Unlock()
		if emit != nil {
			emit(end)
		}
		return
	}

	// Body path: mark the action ended (no other path may emit it) and hand
	// the end event to a pull goroutine. ended is set under the lock now so
	// flush/ConnClose can't race a duplicate emit; the goroutine owns the
	// single emit once the pull finishes.
	rs.ended = true
	done := make(chan struct{})
	rs.pulling = done
	emit := rs.ch.Emit
	capBytes := rs.bodyCap
	rs.mu.Unlock()

	go func() {
		defer close(done)
		body, sha := pullBodySample(ctx, doSend, streamReply, streamDead, handle, capBytes)
		end.RespBody = body
		end.RespSha = sha
		if emit != nil {
			emit(end)
		}
	}()
}

// awaitPull blocks until any in-flight response-body pull spawned by finish
// has completed (its end event emitted). Safe to call when none is in
// flight. Used by flush and the recv loop's ConnClose handler so the pull —
// which needs the recv loop alive to receive StreamChunk frames — isn't cut
// short, and so the end event is emitted exactly once.
func (rs *resultState) awaitPull() {
	if done := rs.pullInFlight(); done != nil {
		<-done
	}
}

// pullInFlight returns the completion channel of an in-flight body pull, or
// nil when none is running.
func (rs *resultState) pullInFlight() <-chan struct{} {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.pulling == nil {
		return nil
	}
	return rs.pulling
}

// drainBodyPull keeps reading the plugin stream and routing StreamChunk
// frames to the in-flight body pull until that pull completes (done closes).
// It is called from the recv loop's ConnClose handler: the plugin queued
// ConnClose before the pull reached cap/EOF, so the loop would otherwise tear
// down with chunks still owed to the pull. Non-StreamChunk frames arriving
// here (the plugin shutting down) are dropped — the conn is closing. A recv
// error ends the drain; the recv loop then returns and its deferred
// close(streamDead) releases the still-parked pull with its partial body (no
// wait for ctx cancellation).
func drainBodyPull(stream pb.Endpoint_HandleConnClient, done <-chan struct{}, getStreamCh func(handle string) chan *pb.StreamChunk) {
	type recvRes struct {
		msg *pb.ConnMessage
		err error
	}
	for {
		select {
		case <-done:
			return
		default:
		}
		ch := make(chan recvRes, 1)
		go func() {
			m, err := stream.Recv()
			ch <- recvRes{m, err}
		}()
		select {
		case <-done:
			return
		case r := <-ch:
			if r.err != nil {
				return
			}
			if sc, ok := r.msg.GetKind().(*pb.ConnMessage_StreamChunk); ok {
				replyCh := getStreamCh(sc.StreamChunk.Handle)
				select {
				case replyCh <- sc.StreamChunk:
				default:
				}
			}
		}
	}
}

// pullBodySample pulls a plugin-offered FACET_STREAM response body up to the
// gateway's body-storage cap, then cancels the stream. It returns the body
// sample (capped, with the truncation marker appended when the body overran
// the cap) and the hex SHA-256 of the captured sample (at most cap+1 bytes).
//
// Unlike the built-in HTTP sampler, this SHA does NOT cover the full upstream
// body: the gateway deliberately stops pulling at cap+1 and cancels the
// stream, so it never sees the bytes past the cap and cannot hash them. That
// is by design — the gateway bounds how much of a plugin response it buffers.
// The sample's shape (capped preview + truncation marker) still matches the
// built-in path so the dashboard renders it identically. Cancelling a stream
// the SDK is still serving is graceful: the SDK drops the registered reader
// and the plugin's source sees a clean close.
func pullBodySample(ctx context.Context, doSend func(*pb.ConnMessage) error, streamReply func(handle string) <-chan *pb.StreamChunk, streamDead <-chan struct{}, handle string, capBytes int) (sample, sha string) {
	bs := newBodySampler(capBytes)
	// Read one extra byte past the cap so we can tell a body that exactly
	// fills the cap (no marker) from one that overran it (marker), matching
	// the built-in sampler's n > cap truncation test.
	pullLimit := capBytes + 1
	data, _ := pullStream(ctx, doSend, streamReply, streamDead, handle, pullLimit)
	// Always cancel so the plugin can release its source, even on EOF.
	_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_StreamCancel{StreamCancel: &pb.StreamCancel{Handle: handle}}})
	bs.write(data)
	return bs.sample(), bs.sha()
}

func (rs *resultState) flush() {
	// Wait for any in-flight body pull to emit its end event first, so we
	// don't race it (it already set rs.ended under the lock, so flushLocked
	// would no-op — but the pull must still get to run to completion and
	// emit). After it returns, flushLocked handles the no-result case.
	rs.awaitPull()
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.flushLocked()
}

// flushLocked persists an unfinished action — no ActionResult arrived (a
// plugin that doesn't report, or a closed conn) — as the end event with an
// empty status, so the action is never lost. Caller holds rs.mu.
func (rs *resultState) flushLocked() {
	if rs.pending == nil || rs.ended {
		return
	}
	end := *rs.pending
	end.Phase = "end"
	rs.ended = true
	if rs.ch.Emit != nil {
		rs.ch.Emit(end)
	}
}

func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

// stringListField extracts a []string from action[key]. JSON decodes a
// list into []any, so string elements are collected and non-string
// elements are skipped; an already-[]string value passes through.
// malformed is true when the key is present but not a list at all (e.g. a
// string or number) — a contract violation the caller can treat as
// unparseable (fail closed) instead of silently coercing to empty. An
// absent key returns (nil, false): nothing was claimed, so nothing is
// wrong.
func stringListField(m map[string]any, key string) (vals []string, malformed bool) {
	v, present := m[key]
	if !present {
		return nil, false
	}
	switch vv := v.(type) {
	case []string:
		return vv, false
	case []any:
		out := make([]string, 0, len(vv))
		for _, item := range vv {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out, false
	}
	return nil, true
}

// builtinRequestFor maps an EvaluateAction's action map onto a
// match.Request shaped the way a built-in facet's matcher expects.
// Plugins that bind their endpoint's Family to a built-in facet
// ("http", "sql") send the action keyed by that facet's CEL
// variables; the gateway translates here so the same matcher the
// gateway's own pipeline runs sees a familiar Request — the endpoint
// reuses the operator's existing http.* / sql.* rules verbatim.
//
// "http" and "sql" are mapped. Other families (k8s, ssh, anything
// bespoke) fall back to a permissive Meta-bag request — a plugin that
// wants those should declare its own facet instead; binding family to a
// built-in we don't map here surfaces as the gateway's default-deny.
func builtinRequestFor(family, peerIP, summary string, action map[string]any, streams map[string][]byte) *match.Request {
	switch family {
	case "sql":
		// The plugin parsed the statement and sent the coarse sql.Meta
		// fields (verb / tables / functions / statement / database); the
		// built-in sql matcher type-asserts req.Meta to *sql.Meta, so build
		// one. A large statement may arrive as a stream field instead of
		// inline JSON.
		tables, badTables := stringListField(action, "tables")
		functions, badFns := stringListField(action, "functions")
		meta := &sql.Meta{
			Verb:      stringField(action, "verb"),
			Tables:    tables,
			Functions: functions,
			Database:  stringField(action, "database"),
		}
		if b, ok := streams["statement"]; ok {
			meta.Statement = string(b)
		} else {
			meta.Statement = stringField(action, "statement")
		}
		req := &match.Request{Family: family, PeerIP: peerIP, Meta: meta}
		// A present-but-wrong-typed list field (a plugin sending `tables`
		// as a string/number instead of a list) is a contract violation.
		// Mark the parse unreliable so sql.verb/tables/functions evaluate to
		// a CEL unknown and any rule referencing them fails closed, rather
		// than silently seeing an empty list and missing a guardrail.
		if badTables || badFns {
			req.Unparseable = true
		}
		return req
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
//
// streamDead is the recv-loop-scoped abort signal: the recv loop closes it
// (via defer) on EVERY exit — clean ConnClose, recv error, agent write
// failure, EOF, plugin crash. Once it's closed no more StreamChunk frames
// can arrive (the loop that routes them is gone), so a pull parked on its
// reply channel would hang until ctx cancellation. Selecting on it here
// releases the pull immediately with whatever bytes it has buffered. We do
// not flag a streamDead abort as truncation: like a recv error, we can't
// tell from outside whether the plugin had more bytes to give.
func pullStream(ctx context.Context, doSend func(*pb.ConnMessage) error, streamReply func(handle string) <-chan *pb.StreamChunk, streamDead <-chan struct{}, handle string, limit int) (data []byte, truncated bool) {
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
		// Bail before issuing another StreamRead if the recv loop is already
		// gone — no chunk could ever come back for it.
		select {
		case <-streamDead:
			return out, false
		default:
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
		case <-streamDead:
			// Recv loop exited (clean or abnormal) while we waited for a
			// chunk: no further chunk can arrive. Return the partial body.
			return out, false
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
	// common holds the framework-level tunnel attrs (via / share /
	// keepalive / credential) the loader peeled from the HCL block before
	// the plugin's schema decode. Exposed via TunnelCommon so the compile
	// pass picks them up exactly like a built-in tunnel.
	common config.TunnelCommon
}

// TunnelCommon hands the framework-level attrs (via / share / keepalive /
// credential) to the compile pass, which resolves `via` and `credential`
// by name against the symbol table. This is what makes `via = <tunnel>`
// (and the share/keepalive knobs) work on a plugin tunnel block.
func (b *dynamicTunnelBody) TunnelCommon() config.TunnelCommon { return b.common }

// dynamicTunnelBody is the CompiledTunnel.Body for a plugin tunnel; it
// implements runtime.TunnelRuntime by delegating to its adapter so the
// gateway's TunnelManager.Acquire can Open it (and thread a `via` parent)
// exactly like a built-in tunnel.
func (b *dynamicTunnelBody) Sharing() runtime.TunnelSharing { return b.adapter.Sharing() }

func (b *dynamicTunnelBody) Open(ctx context.Context, host runtime.TunnelHost, via runtime.Tunnel) (runtime.Tunnel, error) {
	return b.adapter.Open(ctx, host, via)
}

// tunnelAdapter implements runtime.TunnelRuntime via OpenTunnel /
// Dial / CloseTunnel RPCs.
type tunnelAdapter struct {
	client   *Client
	typeName string
}

func (a *tunnelAdapter) Sharing() runtime.TunnelSharing { return runtime.TunnelShareSingleton }

func (a *tunnelAdapter) Open(ctx context.Context, host runtime.TunnelHost, via runtime.Tunnel) (runtime.Tunnel, error) {
	body, ok := tunnelBodyOf(host)
	if !ok {
		return nil, fmt.Errorf("extplugin: tunnel %q has no dynamic body", host.Name)
	}
	// Register this tunnel's transport-dial route and hand the plugin an
	// opaque token. The plugin opens its transport by echoing the token to
	// HostTunnel.DialUpstream; the gateway routes that dial through the
	// parent tunnel when chained (`via = <tunnel>`, via != nil) or directly
	// (via == nil) with its own dialer. The plugin never knows the route —
	// it just dials, like an endpoint plugin's Conn.DialUpstream. The token
	// is registered for every real tunnel, direct or chained.
	var dialToken string
	if a.client.routeReg != nil {
		dialToken = a.client.routeReg.add(via) // via may be nil (direct route)
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
		TunnelTypeName:      a.typeName,
		TunnelInstance:      body.instanceName,
		CanonicalJson:       body.canonicalJSON,
		CredentialSecret:    credSec,
		CredentialExtras:    credExtra,
		TransportDialHandle: dialToken,
	})
	if err != nil {
		if dialToken != "" {
			a.client.routeReg.remove(dialToken)
		}
		return nil, fmt.Errorf("extplugin: OpenTunnel: %w", err)
	}
	return &remoteTunnel{
		client:    a.client,
		handle:    resp.Handle,
		logger:    host.Logger,
		dialToken: dialToken,
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
	client    *Client
	handle    string
	logger    *log.Logger
	dialToken string // non-empty when chained through a parent (`via`)
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
	if t.dialToken != "" && t.client.routeReg != nil {
		t.client.routeReg.remove(t.dialToken)
	}
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
