package extplugin

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"github.com/denoland/clawpatrol/pluginsdk"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// sdkEndpointPlugin wires a real pluginsdk endpoint server (the plugin side)
// AND the gateway's HostControl service (the gateway side) over a single
// go-plugin broker — exactly the multiplexed arrangement the production
// gateway uses. The server half registers the SDK's Endpoint service so the
// gateway's endpointAdapter can drive HandleConn; the client half serves
// HostControl behind the session interceptor so the plugin's inline
// Conn.Evaluate resolves against the connection's session.
type sdkEndpointPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	server   pb.EndpointServer
	sessions *sessionRegistry
}

func (p *sdkEndpointPlugin) GRPCServer(broker *goplugin.GRPCBroker, s *grpc.Server) error {
	// The SDK dials host services (HostControl) through this broker; in
	// production grpcServer.GRPCServer captures it. We register the Endpoint
	// service ourselves, so wire the broker into the SDK's global directly.
	pluginsdk.SetHostBrokerForTest(broker)
	pb.RegisterEndpointServer(s, p.server)
	return nil
}

func (p *sdkEndpointPlugin) GRPCClient(_ context.Context, broker *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	go broker.AcceptAndServe(HostServicesBrokerID, func(opts []grpc.ServerOption) *grpc.Server {
		opts = append(opts, grpc.ChainUnaryInterceptor(sessionUnaryInterceptor(p.sessions)))
		srv := grpc.NewServer(opts...)
		pb.RegisterHostControlServer(srv, hostControl{})
		return srv
	})
	return c, nil
}

// tcpPipe returns a connected pair of loopback TCP conns so the gateway side
// supports CloseWrite (half-close), matching production. The first return
// value is the server (gateway) side, the second the client (agent) side.
func tcpPipe(t *testing.T) (gw, agent net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-accepted
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = r.c.Close() })
	return r.c, a
}

const resultFacetName = "resulttest"

// registerResultFacet installs a synthetic facet whose result schema marks
// "status" as the title — so the gateway lifts result_json["status"] into the
// action's Status, the same shape the aws facet declares. Idempotent across
// the package's tests.
func registerResultFacet(t *testing.T) {
	t.Helper()
	if facet.Lookup(resultFacetName) != nil {
		return
	}
	if diags := registerFacet("resulttestplugin", &pb.FacetDecl{
		Name: resultFacetName,
		Fields: []*pb.FacetFieldDecl{
			{Name: "verb", Kind: pb.FacetKind_FACET_STRING},
		},
		ResultFields: []*pb.FacetFieldDecl{
			{Name: "status", Kind: pb.FacetKind_FACET_STRING, Title: true},
			// body is the FACET_STREAM result field — a response body the
			// gateway pulls up to its cap and cancels.
			{Name: "body", Kind: pb.FacetKind_FACET_STREAM},
		},
	}); diags.HasErrors() {
		t.Fatalf("registerFacet: %v", diags)
	}
}

// startResultPlugin spins up the SDK endpoint plugin with the given
// HandleConn over a real broker and returns a wired endpointAdapter plus the
// compiled endpoint that allows the resulttest facet's GET.
func startResultPlugin(t *testing.T, handle func(ctx context.Context, conn *pluginsdk.Conn) error) (*endpointAdapter, *config.CompiledEndpoint) {
	t.Helper()
	registerResultFacet(t)

	endpoint := pluginsdk.EndpointDef{
		TypeName:   "resulttest_api",
		Family:     resultFacetName,
		TLSMode:    pluginsdk.TLSNone,
		HandleConn: handle,
	}
	sdkSrv := pluginsdk.NewEndpointServerForTest(&pluginsdk.Plugin{
		Name:    "resulttestplugin",
		Version: "0.0.1",
		Facets: []pluginsdk.FacetDef{{
			Name: resultFacetName,
			ResultFields: []pluginsdk.FacetField{
				{Name: "status", Title: true},
				{Name: "body", Kind: pluginsdk.FacetStream},
			},
		}},
		Endpoints: []pluginsdk.EndpointDef{endpoint},
	})

	sessions := newSessionRegistry()
	p := &sdkEndpointPlugin{server: sdkSrv, sessions: sessions}
	gpClient, _ := goplugin.TestPluginGRPCConn(t, true, map[string]goplugin.Plugin{"x": p})
	t.Cleanup(func() { _ = gpClient.Close() })
	raw, err := gpClient.Dispense("x")
	if err != nil {
		t.Fatalf("dispense: %v", err)
	}
	conn, ok := raw.(*grpc.ClientConn)
	if !ok {
		t.Fatalf("dispense returned %T, want *grpc.ClientConn", raw)
	}

	client := &Client{endpoint: pb.NewEndpointClient(conn), sessions: sessions}
	adapter := &endpointAdapter{client: client, typeName: "resulttest_api"}

	m, err := facet.NewMatcher(resultFacetName, "resulttest.verb == 'GET'")
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	ep := &config.CompiledEndpoint{
		Name:   "resulttest-ep",
		Family: resultFacetName,
		Rules: []*config.CompiledRule{
			{Name: "allow-get", Matcher: m, Outcome: config.Outcome{Verdict: "allow"}},
		},
		Plugin: &config.Plugin{Family: resultFacetName},
		Body:   &dynamicEndpointBody{adapter: adapter, instanceName: "resulttest1"},
	}
	return adapter, ep
}

// runResultConn drives one connection through the adapter with the supplied
// agent behaviour and returns the emitted events.
func runResultConn(t *testing.T, adapter *endpointAdapter, ep *config.CompiledEndpoint, drive func(agent net.Conn)) []runtime.ConnEvent {
	return runResultConnCap(t, adapter, ep, 0, drive)
}

// runResultConnCap is runResultConn with an explicit response-body cap on the
// ConnHandle (0 = gateway default). The body cap bounds the FACET_STREAM
// response-body sample the gateway pulls.
func runResultConnCap(t *testing.T, adapter *endpointAdapter, ep *config.CompiledEndpoint, bodyCap int, drive func(agent net.Conn)) []runtime.ConnEvent {
	t.Helper()
	var mu sync.Mutex
	var events []runtime.ConnEvent
	ch := &runtime.ConnHandle{
		Endpoint:       ep,
		PeerIP:         "1.2.3.4",
		UpstreamHost:   "api.example.test",
		DstPort:        443,
		BodyStorageCap: bodyCap,
		Emit: func(ev runtime.ConnEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	}
	gw, agent := tcpPipe(t)
	ch.Conn = gw

	done := make(chan error, 1)
	go func() { done <- adapter.HandleConn(context.Background(), ch) }()
	go drive(agent)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("HandleConn did not return")
	}
	mu.Lock()
	defer mu.Unlock()
	return append([]runtime.ConnEvent(nil), events...)
}

// startEnd splits captured events into the start and end of the action.
func startEnd(events []runtime.ConnEvent) (start, end *runtime.ConnEvent) {
	for i := range events {
		switch events[i].Phase {
		case "start":
			start = &events[i]
		case "end":
			end = &events[i]
		}
	}
	return start, end
}

// awsShapedHandle mirrors the aws plugin's handleAWS tail: read the request,
// evaluate inline (allowed), report the outcome via SetResult, then write the
// response and return.
func awsShapedHandle(ctx context.Context, conn *pluginsdk.Conn) error {
	br := bufio.NewReader(conn)
	if _, err := readHTTPRequestLine(br); err != nil {
		return err
	}
	v, err := conn.Evaluate(ctx, resultFacetName, map[string]any{"verb": "GET"}, "GET /")
	if err != nil {
		return err
	}
	if v.Action != "allow" && v.Action != "hitl_allow" {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
		return nil
	}
	if err := conn.SetResult(ctx, map[string]any{"status": "200"}); err != nil {
		return err
	}
	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	return nil
}

// readHTTPRequestLine consumes a request's headers up to the blank line so the
// handler proceeds without pulling in net/http just to parse a fixed request.
func readHTTPRequestLine(br *bufio.Reader) (string, error) {
	first, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return first, err
		}
		if line == "\r\n" || line == "\n" {
			return first, nil
		}
	}
}

// TestEndpointSetResultStatusCaptured drives the happy path: the agent reads
// the full response before closing. The terminal "end" event must carry the
// plugin-reported status.
func TestEndpointSetResultStatusCaptured(t *testing.T) {
	adapter, ep := startResultPlugin(t, awsShapedHandle)
	events := runResultConn(t, adapter, ep, func(agent net.Conn) {
		_, _ = agent.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
		_, _ = io.Copy(io.Discard, agent)
		_ = agent.Close()
	})

	start, end := startEnd(events)
	if start == nil {
		t.Fatalf("no start event; events=%+v", events)
	}
	if end == nil {
		t.Fatalf("no end event; events=%+v", events)
	}
	if end.ID != start.ID {
		t.Errorf("end.ID=%q != start.ID=%q", end.ID, start.ID)
	}
	if end.Status != "200" {
		t.Fatalf("end.Status=%q, want \"200\"; events=%+v", end.Status, events)
	}
}

// TestEndpointSetResultStatusAgentClosesFirst exercises the production-shaped
// teardown the empty-status bug was blamed on: the agent sends its request and
// closes the connection without waiting to read the response (a cancelled /
// timed-out client), driving pumpConn's agentDone path. The ActionResult the
// plugin sent must still surface as the end event's status — not get clobbered
// by the empty flush-on-close.
func TestEndpointSetResultStatusAgentClosesFirst(t *testing.T) {
	adapter, ep := startResultPlugin(t, awsShapedHandle)
	events := runResultConn(t, adapter, ep, func(agent net.Conn) {
		_, _ = agent.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
		// Close immediately without reading the response.
		_ = agent.Close()
	})

	start, end := startEnd(events)
	if start == nil {
		t.Fatalf("no start event; events=%+v", events)
	}
	if end == nil {
		t.Fatalf("no end event; events=%+v", events)
	}
	if end.Status != "200" {
		t.Fatalf("end.Status=%q, want \"200\" — status lost on agent-closes-first; events=%+v", end.Status, events)
	}
}

// TestEndpointSetResultStatusNoResponseBody covers a plugin that reports its
// outcome via SetResult and returns without writing a response body — the
// ActionResult is the last application frame before the SDK's ConnClose. The
// end event must still carry the status.
func TestEndpointSetResultStatusNoResponseBody(t *testing.T) {
	adapter, ep := startResultPlugin(t, func(ctx context.Context, conn *pluginsdk.Conn) error {
		br := bufio.NewReader(conn)
		if _, err := readHTTPRequestLine(br); err != nil {
			return err
		}
		v, err := conn.Evaluate(ctx, resultFacetName, map[string]any{"verb": "GET"}, "GET /")
		if err != nil {
			return err
		}
		if v.Action != "allow" {
			return nil
		}
		return conn.SetResult(ctx, map[string]any{"status": "204"})
	})
	events := runResultConn(t, adapter, ep, func(agent net.Conn) {
		_, _ = agent.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
		_, _ = io.Copy(io.Discard, agent)
		_ = agent.Close()
	})
	_, end := startEnd(events)
	if end == nil {
		t.Fatalf("no end event; events=%+v", events)
	}
	if end.Status != "204" {
		t.Fatalf("end.Status=%q, want \"204\"; events=%+v", end.Status, events)
	}
}

// cancelTrackingReader wraps a body reader and records whether the SDK closed
// it (the graceful response to the gateway's StreamCancel) versus the plugin
// observing a hard read error. Used to assert that capping/cancelling a
// response-body stream does not error the plugin.
type cancelTrackingReader struct {
	r      io.Reader
	closed atomic.Bool
}

func (c *cancelTrackingReader) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *cancelTrackingReader) Close() error {
	c.closed.Store(true)
	return nil
}

// bodyResultHandle returns a HandleConn that evaluates (allowed), reports its
// outcome via SetResult with a FACET_STREAM body of the given size, writes a
// short response, and returns. The reader it offers is recorded so the test
// can assert the gateway's cancel closed it gracefully.
func bodyResultHandle(bodySize int, reader **cancelTrackingReader) func(ctx context.Context, conn *pluginsdk.Conn) error {
	return func(ctx context.Context, conn *pluginsdk.Conn) error {
		br := bufio.NewReader(conn)
		if _, err := readHTTPRequestLine(br); err != nil {
			return err
		}
		v, err := conn.Evaluate(ctx, resultFacetName, map[string]any{"verb": "GET"}, "GET /")
		if err != nil {
			return err
		}
		if v.Action != "allow" && v.Action != "hitl_allow" {
			return nil
		}
		body := bytes.Repeat([]byte("A"), bodySize)
		ctr := &cancelTrackingReader{r: bytes.NewReader(body)}
		*reader = ctr
		if err := conn.SetResult(ctx, map[string]any{
			"status": "200",
			"body":   pluginsdk.Stream(ctr),
		}); err != nil {
			return err
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		return nil
	}
}

// TestEndpointSetResultBodyCapped offers a response body LARGER than the cap.
// The gateway must pull up to the cap, append the truncation marker, and set
// the sample on the end event — and cancelling the stream must not error the
// plugin (its reader is closed cleanly, HandleConn returns nil).
func TestEndpointSetResultBodyCapped(t *testing.T) {
	const capBytes = 16
	var reader *cancelTrackingReader
	adapter, ep := startResultPlugin(t, bodyResultHandle(capBytes*8, &reader))

	var handleErr error
	var mu sync.Mutex
	var events []runtime.ConnEvent
	ch := &runtime.ConnHandle{
		Endpoint:       ep,
		PeerIP:         "1.2.3.4",
		UpstreamHost:   "api.example.test",
		DstPort:        443,
		BodyStorageCap: capBytes,
		Emit: func(ev runtime.ConnEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	}
	gw, agent := tcpPipe(t)
	ch.Conn = gw
	done := make(chan struct{})
	go func() { handleErr = adapter.HandleConn(context.Background(), ch); close(done) }()
	go func() {
		_, _ = agent.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
		_, _ = io.Copy(io.Discard, agent)
		_ = agent.Close()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("HandleConn did not return")
	}

	mu.Lock()
	evs := append([]runtime.ConnEvent(nil), events...)
	mu.Unlock()
	_, end := startEnd(evs)
	if end == nil {
		t.Fatalf("no end event; events=%+v", evs)
	}
	if end.Status != "200" {
		t.Errorf("end.Status=%q, want \"200\"", end.Status)
	}
	if !strings.HasSuffix(end.RespBody, bodyTruncatedMarker) {
		t.Fatalf("RespBody missing truncation marker; got %q", end.RespBody)
	}
	prefix := strings.TrimSuffix(end.RespBody, bodyTruncatedMarker)
	if len(prefix) != capBytes {
		t.Errorf("capped prefix len=%d, want %d; RespBody=%q", len(prefix), capBytes, end.RespBody)
	}
	if prefix != strings.Repeat("A", capBytes) {
		t.Errorf("capped prefix=%q, want %d A's", prefix, capBytes)
	}
	if end.RespSha == "" {
		t.Errorf("RespSha empty for a non-empty body")
	}
	if handleErr != nil {
		t.Errorf("plugin HandleConn errored by gateway cancel: %v", handleErr)
	}
	if reader == nil {
		t.Errorf("plugin body reader was nil")
	} else {
		// The gateway's StreamCancel and the SDK closing the plugin's reader
		// are asynchronous to the end event (the gateway emits the end as soon
		// as it has the capped sample; the cancel propagates separately). Wait,
		// bounded, for the close to land rather than racing it.
		deadline := time.Now().Add(2 * time.Second)
		for !reader.closed.Load() && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if !reader.closed.Load() {
			t.Errorf("plugin body reader was not closed by the gateway's StreamCancel (graceful cancel)")
		}
	}
}

// blockingBodyReader serves a fixed prefix once, then parks every subsequent
// Read until release is closed. It signals reading exactly once (the first
// time the SDK pulls a chunk on the gateway's behalf) so a test can learn the
// gateway's body pull is genuinely in flight before it tears the transport
// down. Returning io.EOF after release lets the parked Read unwind cleanly.
type blockingBodyReader struct {
	prefix    []byte
	served    atomic.Bool
	reading   chan struct{} // closed once, when the first Read lands
	readingMu sync.Once
	release   chan struct{} // test closes this to unblock the parked Read
}

func newBlockingBodyReader(prefix []byte) *blockingBodyReader {
	return &blockingBodyReader{
		prefix:  prefix,
		reading: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *blockingBodyReader) Read(p []byte) (int, error) {
	b.readingMu.Do(func() { close(b.reading) })
	if b.served.CompareAndSwap(false, true) {
		n := copy(p, b.prefix)
		return n, nil
	}
	// Park until the test releases us; then report EOF so the SDK reader
	// goroutine unwinds without leaking.
	<-b.release
	return 0, io.EOF
}

// TestEndpointSetResultBodyPullConnErrorsNoHang is the regression for the
// mid-pull deadlock: a response-body pull is in flight (the gateway issued a
// StreamRead and is parked waiting for the next StreamChunk) when the plugin
// connection dies UNCLEANLY — the transport is torn down, so the recv loop
// exits via stream.Recv()'s error path, NOT a clean ConnClose. Before the fix
// the parked pull could only be released by ctx cancellation, which can't fire
// because HandleConn's deferred flush awaits that very pull: a permanent hang.
//
// Asserts: the end event is still emitted exactly once, carrying the status
// and the partial body captured before the abort, and HandleConn returns —
// all within a deadline, so a regression hangs the test instead of passing.
func TestEndpointSetResultBodyPullConnErrorsNoHang(t *testing.T) {
	registerResultFacet(t)

	body := newBlockingBodyReader([]byte("PARTIAL-BODY"))
	handlerBlocked := make(chan struct{})
	handle := func(ctx context.Context, conn *pluginsdk.Conn) error {
		br := bufio.NewReader(conn)
		if _, err := readHTTPRequestLine(br); err != nil {
			return err
		}
		v, err := conn.Evaluate(ctx, resultFacetName, map[string]any{"verb": "GET"}, "GET /")
		if err != nil {
			return err
		}
		if v.Action != "allow" && v.Action != "hitl_allow" {
			return nil
		}
		if err := conn.SetResult(ctx, map[string]any{
			"status": "200",
			"body":   pluginsdk.Stream(body),
		}); err != nil {
			return err
		}
		// Do NOT return: returning would queue a clean ConnClose, which the
		// drainBodyPull path already handles. We want the recv loop to exit
		// via the transport-error path instead, so block until torn down.
		close(handlerBlocked)
		<-ctx.Done()
		return ctx.Err()
	}

	// Build the wiring inline (rather than via startResultPlugin) so we keep a
	// handle on the go-plugin client and can sever the transport mid-pull.
	endpoint := pluginsdk.EndpointDef{
		TypeName:   "resulttest_api",
		Family:     resultFacetName,
		TLSMode:    pluginsdk.TLSNone,
		HandleConn: handle,
	}
	sdkSrv := pluginsdk.NewEndpointServerForTest(&pluginsdk.Plugin{
		Name:    "resulttestplugin",
		Version: "0.0.1",
		Facets: []pluginsdk.FacetDef{{
			Name: resultFacetName,
			ResultFields: []pluginsdk.FacetField{
				{Name: "status", Title: true},
				{Name: "body", Kind: pluginsdk.FacetStream},
			},
		}},
		Endpoints: []pluginsdk.EndpointDef{endpoint},
	})
	sessions := newSessionRegistry()
	p := &sdkEndpointPlugin{server: sdkSrv, sessions: sessions}
	gpClient, _ := goplugin.TestPluginGRPCConn(t, true, map[string]goplugin.Plugin{"x": p})
	t.Cleanup(func() { _ = gpClient.Close() })
	raw, err := gpClient.Dispense("x")
	if err != nil {
		t.Fatalf("dispense: %v", err)
	}
	grpcConn, ok := raw.(*grpc.ClientConn)
	if !ok {
		t.Fatalf("dispense returned %T, want *grpc.ClientConn", raw)
	}
	client := &Client{endpoint: pb.NewEndpointClient(grpcConn), sessions: sessions}
	adapter := &endpointAdapter{client: client, typeName: "resulttest_api"}

	m, err := facet.NewMatcher(resultFacetName, "resulttest.verb == 'GET'")
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	ep := &config.CompiledEndpoint{
		Name:   "resulttest-ep",
		Family: resultFacetName,
		Rules: []*config.CompiledRule{
			{Name: "allow-get", Matcher: m, Outcome: config.Outcome{Verdict: "allow"}},
		},
		Plugin: &config.Plugin{Family: resultFacetName},
		Body:   &dynamicEndpointBody{adapter: adapter, instanceName: "resulttest1"},
	}

	const bodyCap = 4096
	var mu sync.Mutex
	var events []runtime.ConnEvent
	ch := &runtime.ConnHandle{
		Endpoint:       ep,
		PeerIP:         "1.2.3.4",
		UpstreamHost:   "api.example.test",
		DstPort:        443,
		BodyStorageCap: bodyCap,
		Emit: func(ev runtime.ConnEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	}
	gw, agent := tcpPipe(t)
	ch.Conn = gw

	done := make(chan error, 1)
	go func() { done <- adapter.HandleConn(context.Background(), ch) }()
	go func() {
		_, _ = agent.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
		// Drain in the background; the conn is torn down by the transport
		// sever below, not the agent.
		_, _ = io.Copy(io.Discard, agent)
	}()

	// Wait until the gateway's body pull is genuinely in flight: the SDK's
	// reader has been invoked (first StreamRead delivered) and the handler is
	// parked after SetResult.
	select {
	case <-body.reading:
	case <-time.After(5 * time.Second):
		t.Fatal("body pull never started (reader Read not invoked)")
	}
	select {
	case <-handlerBlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never reached its post-SetResult block")
	}

	// Sever the plugin transport. The gateway's stream.Recv() now errors and
	// the recv loop exits via its NON-ConnClose path, with the pull parked.
	_ = gpClient.Close()
	close(body.release)
	// Close the agent side too so pumpConn's teardown doesn't sit on the
	// 30s connDrainTimeout waiting for the agent to read a response that the
	// dead plugin will never produce. This is orthogonal to the deadlock: the
	// pull is released by streamDead regardless, but closing the agent keeps
	// the test's deadline tight and exercises the agentDone teardown path
	// whose deferred flush is exactly where the pre-fix hang lived.
	_ = agent.Close()

	// The fix must release the parked pull and let HandleConn return. A
	// regression hangs here instead.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleConn did not return after mid-pull transport error (deadlock regression)")
	}

	mu.Lock()
	evs := append([]runtime.ConnEvent(nil), events...)
	mu.Unlock()

	start, end := startEnd(evs)
	if start == nil {
		t.Fatalf("no start event; events=%+v", evs)
	}
	if end == nil {
		t.Fatalf("no end event — action lost on mid-pull abort; events=%+v", evs)
	}
	// Exactly one end event (no double-emit between the pull goroutine and
	// flush).
	ends := 0
	for i := range evs {
		if evs[i].Phase == "end" {
			ends++
		}
	}
	if ends != 1 {
		t.Fatalf("want exactly one end event, got %d; events=%+v", ends, evs)
	}
	if end.Status != "200" {
		t.Errorf("end.Status=%q, want \"200\"; events=%+v", end.Status, evs)
	}
	// The partial body captured before the abort surfaces on the end event.
	if end.RespBody != "PARTIAL-BODY" {
		t.Errorf("end.RespBody=%q, want %q (partial body before abort)", end.RespBody, "PARTIAL-BODY")
	}
}

// TestEndpointSetResultBodySmall offers a response body SMALLER than the cap.
// The full body must surface on the end event with no truncation marker.
func TestEndpointSetResultBodySmall(t *testing.T) {
	const capBytes = 4096
	const bodyLen = 11
	want := strings.Repeat("A", bodyLen)
	var reader *cancelTrackingReader
	adapter, ep := startResultPlugin(t, bodyResultHandle(bodyLen, &reader))

	events := runResultConnCap(t, adapter, ep, capBytes, func(agent net.Conn) {
		_, _ = agent.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
		_, _ = io.Copy(io.Discard, agent)
		_ = agent.Close()
	})
	_, end := startEnd(events)
	if end == nil {
		t.Fatalf("no end event; events=%+v", events)
	}
	if end.Status != "200" {
		t.Errorf("end.Status=%q, want \"200\"", end.Status)
	}
	if strings.Contains(end.RespBody, bodyTruncatedMarker) {
		t.Errorf("small body should not be truncated; RespBody=%q", end.RespBody)
	}
	if end.RespBody != want {
		t.Errorf("RespBody=%q, want %q", end.RespBody, want)
	}
}
