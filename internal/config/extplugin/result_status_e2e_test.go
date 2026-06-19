package extplugin

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
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
			Name:         resultFacetName,
			ResultFields: []pluginsdk.FacetField{{Name: "status", Title: true}},
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
	t.Helper()
	var mu sync.Mutex
	var events []runtime.ConnEvent
	ch := &runtime.ConnHandle{
		Endpoint:     ep,
		PeerIP:       "1.2.3.4",
		UpstreamHost: "api.example.test",
		DstPort:      443,
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
