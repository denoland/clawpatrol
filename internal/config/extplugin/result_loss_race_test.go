package extplugin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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

// slowBodyReader serves a fixed body but delays each Read a touch, so the
// gateway's body pull is reliably still in flight (parked on a StreamChunk)
// while the connection tears down. This widens the window the result-loss race
// lives in.
type slowBodyReader struct {
	r     *bytes.Reader
	delay time.Duration
}

func (s *slowBodyReader) Read(p []byte) (int, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return s.r.Read(p)
}
func (s *slowBodyReader) Close() error { return nil }

// bodyResultHandleSlow reports a result with a FACET_STREAM body, then writes a
// short response and returns immediately — the production aws_api shape. The
// body is served with a small per-read delay.
func bodyResultHandleSlow(body []byte, delay time.Duration) func(ctx context.Context, conn *pluginsdk.Conn) error {
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
		if err := conn.SetResult(ctx, map[string]any{
			"status": "200",
			"body":   pluginsdk.Stream(&slowBodyReader{r: bytes.NewReader(body), delay: delay}),
		}); err != nil {
			return err
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		return nil
	}
}

// newResultPluginShared builds one SDK endpoint plugin over a single broker and
// returns an adapter + endpoint that can drive MANY connections — the
// production arrangement (one plugin subprocess, many conns), unlike
// startResultPlugin which the existing tests use per-test. Reusing one plugin
// process across iterations is what surfaces the "first conns after a fresh
// spawn" loss.
func newResultPluginShared(t *testing.T, handle func(ctx context.Context, conn *pluginsdk.Conn) error) (*endpointAdapter, *config.CompiledEndpoint) {
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

// driveResultConnEvents runs one connection through the adapter with the given
// agent behaviour and returns the captured events for that conn.
func driveResultConnEvents(adapter *endpointAdapter, ep *config.CompiledEndpoint, bodyCap int, drive func(agent net.Conn)) ([]runtime.ConnEvent, error) {
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	agent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, err
	}
	gw := <-accepted
	if gw == nil {
		return nil, fmt.Errorf("accept failed")
	}
	ch.Conn = gw

	done := make(chan error, 1)
	go func() { done <- adapter.HandleConn(context.Background(), ch) }()
	go drive(agent)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("HandleConn did not return")
	}
	_ = agent.Close()
	_ = gw.Close()
	mu.Lock()
	defer mu.Unlock()
	return append([]runtime.ConnEvent(nil), events...), nil
}

// TestEndpointResultLossRace stresses the plugin result lifecycle the way
// production does: one plugin subprocess, many sequential one-shot connections,
// each reporting a status + FACET_STREAM body, with the agent closing as soon
// as it has the response (a fast / cancelled client). The body pull is in
// flight when the conn tears down. EVERY connection's end event must carry both
// the reported status ("200") and the body — never an empty flush end.
func TestEndpointResultLossRace(t *testing.T) {
	const body = "RESPONSE-BODY-CONTENTS"
	adapter, ep := newResultPluginShared(t, bodyResultHandleSlow([]byte(body), 2*time.Millisecond))

	iters := 200
	if testing.Short() {
		iters = 30
	}
	for i := 0; i < iters; i++ {
		events, err := driveResultConnEvents(adapter, ep, 4096, func(agent net.Conn) {
			_, _ = agent.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
			// Read the response then close immediately — the fast client the
			// production loss showed up on.
			br := bufio.NewReader(agent)
			_, _ = readHTTPRequestLine(br)
			_ = agent.Close()
		})
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		start, end := startEnd(events)
		if start == nil {
			t.Fatalf("iter %d: no start event; events=%+v", i, events)
		}
		if end == nil {
			t.Fatalf("iter %d: no end event; events=%+v", i, events)
		}
		// Exactly one end event.
		ends := 0
		for j := range events {
			if events[j].Phase == "end" {
				ends++
			}
		}
		if ends != 1 {
			t.Fatalf("iter %d: want exactly one end event, got %d; events=%+v", i, ends, events)
		}
		if end.Status != "200" {
			t.Fatalf("iter %d: end.Status=%q, want %q — STATUS LOST; events=%+v", i, end.Status, "200", events)
		}
		if end.RespBody != body {
			t.Fatalf("iter %d: end.RespBody=%q, want %q — BODY LOST; events=%+v", i, end.RespBody, body, events)
		}
	}
}

// TestEndpointResultLossRaceAgentAbandons is the harsher teardown: the agent
// fires its request and closes WITHOUT reading the response (a cancelled /
// timed-out client). The plugin still reports its status + body. The body
// sample may legitimately be partial or empty here (the gateway tears the
// agent side down before the response is consumed), but the STATUS must never
// be lost and exactly one end event must persist — the regression dropped both
// status and body together.
func TestEndpointResultLossRaceAgentAbandons(t *testing.T) {
	const body = "RESPONSE-BODY-CONTENTS"
	adapter, ep := newResultPluginShared(t, bodyResultHandleSlow([]byte(body), 2*time.Millisecond))

	iters := 200
	if testing.Short() {
		iters = 30
	}
	for i := 0; i < iters; i++ {
		events, err := driveResultConnEvents(adapter, ep, 4096, func(agent net.Conn) {
			_, _ = agent.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
			// Close immediately without reading the response.
			_ = agent.Close()
		})
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		start, end := startEnd(events)
		if start == nil {
			t.Fatalf("iter %d: no start event; events=%+v", i, events)
		}
		if end == nil {
			t.Fatalf("iter %d: no end event; events=%+v", i, events)
		}
		ends := 0
		for j := range events {
			if events[j].Phase == "end" {
				ends++
			}
		}
		if ends != 1 {
			t.Fatalf("iter %d: want exactly one end event, got %d; events=%+v", i, ends, events)
		}
		if end.Status != "200" {
			t.Fatalf("iter %d: end.Status=%q, want %q — STATUS LOST; events=%+v", i, end.Status, "200", events)
		}
	}
}

var _ = io.Discard
