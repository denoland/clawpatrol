package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// middlewareHarness drives the HTTPS MITM dispatcher against an upstream
// that records the request body it received, so a test can assert what
// the request-side middleware chain forwarded.
type middlewareHarness struct {
	gateway  *Gateway
	endpoint *config.CompiledEndpoint
	host     string
	lastBody *atomic.Pointer[string]
	upCalled *atomic.Bool
}

func newMiddlewareHarness(t *testing.T, host, policyHCL string) *middlewareHarness {
	t.Helper()

	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	gw, diags := config.LoadBytes([]byte(policyHCL), "mw-chain-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load config: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	ep := policy.Endpoints["anthropic"]
	if ep == nil {
		t.Fatal("missing compiled anthropic endpoint")
	}

	lastBody := &atomic.Pointer[string]{}
	upCalled := &atomic.Bool{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upCalled.Store(true)
		b, _ := io.ReadAll(r.Body)
		s := string(b)
		lastBody.Store(&s)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)

	upstreamAddr := upstream.Listener.Addr().String()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	t.Cleanup(transport.CloseIdleConnections)

	sink, err := NewSink(nil, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { close(sink.ch) })

	certs, _ := inMemoryCertCache(t)
	g := &Gateway{
		db:      db,
		certs:   certs,
		sink:    sink,
		hitl:    newHITLRegistry(sink),
		secrets: newGatewaySecretStore(db, nil),
		onboard: newOnboardRegistry(),
	}
	g.cfg.Store(gw)
	g.policy.Store(policy)
	g.transports.Store(ep, transport)

	return &middlewareHarness{gateway: g, endpoint: ep, host: host, lastBody: lastBody, upCalled: upCalled}
}

type mwResponse struct {
	status int
	body   string
}

func (h *middlewareHarness) post(t *testing.T, path, body string) mwResponse {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.gateway.mitmHTTPS(serverConn, h.host, h.endpoint)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: h.host})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://"+h.host+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
	return mwResponse{status: resp.StatusCode, body: string(respBody)}
}

const mwChainPolicy = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

middleware "anthropic_system_prompt" "first" {
  text = "FIRST"
}
middleware "anthropic_system_prompt" "second" {
  text = "SECOND"
}
endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  middleware = [anthropic_system_prompt.first, anthropic_system_prompt.second]
}
credential "anthropic_manual_key" "key" {
  endpoint = https.anthropic
}
profile "default" {
  credentials = [anthropic_manual_key.key]
}
`

// TestMiddlewareChainOrderedInjection verifies that two middlewares run
// in declared order: the forwarded /v1/messages body carries the base
// system prompt followed by FIRST then SECOND.
func TestMiddlewareChainOrderedInjection(t *testing.T) {
	h := newMiddlewareHarness(t, "api.anthropic.com", mwChainPolicy)

	resp := h.post(t, "/v1/messages", `{"model":"claude","system":"BASE","messages":[]}`)
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d (body %q), want 200", resp.status, resp.body)
	}
	fwd := h.lastBody.Load()
	if fwd == nil {
		t.Fatal("upstream received no body")
	}
	var payload struct {
		System string `json:"system"`
	}
	if err := json.Unmarshal([]byte(*fwd), &payload); err != nil {
		t.Fatalf("forwarded body not JSON: %v (%s)", err, *fwd)
	}
	if want := "BASE\n\nFIRST\n\nSECOND"; payload.System != want {
		t.Errorf("forwarded system = %q, want %q", payload.System, want)
	}
}

// TestMiddlewareChainPassthroughNonMessages verifies a request that the
// middleware doesn't apply to (wrong path) forwards unchanged and still
// reaches upstream.
func TestMiddlewareChainPassthroughNonMessages(t *testing.T) {
	h := newMiddlewareHarness(t, "api.anthropic.com", mwChainPolicy)

	const body = `{"hello":"world"}`
	resp := h.post(t, "/v1/complete", body)
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d (body %q), want 200", resp.status, resp.body)
	}
	fwd := h.lastBody.Load()
	if fwd == nil || *fwd != body {
		t.Errorf("forwarded body = %v, want unchanged %q", fwd, body)
	}
}

// TestMiddlewareChainFailClosed verifies a middleware error (malformed
// /v1/messages JSON) fails the request closed with a 502 and never calls
// upstream.
func TestMiddlewareChainFailClosed(t *testing.T) {
	h := newMiddlewareHarness(t, "api.anthropic.com", mwChainPolicy)

	resp := h.post(t, "/v1/messages", `this is not json`)
	if resp.status != http.StatusBadGateway {
		t.Fatalf("status = %d (body %q), want 502", resp.status, resp.body)
	}
	if h.upCalled.Load() {
		t.Error("upstream was called despite middleware failure — should fail closed")
	}
}
