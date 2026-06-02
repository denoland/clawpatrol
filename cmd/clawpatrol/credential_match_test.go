package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// TestMITMCredentialPinnedRuleMatchesOnHTTPSPath is a regression test for
// the bug reported in the "Claw Patrol HITL not triggering for Deno Deploy
// sandbox deploy mutations" handoff.
//
// Root cause: the HTTPS MITM handler ran runtime.MatchRequest *before*
// resolving the dispatching credential, and never populated
// match.Request.Credential. So any rule carrying a `credential =
// bearer_token.X` pin (dispatch.go:100-104 compares req.Credential against
// the rule's pin by bare name) was silently skipped on the HTTPS path —
// req.Credential was always "". The request then fell through to a
// low-priority default-deny rule, producing a 403 instead of the intended
// verdict.
//
// This test pins an *allow* rule to the endpoint's credential and adds a
// lower-priority default deny. Before the fix the pinned rule never
// matches and the request is denied (403); after the fix the credential is
// resolved before matching, the pin matches, and the request is forwarded
// upstream (200). The gist's approve→202 symptom shares this exact root
// cause — verdict type is irrelevant to whether the pinned rule is even
// reached.
func TestMITMCredentialPinnedRuleMatchesOnHTTPSPath(t *testing.T) {
	const policyHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential "bearer_token" "pat" {
  endpoint = https.api
}
rule "pat-mutations" {
  endpoint   = https.api
  credential = bearer_token.pat
  priority   = 100
  condition  = "http.method != 'GET'"
  verdict    = "allow"
  reason     = "pinned credential allows mutations"
}
rule "api-default" {
  endpoint = https.api
  priority = -100
  verdict  = "deny"
  reason   = "console mutations require an explicit rule"
}
profile "default" {
  credentials = [bearer_token.pat]
}
`

	h := newCredentialMatchHarness(t, policyHCL)

	t.Run("pinned credential allows mutation", func(t *testing.T) {
		resp := h.send(t, http.MethodPost, `{"app":"avocet-test"}`)
		if resp.status != http.StatusOK {
			t.Fatalf("POST status = %d (body %q); want 200 — the credential-pinned rule should match on the HTTPS path", resp.status, resp.body)
		}
		if !strings.Contains(resp.body, "upstream-ok") {
			t.Fatalf("POST body = %q; want upstream response forwarded", resp.body)
		}
	})

	// Sanity check: the pin must not blanket-allow. A GET fails the rule's
	// `http.method != 'GET'` condition, so it still falls through to the
	// default deny. This guards against a "fix" that ignores the condition.
	t.Run("condition still gates the pinned rule", func(t *testing.T) {
		resp := h.send(t, http.MethodGet, "")
		if resp.status != http.StatusForbidden {
			t.Fatalf("GET status = %d (body %q); want 403 from the default deny", resp.status, resp.body)
		}
	})
}

type credentialMatchHarness struct {
	gateway  *Gateway
	endpoint *config.CompiledEndpoint
}

type credentialMatchResponse struct {
	status int
	body   string
}

func newCredentialMatchHarness(t *testing.T, policyHCL string) *credentialMatchHarness {
	t.Helper()

	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	gw, diags := config.LoadBytes([]byte(policyHCL), "credential-match-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load config: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	ep := policy.Endpoints["api"]
	if ep == nil {
		t.Fatal("missing compiled api endpoint")
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
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
		cfg:     gw,
		db:      db,
		certs:   certs,
		sink:    sink,
		hitl:    newHITLRegistry(sink),
		secrets: newGatewaySecretStore(db, nil),
		onboard: newOnboardRegistry(),
	}
	g.policy.Store(policy)
	g.transports.Store(ep, transport)

	return &credentialMatchHarness{gateway: g, endpoint: ep}
}

func (h *credentialMatchHarness) send(t *testing.T, method, body string) credentialMatchResponse {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.gateway.mitmHTTPS(serverConn, "api.example.test", h.endpoint)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "api.example.test"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://api.example.test/api/v2/sandboxes/sbx_nonexistent/deploy", reqBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// The agent dispatches with a placeholder bearer token, mirroring the
	// gist's `Authorization: Bearer PH_deno_sandbox`.
	req.Header.Set("Authorization", "Bearer PH_pat")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	_ = resp.Body.Close()
	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
	return credentialMatchResponse{status: resp.StatusCode, body: string(respBody)}
}
