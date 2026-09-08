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

func TestInspectUnknownHostRules(t *testing.T) {
	const hcl = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

defaults { unknown_host = "inspect" }

endpoint "https" "unknown" { hosts = [] }

rule "deny-tgz" {
  endpoint  = https.unknown
  priority  = 100
  condition = "http.path.endsWith('.tgz')"
  verdict   = "deny"
  reason    = "package resolve"
}

rule "allow-unknown" {
  endpoint  = https.unknown
  priority  = -100
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [] }
`

	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	gw, diags := config.LoadBytes([]byte(hcl), "inspect-unknown-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := policy.UnknownInspect
	if ep == nil {
		t.Fatal("missing UnknownInspect")
	}

	var hits int
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("page-ok"))
	}))
	t.Cleanup(upstream.Close)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstream.Listener.Addr().String())
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

	page := inspectUnknownSend(t, g, "/")
	if page.status != http.StatusOK || !strings.Contains(page.body, "page-ok") {
		t.Fatalf("GET / = %d %q, want 200 page-ok", page.status, page.body)
	}
	beforeDeny := hits
	denied := inspectUnknownSend(t, g, "/pkg.tgz")
	if denied.status != http.StatusForbidden {
		t.Fatalf("GET /pkg.tgz = %d %q, want 403", denied.status, denied.body)
	}
	if hits != beforeDeny {
		t.Fatal("deny leaked to upstream")
	}
}

func inspectUnknownSend(t *testing.T, g *Gateway, path string) credentialMatchResponse {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	g.onboard.profileByIP[peerIP(serverConn)] = "default"
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handle(serverConn, "", 443)
	}()
	if err := clientConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         unknownHostSNI,
		NextProtos:         []string{"http/1.1"},
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+unknownHostSNI+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()
	// Close the raw pipe first. tls.Conn.Close deadlocks on net.Pipe
	// if handle() is blocked in ReadRequest.
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return credentialMatchResponse{status: resp.StatusCode, body: string(body)}
}
