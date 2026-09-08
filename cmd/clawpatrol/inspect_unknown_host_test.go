package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
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

	h := newCredentialMatchHarness(t, hcl, "unknown")
	page := inspectUnknownSend(t, h.gateway, unknownHostSNI, "/")
	if page.status != http.StatusOK || !strings.Contains(page.body, "upstream-ok") {
		t.Fatalf("GET / = %d %q, want 200 upstream-ok", page.status, page.body)
	}
	denied := inspectUnknownSend(t, h.gateway, unknownHostSNI, "/pkg.tgz")
	if denied.status != http.StatusForbidden {
		t.Fatalf("GET /pkg.tgz = %d %q, want 403", denied.status, denied.body)
	}
	if strings.Contains(denied.body, "upstream-ok") {
		t.Fatal("deny leaked to upstream")
	}
}

func TestInspectNamedHostWins(t *testing.T) {
	const hcl = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

defaults { unknown_host = "inspect" }

endpoint "https" "api" { hosts = ["api.example.test"] }
endpoint "https" "unknown" { hosts = [] }

credential "bearer_token" "tok" { endpoint = https.api }

rule "deny-unknown" {
  endpoint  = https.unknown
  priority  = 100
  condition = "true"
  verdict   = "deny"
}

rule "allow-api" {
  endpoint  = https.api
  priority  = 100
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [bearer_token.tok] }
`

	h := newCredentialMatchHarness(t, hcl, "unknown")
	api := h.gateway.Policy().Endpoints["api"]
	if api == nil {
		t.Fatal("missing compiled api endpoint")
	}
	if tr, ok := h.gateway.transports.Load(h.endpoint); ok {
		h.gateway.transports.Store(api, tr)
	}

	named := inspectUnknownSend(t, h.gateway, "api.example.test", "/")
	if named.status != http.StatusOK || !strings.Contains(named.body, "upstream-ok") {
		t.Fatalf("named GET / = %d %q, want 200 upstream-ok", named.status, named.body)
	}
	unknown := inspectUnknownSend(t, h.gateway, unknownHostSNI, "/")
	if unknown.status != http.StatusForbidden {
		t.Fatalf("unknown GET / = %d %q, want 403", unknown.status, unknown.body)
	}
}

func inspectUnknownSend(t *testing.T, g *Gateway, host, path string) credentialMatchResponse {
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
		ServerName:         host,
		NextProtos:         []string{"http/1.1"},
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
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
