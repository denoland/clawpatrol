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

	"github.com/denoland/clawpatrol/internal/config"
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

	h := newEndpointHarness(t, hcl, config.UnknownInspectEndpoint)
	page := inspectUnknownSend(t, h.gateway, "/")
	if page.status != http.StatusOK || !strings.Contains(page.body, "upstream-ok") {
		t.Fatalf("GET / = %d %q, want 200 upstream-ok", page.status, page.body)
	}
	denied := inspectUnknownSend(t, h.gateway, "/pkg.tgz")
	if denied.status != http.StatusForbidden {
		t.Fatalf("GET /pkg.tgz = %d %q, want 403", denied.status, denied.body)
	}
	if strings.Contains(denied.body, "upstream-ok") {
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
