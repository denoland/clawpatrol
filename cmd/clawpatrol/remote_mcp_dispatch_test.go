package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestUnmatchedHTTPSTransportIsGatewayOwned(t *testing.T) {
	tr := (&Gateway{}).unmatchedHTTPSTransport()
	if tr == nil {
		t.Fatal("unmatchedHTTPSTransport returned nil")
	}
	defer tr.CloseIdleConnections()
	if tr == http.DefaultTransport {
		t.Fatal("unmatched HTTPS forwarding must not use http.DefaultTransport")
	}
	if tr.Proxy != nil {
		t.Fatal("unmatched HTTPS forwarding must not inherit environment proxy settings")
	}
	if tr.DialContext == nil {
		t.Fatal("unmatched HTTPS forwarding must use a gateway-owned dialer")
	}
	if tr.DialTLSContext == nil {
		t.Fatal("unmatched HTTPS forwarding must use explicit gateway-owned TLS dialing")
	}
	if tr.ForceAttemptHTTP2 {
		t.Fatal("unmatched HTTPS forwarding should preserve the gateway's HTTP/1.1-only MITM upstream behavior")
	}
}

func TestForwardUnmatchedHTTPSFailsClosedOnForwardError(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := http.NewRequest("GET", "https://127.0.0.1:1/v1/users", nil)
		if err != nil {
			t.Errorf("new request: %v", err)
			return
		}
		req.RequestURI = "/v1/users"
		(&Gateway{}).forwardUnmatchedHTTPS(serverConn, req, "127.0.0.1:1", Event{Action: "passthrough"}, time.Now())
		_ = serverConn.Close()
	}()

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("response = %d %q, want 502", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwardUnmatchedHTTPS did not return")
	}
}
