package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

func TestHandleInterceptsRawIPHTTPSOnDeclaredNonDefaultPort(t *testing.T) {
	const rawIP = "192.168.1.50"
	const rawPort uint16 = 8006

	gw, policy, ep := compileRawIPPolicy(t, rawIP, rawPort)
	certs, _ := inMemoryCertCache(t)
	sink, err := NewSink(nil, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer close(sink.ch)
	events, cancel := sink.Subscribe()
	defer cancel()

	upstreamSeen := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	defer tr.CloseIdleConnections()

	g := &Gateway{certs: certs, sink: sink, secrets: fakeSecretStore{}}
	g.cfg.Store(gw)
	g.policy.Store(policy)
	g.transports.Store(ep, tr)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handle(serverConn, rawIP, rawPort)
	}()

	// No ServerName means no SNI, matching clients that connect to a
	// TLS service via an IP literal.
	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
	defer func() { _ = clientTLS.Close() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+net.JoinHostPort(rawIP, "8006")+"/api2/json/version", nil)
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
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response = %d %q, want 200 ok", resp.StatusCode, body)
	}

	select {
	case got := <-upstreamSeen:
		if got != net.JoinHostPort(rawIP, "8006") {
			t.Fatalf("upstream Host = %q, want %q", got, net.JoinHostPort(rawIP, "8006"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}

	var sawEnd bool
	deadline := time.After(2 * time.Second)
	for !sawEnd {
		select {
		case pkt := <-events:
			ev := pkt.ev
			if ev.Mode != "mitm" {
				continue
			}
			if ev.Host != net.JoinHostPort(rawIP, "8006") {
				t.Fatalf("event Host = %q, want %q", ev.Host, net.JoinHostPort(rawIP, "8006"))
			}
			if ev.Endpoint != "proxmox" {
				t.Fatalf("event Endpoint = %q, want proxmox", ev.Endpoint)
			}
			if ev.Phase == "end" {
				sawEnd = true
			}
		case <-deadline:
			t.Fatal("timed out waiting for dashboard event")
		}
	}

	_ = clientTLS.Close()
	<-done
}

func TestRawIPHTTPSMITMPortDispatchIsLimitedToDeclaredEndpoints(t *testing.T) {
	const rawIP = "192.168.1.50"
	gw, policy, _ := compileRawIPPolicy(t, rawIP, 8006)
	g := &Gateway{}
	g.cfg.Store(gw)
	g.policy.Store(policy)

	if ep, authority, certHost := g.httpsMITMEndpoint("default", rawIP, 8006); ep == nil || ep.Name != "proxmox" ||
		authority != net.JoinHostPort(rawIP, "8006") || certHost != rawIP {
		t.Fatalf("raw IP :8006 lookup = (%v, %q, %q), want proxmox, authority with port, cert host without port", ep, authority, certHost)
	}
	if ep, _, _ := g.httpsMITMEndpoint("default", rawIP, 8443); ep != nil {
		t.Fatalf("raw IP :8443 resolved to %+v, want nil because endpoint did not declare that port", ep)
	}
}

func compileRawIPPolicy(t *testing.T, rawIP string, rawPort uint16) (*config.Gateway, *config.CompiledPolicy, *config.CompiledEndpoint) {
	t.Helper()
	src := testGatewayPrefix + `
endpoint "https" "proxmox" {
  hosts = ["` + net.JoinHostPort(rawIP, strconv.Itoa(int(rawPort))) + `"]
}
credential "bearer_token" "proxmox" {
  endpoint = https.proxmox
}
profile "default" { credentials = [bearer_token.proxmox] }
rule "allow-proxmox" {
  endpoint = https.proxmox
  verdict  = "allow"
}
`
	gw, diags := config.LoadBytes([]byte(src), "raw-ip.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := cp.Endpoints["proxmox"]
	if ep == nil {
		t.Fatal("compiled policy missing proxmox endpoint")
	}
	if !strings.Contains(ep.Hosts[0], rawIP) || !strings.Contains(ep.Hosts[0], "8006") {
		t.Fatalf("compiled host = %q, want raw IP port", ep.Hosts[0])
	}
	return gw, cp, ep
}
