package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const telegramTestPlaceholder = "0000000000:clawpatrol-placeholder-do-not-use"

var fakeTelegramRequestBodyToken = []byte("999999999:FAKE_REDACTED_TELEGRAM_TOKEN_DO_NOT_USE")

type telegramRequestBodySecretStore struct{}

func (telegramRequestBodySecretStore) Get(string) (runtime.Secret, error) {
	return runtime.Secret{Bytes: fakeTelegramRequestBodyToken}, nil
}

func TestTelegramInjectedTokenRedactedFromRequestBodyAuditSample(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "telegram_api" {
  hosts = ["api.telegram.org"]
}
credential "telegram_bot_token" "telegram_cred" { endpoint = https.telegram_api }
profile "default" { credentials = [telegram_bot_token.telegram_cred] }
rule "allow-telegram" {
  endpoint = https.telegram_api
  verdict  = "allow"
}
`), "telegram-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := policy.Endpoints["telegram_api"]

	upstreamBodies := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		upstreamBodies <- string(body)
		w.WriteHeader(http.StatusOK)
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

	sink, err := NewSink(nil, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer close(sink.ch)
	events, cancel := sink.Subscribe()
	defer cancel()

	certs, _ := inMemoryCertCache(t)
	g := &Gateway{
		certs:   certs,
		sink:    sink,
		secrets: telegramRequestBodySecretStore{},
	}
	g.cfg.Store(gw)
	g.policy.Store(policy)
	g.transports.Store(ep, tr)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.mitmHTTPS(serverConn, "api.telegram.org", ep)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "api.telegram.org"})
	defer func() { _ = clientTLS.Close() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	requestBody := "url=https://agent.example/hook/" + telegramTestPlaceholder + "&drop_pending_updates=true"
	req, err := http.NewRequest(http.MethodPost, "https://api.telegram.org/bot"+telegramTestPlaceholder+"/setWebhook", strings.NewReader(requestBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	var upstreamBody string
	select {
	case upstreamBody = <-upstreamBodies:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request body")
	}
	if !strings.Contains(upstreamBody, string(fakeTelegramRequestBodyToken)) {
		t.Fatal("upstream body did not receive injected Telegram token")
	}

	var end Event
	select {
	case end = <-endEvent(events):
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for terminal audit event")
	}
	if strings.Contains(end.ReqBody, string(fakeTelegramRequestBodyToken)) {
		t.Fatal("request body audit sample contains injected Telegram token")
	}
	if !strings.Contains(end.ReqBody, telegramTestPlaceholder) && !strings.Contains(strings.ToLower(end.ReqBody), "redact") {
		t.Fatalf("request body audit sample = %q, want placeholder or redaction marker", end.ReqBody)
	}

	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
}

func endEvent(events <-chan eventPacket) <-chan Event {
	out := make(chan Event, 1)
	go func() {
		defer close(out)
		for pkt := range events {
			if pkt.ev.Phase == "end" {
				out <- pkt.ev
				return
			}
		}
	}()
	return out
}
