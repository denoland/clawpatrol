package main

import (
	"bufio"
	"bytes"
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
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type uppercaseRequestCredential struct{}

func (uppercaseRequestCredential) InjectHTTP(_ context.Context, req *http.Request, _ runtime.Secret) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	body = bytes.ToUpper(body)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return nil
}

func (uppercaseRequestCredential) RewritesHTTPRequest() bool { return true }

type transformFixtureSecretStore struct{}

func (transformFixtureSecretStore) Get(string) (runtime.Secret, error) {
	return runtime.Secret{Bytes: []byte("unused-test-secret")}, nil
}

func TestTransformedRequestBodyFixtureIsRejectedAfterPersistence(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential "bearer_token" "transform" { endpoint = https.api }
profile "default" { credentials = [bearer_token.transform] }
rule "allow-original-body" {
  endpoint  = https.api
  priority  = 100
  condition = "http.body == 'hello world'"
  verdict   = "allow"
}
rule "deny-other-body" {
  endpoint = https.api
  priority = -100
  verdict  = "deny"
}
`), "transformed-fixture-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	policy.Credentials["transform"].Body = uppercaseRequestCredential{}
	ep := policy.Endpoints["api"]

	upstreamBodies := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		upstreamBodies <- string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()

	db, err := OpenDB(filepath.Join(t.TempDir(), "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()
	sink, err := NewSink(db, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sink.Close(ctx)
	}()
	events, cancelEvents := sink.Subscribe()
	defer cancelEvents()

	certs, _ := inMemoryCertCache(t)
	g := &Gateway{db: db, certs: certs, sink: sink, secrets: transformFixtureSecretStore{}}
	g.cfg.Store(gw)
	g.policy.Store(policy)
	g.transports.Store(ep, transport)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.mitmHTTPS(serverConn, "api.example.test", ep)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "api.example.test"})
	defer func() { _ = clientTLS.Close() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.example.test/transform", strings.NewReader("hello world"))
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
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; pre-transform body rule should allow", resp.StatusCode, http.StatusNoContent)
	}

	select {
	case got := <-upstreamBodies:
		if got != "HELLO WORLD" {
			t.Fatalf("upstream body = %q, want transformed body", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream body")
	}

	end := waitHTTPSAuditEnd(t, events, "allow")
	if end.Rule != "allow-original-body" {
		t.Fatalf("matched rule = %q, want pre-transform body rule", end.Rule)
	}
	if end.ReqBody != "HELLO WORLD" {
		t.Fatalf("audit body = %q, want transformed body", end.ReqBody)
	}
	if !end.ReqTransformed {
		t.Fatal("live event did not mark the successfully transformed request")
	}

	stored, err := (&webMux{g: g}).loadAction(end.ID)
	if err != nil {
		t.Fatalf("load persisted action: %v", err)
	}
	if !stored.ReqTransformed {
		t.Fatal("persisted event lost the request-transformed flag")
	}
	rw := httptest.NewRecorder()
	(&webMux{g: g}).writeActionFixture(rw, stored)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("fixture export status = %d, want 400; body=%s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "transformed") {
		t.Fatalf("fixture export error = %q, want transformed-request explanation", rw.Body.String())
	}

	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
}
