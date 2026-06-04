package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type captureBodySampleApprover struct {
	seen chan string
}

func (a captureBodySampleApprover) Approve(_ context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	a.seen <- req.BodySample
	return runtime.ApproveVerdict{Decision: "deny", Reason: "captured body sample", By: "test"}, nil
}

func TestHTTPSApproveChainReceivesBufferedRequestBodySample(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential "bearer_token" "pat" { endpoint = https.api }
approver "human_approver" "capture" {
  channel = "#ops"
}
rule "approved-post" {
  endpoint  = https.api
  condition = "http.method == 'POST' && http.path == '/v1/resources/update'"
  approve   = [human_approver.capture]
}
profile "default" { credentials = [bearer_token.pat] }
`), "hitl-body-sample-test.hcl")
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

	seenBodySamples := make(chan string, 1)
	policy.Approvers["capture"] = &config.Entity{
		Symbol: &config.Symbol{Name: "capture"},
		Body:   captureBodySampleApprover{seen: seenBodySamples},
	}

	sink, err := NewSink(nil, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer close(sink.ch)
	certs, _ := inMemoryCertCache(t)
	g := &Gateway{certs: certs, sink: sink}
	g.cfg.Store(gw)
	g.policy.Store(policy)

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

	requestBody := `{"resource":"example","message":"Please apply this update."}`
	req, err := http.NewRequest(http.MethodPost, "https://api.example.test/v1/resources/update", strings.NewReader(requestBody))
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
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	select {
	case got := <-seenBodySamples:
		if got != requestBody {
			t.Fatalf("BodySample = %q, want request body %q", got, requestBody)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for approver body sample")
	}

	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
}
