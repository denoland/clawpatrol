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
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type kubernetesApprovalCapture struct {
	credentials chan string
}

func (a kubernetesApprovalCapture) Approve(_ context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	a.credentials <- req.Request.Credential
	return runtime.ApproveVerdict{Decision: "allow", By: "test"}, nil
}

func TestMITMKubernetesSelectsBearerPlaceholderCredential(t *testing.T) {
	const policyHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "kubernetes" "cluster" {
  server = "cluster.example.test"
}
credential "bearer_token" "reader" {
  endpoint = kubernetes.cluster
}
credential "bearer_token" "admin" {
  endpoint = kubernetes.cluster
}
approver "human_approver" "admin_gate" {
  channel = "#cluster-admins"
}
rule "admin-approval" {
  endpoint   = kubernetes.cluster
  credential = bearer_token.admin
  priority   = 100
  approve    = [human_approver.admin_gate]
}
rule "cluster-default" {
  endpoint = kubernetes.cluster
  priority = -100
  verdict  = "allow"
}
profile "default" {
  credentials = [
    { credential = bearer_token.reader, placeholder = "PH_k8s" },
    { credential = bearer_token.admin, placeholder = "PH_k8s_admin" },
  ]
}
`

	h := newKubernetesCredentialDispatchHarness(t, policyHCL)

	tests := []struct {
		name          string
		authorization string
		wantStatus    int
		wantUpstream  string
		wantApproval  string
	}{
		{
			name:          "reader placeholder selects reader",
			authorization: "Bearer PH_k8s",
			wantStatus:    http.StatusOK,
			wantUpstream:  "Bearer reader-secret",
		},
		{
			name:          "admin placeholder selects admin and approval rule",
			authorization: "Bearer PH_k8s_admin",
			wantStatus:    http.StatusOK,
			wantUpstream:  "Bearer admin-secret",
			wantApproval:  "admin",
		},
		{
			name:          "unknown placeholder is not replaced",
			authorization: "Bearer PH_unknown",
			wantStatus:    http.StatusUnauthorized,
			wantUpstream:  "Bearer PH_unknown",
		},
		{
			name:         "missing placeholder is not replaced",
			wantStatus:   http.StatusUnauthorized,
			wantUpstream: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, upstreamAuthorization := h.send(t, tt.authorization)
			if status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", status, tt.wantStatus)
			}
			if upstreamAuthorization != tt.wantUpstream {
				t.Fatalf("upstream Authorization = %q, want %q", upstreamAuthorization, tt.wantUpstream)
			}
			select {
			case got := <-h.approvals:
				if got != tt.wantApproval {
					t.Fatalf("approval credential = %q, want %q", got, tt.wantApproval)
				}
			default:
				if tt.wantApproval != "" {
					t.Fatalf("approval credential missing, want %q", tt.wantApproval)
				}
			}
		})
	}
}

type kubernetesCredentialDispatchHarness struct {
	gateway   *Gateway
	endpoint  *config.CompiledEndpoint
	approvals chan string
}

func newKubernetesCredentialDispatchHarness(t *testing.T, policyHCL string) *kubernetesCredentialDispatchHarness {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := setCredentialSlot(db, "reader", "", "reader-secret"); err != nil {
		t.Fatalf("set reader credential: %v", err)
	}
	if err := setCredentialSlot(db, "admin", "", "admin-secret"); err != nil {
		t.Fatalf("set admin credential: %v", err)
	}

	gw, diags := config.LoadBytes([]byte(policyHCL), "kubernetes-credential-dispatch-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load config: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	ep := policy.Endpoints["cluster"]
	if ep == nil {
		t.Fatal("missing compiled Kubernetes endpoint")
	}
	approvals := make(chan string, 1)
	policy.Approvers["admin_gate"].Body = kubernetesApprovalCapture{credentials: approvals}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if authorization != "Bearer reader-secret" && authorization != "Bearer admin-secret" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write([]byte(authorization))
	}))
	t.Cleanup(upstream.Close)
	upstreamAddr := upstream.Listener.Addr().String()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	t.Cleanup(transport.CloseIdleConnections)

	sink, err := NewSink(nil, 16)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { close(sink.ch) })
	certs, _ := inMemoryCertCache(t)
	gateway := &Gateway{
		db:      db,
		certs:   certs,
		sink:    sink,
		hitl:    newHITLRegistry(sink),
		secrets: newGatewaySecretStore(db, nil),
		onboard: newOnboardRegistry(),
	}
	gateway.cfg.Store(gw)
	gateway.policy.Store(policy)
	gateway.transports.Store(ep, transport)
	return &kubernetesCredentialDispatchHarness{gateway: gateway, endpoint: ep, approvals: approvals}
}

func (h *kubernetesCredentialDispatchHarness) send(t *testing.T, authorization string) (int, string) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.gateway.mitmHTTPS(serverConn, "cluster.example.test", h.endpoint)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "cluster.example.test"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://cluster.example.test/api/v1/namespaces", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
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
		t.Fatalf("read response body: %v", err)
	}
	_ = resp.Body.Close()
	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
	return resp.StatusCode, strings.TrimSpace(string(body))
}
