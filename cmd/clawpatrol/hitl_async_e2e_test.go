package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
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
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type hitlAsyncE2EHarness struct {
	db       *sql.DB
	store    *HITLOperationStore
	gateway  *Gateway
	endpoint *config.CompiledEndpoint
	handler  http.Handler
	token    string
	upstream chan hitlRetryRelayUpstreamRequest
}

func TestHITLAsyncApprovalGrantEndToEndHTTPFlow(t *testing.T) {
	h := newHITLAsyncE2EHarness(t)
	requestBody := `{"resource":"example","message":"approve me"}`

	first := h.sendMITMRequest(t, http.MethodPost, "", requestBody)
	if first.StatusCode != http.StatusAccepted {
		t.Fatalf("first request status = %d, body = %q; want async 202", first.StatusCode, first.Body)
	}
	if upstreamCalls := h.drainUpstreamRequests(); upstreamCalls != 0 {
		t.Fatalf("upstream calls after 202 = %d, want 0", upstreamCalls)
	}
	accepted := decodeResponseJSON(t, first.Body)
	operationID, _ := accepted["operation_id"].(string)
	if operationID == "" {
		t.Fatalf("operation_id missing from 202 body: %#v", accepted)
	}
	if accepted["upstream_called"] != false {
		t.Fatalf("202 upstream_called = %v, want false", accepted["upstream_called"])
	}
	statusURL, _ := accepted["status_url"].(string)
	wantStatusURLPrefix := "https://gateway.example.test/api/hitl/operations/" + operationID + "/status?token="
	if !strings.HasPrefix(statusURL, wantStatusURLPrefix) || strings.TrimPrefix(statusURL, wantStatusURLPrefix) == "" {
		t.Fatalf("status_url = %v, want public operation-scoped capability URL with token", accepted["status_url"])
	}
	if _, ok := accepted["retry_header_name"]; ok {
		t.Fatalf("initial 202 included retry_header_name before approval: %#v", accepted)
	}

	pendingStatus := h.pollStatusURL(t, statusURL)
	if pendingStatus.Code != http.StatusOK {
		t.Fatalf("pending status code = %d, body = %s", pendingStatus.Code, pendingStatus.Body.String())
	}
	pendingBody := decodeJSONBody(t, pendingStatus)
	if pendingBody["state"] != string(HITLOperationStatePendingApproval) {
		t.Fatalf("status state before approval = %v, want %s", pendingBody["state"], HITLOperationStatePendingApproval)
	}
	if pendingBody["upstream_called"] != false {
		t.Fatalf("pending upstream_called = %v, want false", pendingBody["upstream_called"])
	}

	pending := h.gateway.hitl.List()
	if len(pending) != 1 {
		t.Fatalf("pending HITL entries = %d, want 1: %#v", len(pending), pending)
	}
	if pending[0].OperationID != operationID {
		t.Fatalf("pending OperationID = %q, want %q", pending[0].OperationID, operationID)
	}
	if pending[0].OperationState != runtime.HITLOperationStatePendingApproval {
		t.Fatalf("pending OperationState = %q, want pending_approval", pending[0].OperationState)
	}
	if pending[0].ApprovalEffect != runtime.HITLApprovalEffectCreateRetryGrant {
		t.Fatalf("pending ApprovalEffect = %q, want create_retry_grant", pending[0].ApprovalEffect)
	}

	decision := h.gateway.hitl.DecideWithResult(pending[0].ID, runtime.HITLDecision{Allow: true, By: "dashboard"})
	if !decision.OK || decision.State != runtime.HITLStateApproved {
		t.Fatalf("approve result = %#v, want approved retry grant", decision)
	}
	approvedStatus := h.pollStatusURL(t, statusURL)
	approvedBody := decodeJSONBody(t, approvedStatus)
	if approvedBody["state"] != string(HITLOperationStateApprovedWaitingForRetry) {
		t.Fatalf("status state after approval = %v, want %s", approvedBody["state"], HITLOperationStateApprovedWaitingForRetry)
	}
	if approvedBody["retry_header_name"] != hitlRetryOperationHeader || approvedBody["retry_header_value"] != operationID {
		t.Fatalf("retry envelope mismatch after approval: %#v", approvedBody)
	}

	retry := h.sendMITMRequest(t, http.MethodPost, operationID, requestBody)
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("retry status = %d, body = %q; want upstream 200", retry.StatusCode, retry.Body)
	}
	if !strings.Contains(retry.Body, "relayed by upstream") {
		t.Fatalf("retry body = %q, want upstream response", retry.Body)
	}
	upstream := h.nextUpstreamRequest(t)
	if upstream.Body != requestBody {
		t.Fatalf("upstream body = %q, want original body %q", upstream.Body, requestBody)
	}
	if upstream.RetryOperationValue != "" {
		t.Fatalf("upstream received internal %s header = %q", hitlRetryOperationHeader, upstream.RetryOperationValue)
	}

	finalStatus := h.pollStatusURL(t, statusURL)
	finalBody := decodeJSONBody(t, finalStatus)
	if finalBody["state"] != string(HITLOperationStateUpstreamSucceeded) {
		t.Fatalf("final state = %v, want %s", finalBody["state"], HITLOperationStateUpstreamSucceeded)
	}
	if finalBody["upstream_called"] != true || finalBody["terminal"] != true {
		t.Fatalf("final envelope = %#v, want terminal upstream-called success", finalBody)
	}
}

func newHITLAsyncE2EHarness(t *testing.T) *hitlAsyncE2EHarness {
	t.Helper()

	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	persistHITLRetryRelayCredentialSecret(t, db)
	token, err := mintAndPersistPeerAPIToken(db, hitlRetryRelayTestPeerIP)
	if err != nil {
		t.Fatalf("mint peer API token: %v", err)
	}

	gw, diags := config.LoadBytes([]byte(`
public_url = "https://gateway.example.test"
control = "wireguard"
wg_subnet_cidr = "10.55.0.0/24"

credential "bearer_token" "pat" {}
endpoint "https" "api" {
  hosts      = ["api.example.test"]
  credential = pat
}
approver "human_approver" "ops" {
  channel           = "#ops"
  timeout           = 60
  sync_wait_timeout = "1ms"
  async_grant {
    enabled            = true
    approval_ttl       = "15m"
    approved_retry_ttl = "5m"
    fingerprint_body   = "raw"
    max_body_bytes     = 1048576
  }
}
rule "approved-post" {
  endpoint  = api
  condition = "http.method == 'POST' && http.path == '/v1/resources/update'"
  approve   = [ops]
}
profile "default" {
  endpoints = [api]
  hitl_async_grants = true
}
`), "hitl-async-e2e-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load config: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	ep := policy.Endpoints[hitlRetryRelayTestEndpoint]
	if ep == nil {
		t.Fatal("missing compiled api endpoint")
	}

	upstreamRequests := make(chan hitlRetryRelayUpstreamRequest, 2)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		upstreamRequests <- hitlRetryRelayUpstreamRequest{
			Body:                string(body),
			RetryOperationValue: r.Header.Get(hitlRetryOperationHeader),
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("relayed by upstream"))
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
	registry := newHITLRegistry(sink)
	g := &Gateway{
		cfg:     gw,
		db:      db,
		certs:   certs,
		sink:    sink,
		hitl:    registry,
		secrets: newGatewaySecretStore(db, nil),
		onboard: newOnboardRegistry(),
	}
	registry.asyncGrantResolver = g.resolveAsyncHITLGrant
	g.policy.Store(policy)
	g.transports.Store(ep, transport)

	return &hitlAsyncE2EHarness{
		db:       db,
		store:    NewHITLOperationStore(db),
		gateway:  g,
		endpoint: ep,
		handler:  newWebMux(g, gw.Join(), gw.PublicURL),
		token:    token,
		upstream: upstreamRequests,
	}
}

func (h *hitlAsyncE2EHarness) sendMITMRequest(t *testing.T, method, operationID, requestBody string) hitlRetryRelayResponse {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.gateway.mitmHTTPS(serverConn, hitlRetryRelayTestHost, h.endpoint)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: hitlRetryRelayTestHost})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	req, err := http.NewRequest(method, "https://"+hitlRetryRelayTestHost+hitlRetryRelayTestPath, strings.NewReader(requestBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if operationID != "" {
		req.Header.Set(hitlRetryOperationHeader, operationID)
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
	return hitlRetryRelayResponse{StatusCode: resp.StatusCode, Body: string(body)}
}

func (h *hitlAsyncE2EHarness) pollStatusURL(t *testing.T, statusURL string) *httptest.ResponseRecorder {
	t.Helper()
	return h.pollStatusRequest(t, statusURL, false)
}

func (h *hitlAsyncE2EHarness) pollStatusRequest(t *testing.T, target string, withBearer bool) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if withBearer {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	h.handler.ServeHTTP(rr, req)
	return rr
}

func (h *hitlAsyncE2EHarness) nextUpstreamRequest(t *testing.T) hitlRetryRelayUpstreamRequest {
	t.Helper()
	select {
	case req := <-h.upstream:
		return req
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}
	return hitlRetryRelayUpstreamRequest{}
}

func (h *hitlAsyncE2EHarness) drainUpstreamRequests() int {
	count := 0
	for {
		select {
		case <-h.upstream:
			count++
		default:
			return count
		}
	}
}

func decodeResponseJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode JSON body: %v\nbody=%s", err, body)
	}
	return out
}
