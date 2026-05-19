package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

const (
	hitlRetryRelayTestProfile      = "default"
	hitlRetryRelayTestPeerIP       = "pipe"
	hitlRetryRelayTestEndpoint     = "api"
	hitlRetryRelayTestRule         = "approved-post"
	hitlRetryRelayTestApprover     = "human_approver.ops"
	hitlRetryRelayTestHost         = "api.example.test"
	hitlRetryRelayTestPath         = "/v1/resources/update"
	hitlRetryRelayTestCredential   = "pat"
	hitlRetryRelayTestCredentialNS = int64(1_700_003_000_000_000_000)
)

type hitlRetryRelayDenyApprover struct {
	calls atomic.Int32
}

func (a *hitlRetryRelayDenyApprover) Approve(_ context.Context, _ runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	a.calls.Add(1)
	return runtime.ApproveVerdict{Decision: "deny", Reason: "approval chain should be bypassed by a retry grant", By: "test"}, nil
}

type hitlRetryRelayUpstreamRequest struct {
	Body                string
	RetryOperationValue string
}

type hitlRetryRelayHarness struct {
	db          *sql.DB
	store       *HITLOperationStore
	gateway     *Gateway
	endpoint    *config.CompiledEndpoint
	approver    *hitlRetryRelayDenyApprover
	fingerprint HITLFingerprintKey
	authBinding string
	upstream    chan hitlRetryRelayUpstreamRequest
}

func TestHITLRetryRelayConsumesApprovedGrantAndForwardsOnlyOnce(t *testing.T) {
	h := newHITLRetryRelayHarness(t)
	requestBody := `{"resource":"example","approved":true}`
	op := h.createApprovedRetryOperation(t, "hitl_op_retry_match", requestBody)

	resp := h.sendRetryRequest(t, op.ID, requestBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first retry status = %d, body = %q; want upstream 200", resp.StatusCode, resp.Body)
	}
	if !strings.Contains(resp.Body, "relayed") {
		t.Fatalf("first retry body = %q, want upstream response", resp.Body)
	}
	upstream := h.nextUpstreamRequest(t)
	if upstream.Body != requestBody {
		t.Fatalf("upstream body = %q, want original body %q", upstream.Body, requestBody)
	}
	if upstream.RetryOperationValue != "" {
		t.Fatalf("upstream received internal %s header = %q", hitlRetryOperationHeader, upstream.RetryOperationValue)
	}
	if calls := h.approver.calls.Load(); calls != 0 {
		t.Fatalf("approve chain calls after matching retry = %d, want 0", calls)
	}

	consumed := h.getOperation(t, op.ID)
	if consumed.State != HITLOperationStateUpstreamSucceeded {
		t.Fatalf("state after retry = %s, want %s", consumed.State, HITLOperationStateUpstreamSucceeded)
	}
	if consumed.TerminalAt == nil {
		t.Fatal("TerminalAt = nil after successful retry, want terminal status for pollers")
	}
	if !consumed.UpstreamCalled {
		t.Fatal("UpstreamCalled = false, want true")
	}
	if consumed.GrantConsumedAt == nil {
		t.Fatal("GrantConsumedAt = nil, want consumed timestamp")
	}
	if consumed.GrantConsumedBy != hitlPeerPrincipalID(hitlRetryRelayTestPeerIP) {
		t.Fatalf("GrantConsumedBy = %q, want %q", consumed.GrantConsumedBy, hitlPeerPrincipalID(hitlRetryRelayTestPeerIP))
	}

	second := h.sendRetryRequest(t, op.ID, requestBody)
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("second retry status = %d, body = %q; want safe one-shot conflict", second.StatusCode, second.Body)
	}
	h.assertNoUpstreamRequest(t)
	if calls := h.approver.calls.Load(); calls != 0 {
		t.Fatalf("approve chain calls after consumed retry = %d, want 0", calls)
	}
}

func TestHITLRetryRelayMismatchDoesNotForwardOrFallBackToApproval(t *testing.T) {
	h := newHITLRetryRelayHarness(t)
	approvedBody := `{"resource":"example","approved":true}`
	op := h.createApprovedRetryOperation(t, "hitl_op_retry_mismatch", approvedBody)

	resp := h.sendRetryRequest(t, op.ID, approvedBody+"\n")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("mismatched retry status = %d, body = %q; want safe conflict", resp.StatusCode, resp.Body)
	}
	h.assertNoUpstreamRequest(t)
	if calls := h.approver.calls.Load(); calls != 0 {
		t.Fatalf("approve chain calls after mismatched retry = %d, want 0", calls)
	}

	unchanged := h.getOperation(t, op.ID)
	if unchanged.State != HITLOperationStateApprovedWaitingForRetry {
		t.Fatalf("state after mismatch = %s, want %s", unchanged.State, HITLOperationStateApprovedWaitingForRetry)
	}
	if unchanged.UpstreamCalled {
		t.Fatal("UpstreamCalled = true after mismatch, want false")
	}
	if unchanged.GrantConsumedAt != nil {
		t.Fatalf("GrantConsumedAt = %v after mismatch, want nil", unchanged.GrantConsumedAt)
	}
}

func TestHITLRetryRelayFingerprintsRetryBodyForDeleteRequests(t *testing.T) {
	h := newHITLRetryRelayHarness(t)
	requestBody := `{"resource":"example","delete":true}`
	op := h.createApprovedRetryOperationForMethod(t, "hitl_op_retry_delete", http.MethodDelete, requestBody)

	resp := h.sendRetryRequestWithMethod(t, op.ID, http.MethodDelete, requestBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete retry status = %d, body = %q; want upstream 200", resp.StatusCode, resp.Body)
	}
	upstream := h.nextUpstreamRequest(t)
	if upstream.Body != requestBody {
		t.Fatalf("delete upstream body = %q, want original body %q", upstream.Body, requestBody)
	}
	if upstream.RetryOperationValue != "" {
		t.Fatalf("upstream received internal %s header = %q", hitlRetryOperationHeader, upstream.RetryOperationValue)
	}
	if calls := h.approver.calls.Load(); calls != 0 {
		t.Fatalf("approve chain calls after delete retry = %d, want 0", calls)
	}
	consumed := h.getOperation(t, op.ID)
	if consumed.State != HITLOperationStateUpstreamSucceeded {
		t.Fatalf("delete retry state = %s, want %s", consumed.State, HITLOperationStateUpstreamSucceeded)
	}
	if consumed.TerminalAt == nil {
		t.Fatal("delete retry TerminalAt = nil, want terminal status for pollers")
	}
}

func TestHITLRetryRelayUsesRemappedAgentPrincipal(t *testing.T) {
	h := newHITLRetryRelayHarness(t)
	requestBody := `{"resource":"example","approved":true}`
	parentIP := "100.64.0.10"
	h.gateway.onboard = newOnboardRegistry()
	h.gateway.onboard.setEphemeralProfile(hitlRetryRelayTestPeerIP, parentIP, hitlRetryRelayTestProfile)
	op := h.createApprovedRetryOperationForMethodAndPrincipal(t, "hitl_op_retry_ephemeral", http.MethodPost, requestBody, hitlPeerPrincipalID(parentIP))

	resp := h.sendRetryRequest(t, op.ID, requestBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ephemeral retry status = %d, body = %q; want upstream 200", resp.StatusCode, resp.Body)
	}
	if calls := h.approver.calls.Load(); calls != 0 {
		t.Fatalf("approve chain calls after remapped retry = %d, want 0", calls)
	}
	consumed, err := h.store.GetForPrincipal(context.Background(), op.ID, hitlRetryRelayTestProfile, hitlPeerPrincipalID(parentIP))
	if err != nil {
		t.Fatalf("GetForPrincipal parent: %v", err)
	}
	if consumed.GrantConsumedBy != hitlPeerPrincipalID(parentIP) {
		t.Fatalf("GrantConsumedBy = %q, want %q", consumed.GrantConsumedBy, hitlPeerPrincipalID(parentIP))
	}
}

type hitlRetryRelayResponse struct {
	StatusCode int
	Body       string
}

func newHITLRetryRelayHarness(t *testing.T) *hitlRetryRelayHarness {
	t.Helper()

	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	fingerprintKey := HITLFingerprintKey{
		ID:   "hitl-hmac:v1",
		Root: []byte("retry relay test hmac root; deterministic and not a real secret"),
	}
	persistHITLRetryRelayFingerprintKey(t, db, fingerprintKey)
	persistHITLRetryRelayCredentialSecret(t, db)

	authBinding, err := BuildHITLCredentialAuthBindingID(HITLCredentialAuthBindingInput{
		ProfileID:    hitlRetryRelayTestProfile,
		CredentialID: hitlRetryRelayTestCredential,
		Generation:   fmt.Sprintf("credential-secret:%d", hitlRetryRelayTestCredentialNS),
	})
	if err != nil {
		t.Fatalf("BuildHITLCredentialAuthBindingID: %v", err)
	}

	gw, diags := config.LoadBytes([]byte(`
public_url = "https://gateway.example.test"

credential "bearer_token" "pat" {}
endpoint "https" "api" {
  hosts      = ["api.example.test"]
  credential = pat
}
approver "human_approver" "ops" {
  channel = "#ops"
}
rule "approved-post" {
  endpoint  = api
  condition = "(http.method == 'POST' || http.method == 'DELETE') && http.path == '/v1/resources/update'"
  approve   = [ops]
}
profile "default" {
  endpoints = [api]
  hitl_async_grants = true
}
`), "hitl-retry-relay-test.hcl")
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

	approver := &hitlRetryRelayDenyApprover{}
	policy.Approvers["ops"] = &config.Entity{Symbol: &config.Symbol{Name: "ops"}, Body: approver}

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
	g := &Gateway{
		cfg:     gw,
		db:      db,
		certs:   certs,
		sink:    sink,
		hitl:    newHITLRegistry(sink),
		secrets: newGatewaySecretStore(db, nil),
	}
	g.policy.Store(policy)
	g.transports.Store(ep, transport)

	return &hitlRetryRelayHarness{
		db:          db,
		store:       NewHITLOperationStore(db),
		gateway:     g,
		endpoint:    ep,
		approver:    approver,
		fingerprint: fingerprintKey,
		authBinding: authBinding,
		upstream:    upstreamRequests,
	}
}

func persistHITLRetryRelayFingerprintKey(t *testing.T, db *sql.DB, key HITLFingerprintKey) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO gateway_blobs (kind, name, value, updated_ns) VALUES (?, ?, ?, ?)`, "hitl_fingerprint_hmac", key.ID, key.Root, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("persist fingerprint key: %v", err)
	}
}

func persistHITLRetryRelayCredentialSecret(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO credential_secrets (credential, slot, value, updated_ns) VALUES (?, ?, ?, ?)`, hitlRetryRelayTestCredential, "", "retry-relay-test-token", hitlRetryRelayTestCredentialNS)
	if err != nil {
		t.Fatalf("persist credential secret: %v", err)
	}
}

func (h *hitlRetryRelayHarness) createApprovedRetryOperation(t *testing.T, id, requestBody string) HITLOperation {
	t.Helper()
	return h.createApprovedRetryOperationForMethod(t, id, http.MethodPost, requestBody)
}

func (h *hitlRetryRelayHarness) createApprovedRetryOperationForMethod(t *testing.T, id, method, requestBody string) HITLOperation {
	t.Helper()
	return h.createApprovedRetryOperationForMethodAndPrincipal(t, id, method, requestBody, hitlPeerPrincipalID(hitlRetryRelayTestPeerIP))
}

func (h *hitlRetryRelayHarness) createApprovedRetryOperationForMethodAndPrincipal(t *testing.T, id, method, requestBody, principalID string) HITLOperation {
	t.Helper()
	fp := h.fingerprintForMethodBodyAndPrincipal(t, method, requestBody, principalID)
	now := time.Now().UTC()
	op, err := h.store.Create(context.Background(), HITLOperationCreate{
		ID:                  id,
		State:               HITLOperationStateApprovedWaitingForRetry,
		ProfileID:           hitlRetryRelayTestProfile,
		PrincipalID:         principalID,
		EndpointID:          hitlRetryRelayTestEndpoint,
		ApprovalRuleID:      hitlRetryRelayTestRule,
		ApproverID:          hitlRetryRelayTestApprover,
		Method:              method,
		Scheme:              "https",
		Host:                hitlRetryRelayTestHost,
		RedactedPath:        hitlRetryRelayTestPath,
		RedactedHeadersJSON: `{"content-type":"application/json"}`,
		AuthBindingID:       h.authBinding,
		FingerprintVersion:  fp.Version,
		HMACKeyID:           fp.HMACKeyID,
		RequestFingerprint:  fp.RequestFingerprint,
		CreatedAt:           now.Add(-2 * time.Minute),
		SyncWaitDeadline:    now.Add(-time.Minute),
		ApprovalExpiresAt:   now.Add(10 * time.Minute),
		RetryExpiresAt:      now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Create retry operation: %v", err)
	}
	return op
}

func (h *hitlRetryRelayHarness) fingerprintForBody(t *testing.T, requestBody string) HITLRequestFingerprintResult {
	t.Helper()
	return h.fingerprintForMethodAndBody(t, http.MethodPost, requestBody)
}

func (h *hitlRetryRelayHarness) fingerprintForMethodAndBody(t *testing.T, method, requestBody string) HITLRequestFingerprintResult {
	t.Helper()
	return h.fingerprintForMethodBodyAndPrincipal(t, method, requestBody, hitlPeerPrincipalID(hitlRetryRelayTestPeerIP))
}

func (h *hitlRetryRelayHarness) fingerprintForMethodBodyAndPrincipal(t *testing.T, method, requestBody, principalID string) HITLRequestFingerprintResult {
	t.Helper()
	result, err := ComputeHITLRequestFingerprint(HITLRequestFingerprintInput{
		Key:            h.fingerprint,
		ProfileID:      hitlRetryRelayTestProfile,
		PrincipalID:    principalID,
		EndpointID:     hitlRetryRelayTestEndpoint,
		ApprovalRuleID: hitlRetryRelayTestRule,
		Method:         method,
		Scheme:         "https",
		Host:           hitlRetryRelayTestHost,
		Path:           hitlRetryRelayTestPath,
		RawBody:        []byte(requestBody),
		AuthBindingID:  h.authBinding,
	})
	if err != nil {
		t.Fatalf("ComputeHITLRequestFingerprint: %v", err)
	}
	return result
}

func (h *hitlRetryRelayHarness) sendRetryRequest(t *testing.T, operationID, requestBody string) hitlRetryRelayResponse {
	t.Helper()
	return h.sendRetryRequestWithMethod(t, operationID, http.MethodPost, requestBody)
}

func (h *hitlRetryRelayHarness) sendRetryRequestWithMethod(t *testing.T, operationID, method, requestBody string) hitlRetryRelayResponse {
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
	req.Header.Set(hitlRetryOperationHeader, operationID)
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

func (h *hitlRetryRelayHarness) nextUpstreamRequest(t *testing.T) hitlRetryRelayUpstreamRequest {
	t.Helper()
	select {
	case req := <-h.upstream:
		return req
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}
	return hitlRetryRelayUpstreamRequest{}
}

func (h *hitlRetryRelayHarness) assertNoUpstreamRequest(t *testing.T) {
	t.Helper()
	select {
	case req := <-h.upstream:
		t.Fatalf("unexpected upstream request: body=%q retry_header=%q", req.Body, req.RetryOperationValue)
	case <-time.After(150 * time.Millisecond):
	}
}

func (h *hitlRetryRelayHarness) getOperation(t *testing.T, id string) HITLOperation {
	t.Helper()
	op, err := h.store.GetForPrincipal(context.Background(), id, hitlRetryRelayTestProfile, hitlPeerPrincipalID(hitlRetryRelayTestPeerIP))
	if err != nil {
		t.Fatalf("GetForPrincipal: %v", err)
	}
	return op
}
