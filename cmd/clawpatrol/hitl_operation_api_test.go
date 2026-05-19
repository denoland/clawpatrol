package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

func TestHITLOperationAcceptedResponseUsesConfiguredPublicURL(t *testing.T) {
	now := time.Unix(1_700_001_000, 0).UTC()
	op := HITLOperation{
		ID:                "hitl_op_202",
		State:             HITLOperationStatePendingApproval,
		ApprovalExpiresAt: now.Add(15 * time.Minute),
	}

	rr := httptest.NewRecorder()
	writeHITLOperationAccepted(rr, op, "https://gateway.example.test/")

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body = %s", rr.Code, rr.Body.String())
	}
	wantURL := "https://gateway.example.test/api/hitl/operations/hitl_op_202/status"
	if got := rr.Header().Get("Location"); got != wantURL {
		t.Fatalf("Location = %q, want %q", got, wantURL)
	}
	if got := rr.Header().Get("Retry-After"); got != "5" {
		t.Fatalf("Retry-After = %q, want 5", got)
	}
	if got := rr.Header().Get("Clawpatrol-HITL-State"); got != string(HITLOperationStatePendingApproval) {
		t.Fatalf("Clawpatrol-HITL-State = %q", got)
	}
	if got := rr.Header().Get("Clawpatrol-Upstream-Called"); got != "false" {
		t.Fatalf("Clawpatrol-Upstream-Called = %q", got)
	}

	body := decodeJSONBody(t, rr)
	if body["operation_id"] != op.ID {
		t.Fatalf("operation_id = %v, want %q", body["operation_id"], op.ID)
	}
	if body["status_url"] != wantURL {
		t.Fatalf("status_url = %v, want %q", body["status_url"], wantURL)
	}
	if body["upstream_called"] != false {
		t.Fatalf("upstream_called = %v, want false", body["upstream_called"])
	}
	if body["retry_original_request"] != true {
		t.Fatalf("retry_original_request = %v, want true", body["retry_original_request"])
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "upstream service") || !strings.Contains(msg, "status_url") {
		t.Fatalf("message is not useful agent guidance: %q", msg)
	}
}

func TestHITLOperationStatusRequiresPeerAPIToken(t *testing.T) {
	h := newHITLOperationAPITestHarness(t)
	op := h.createOperation(t, HITLOperationCreate{ID: "hitl_op_requires_auth", State: HITLOperationStatePendingApproval})

	for _, path := range []string{
		"/api/hitl/operations/" + op.ID + "/status",
		"/api/hitl/operations/",
		"/api/hitl/operations/foo/bar",
	} {
		t.Run(path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			h.handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body = %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHITLOperationStatusRequiresSameProfileAndPrincipal(t *testing.T) {
	h := newHITLOperationAPITestHarness(t)
	op := h.createOperation(t, HITLOperationCreate{ID: "hitl_op_owner", State: HITLOperationStatePendingApproval})

	for _, tc := range []struct {
		name  string
		token string
		path  string
	}{
		{name: "wrong principal", token: h.otherToken, path: "/api/hitl/operations/" + op.ID + "/status"},
		{name: "unknown operation", token: h.ownerToken, path: "/api/hitl/operations/hitl_op_missing/status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			h.handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body = %s", rr.Code, rr.Body.String())
			}
			body := decodeJSONBody(t, rr)
			if body["error"] != "hitl_operation_not_found" {
				t.Fatalf("error = %v, want hitl_operation_not_found; body = %#v", body["error"], body)
			}
		})
	}
}

func TestHITLOperationStatusEndpointReturnsStateSpecificEnvelope(t *testing.T) {
	h := newHITLOperationAPITestHarness(t)
	now := time.Unix(1_700_002_000, 0).UTC()

	pending := h.createOperation(t, HITLOperationCreate{
		ID:                "hitl_op_pending",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now,
		SyncWaitDeadline:  now.Add(-time.Minute),
		ApprovalExpiresAt: now.Add(15 * time.Minute),
	})
	approved := h.createOperation(t, HITLOperationCreate{
		ID:                "hitl_op_approved",
		State:             HITLOperationStateApprovedWaitingForRetry,
		CreatedAt:         now.Add(-2 * time.Minute),
		SyncWaitDeadline:  now.Add(-time.Minute),
		ApprovalExpiresAt: now.Add(15 * time.Minute),
		RetryExpiresAt:    now.Add(5 * time.Minute),
	})
	executing := h.createOperation(t, HITLOperationCreate{
		ID:                "hitl_op_executing",
		State:             HITLOperationStateExecutingUpstream,
		CreatedAt:         now.Add(-3 * time.Minute),
		SyncWaitDeadline:  now.Add(-2 * time.Minute),
		ApprovalExpiresAt: now.Add(15 * time.Minute),
	})
	denied := h.createOperation(t, HITLOperationCreate{
		ID:                "hitl_op_denied",
		State:             HITLOperationStateDenied,
		CreatedAt:         now.Add(-4 * time.Minute),
		SyncWaitDeadline:  now.Add(-3 * time.Minute),
		ApprovalExpiresAt: now.Add(15 * time.Minute),
	})
	expiredBase := h.createOperation(t, HITLOperationCreate{
		ID:                "hitl_op_expired",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now.Add(-30 * time.Minute),
		SyncWaitDeadline:  now.Add(-29 * time.Minute),
		ApprovalExpiresAt: now.Add(-15 * time.Minute),
	})
	expired := h.transitionOperation(t, expiredBase, HITLOperationStateExpired, now, func(tr *HITLOperationTransition) {
		tr.ExpiredReason = "approval_ttl"
	})
	syncWaiting := h.createOperation(t, HITLOperationCreate{
		ID:                "hitl_op_sync_waiting",
		State:             HITLOperationStateSyncWaiting,
		CreatedAt:         now,
		SyncWaitDeadline:  now.Add(time.Minute),
		ApprovalExpiresAt: now.Add(15 * time.Minute),
	})
	clientDisconnectedBase := h.createOperation(t, HITLOperationCreate{
		ID:                "hitl_op_client_disconnected",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now.Add(-5 * time.Minute),
		SyncWaitDeadline:  now.Add(-4 * time.Minute),
		ApprovalExpiresAt: now.Add(15 * time.Minute),
	})
	clientDisconnected := h.transitionOperation(t, clientDisconnectedBase, HITLOperationStateClientDisconnected, now, nil)
	succeededBase := h.createOperation(t, HITLOperationCreate{
		ID:                "hitl_op_upstream_succeeded",
		State:             HITLOperationStateApprovedWaitingForRetry,
		CreatedAt:         now.Add(-6 * time.Minute),
		SyncWaitDeadline:  now.Add(-5 * time.Minute),
		ApprovalExpiresAt: now.Add(15 * time.Minute),
		RetryExpiresAt:    now.Add(5 * time.Minute),
	})
	succeeded := h.transitionOperation(t, succeededBase, HITLOperationStateUpstreamSucceeded, now, func(tr *HITLOperationTransition) {
		tr.UpstreamCalled = true
	})
	failedBase := h.createOperation(t, HITLOperationCreate{
		ID:                "hitl_op_upstream_failed",
		State:             HITLOperationStateApprovedWaitingForRetry,
		CreatedAt:         now.Add(-7 * time.Minute),
		SyncWaitDeadline:  now.Add(-6 * time.Minute),
		ApprovalExpiresAt: now.Add(15 * time.Minute),
		RetryExpiresAt:    now.Add(5 * time.Minute),
	})
	failed := h.transitionOperation(t, failedBase, HITLOperationStateUpstreamFailed, now, func(tr *HITLOperationTransition) {
		tr.UpstreamCalled = true
		tr.LastError = "upstream timeout"
	})

	cases := []struct {
		name                string
		op                  HITLOperation
		wantState           HITLOperationState
		wantTerminal        bool
		wantUpstream        bool
		wantRetryAfter      bool
		wantRetryEnvelope   bool
		wantExpiredReason   string
		wantCompletedAt     bool
		wantNoRetryEnvelope bool
	}{
		{name: "sync waiting", op: syncWaiting, wantState: HITLOperationStateSyncWaiting, wantTerminal: false, wantUpstream: false, wantRetryAfter: true},
		{name: "pending", op: pending, wantState: HITLOperationStatePendingApproval, wantTerminal: false, wantUpstream: false, wantRetryAfter: true},
		{name: "approved", op: approved, wantState: HITLOperationStateApprovedWaitingForRetry, wantTerminal: false, wantUpstream: false, wantRetryEnvelope: true},
		{name: "executing", op: executing, wantState: HITLOperationStateExecutingUpstream, wantTerminal: false, wantUpstream: true},
		{name: "denied", op: denied, wantState: HITLOperationStateDenied, wantTerminal: true, wantUpstream: false, wantNoRetryEnvelope: true},
		{name: "expired", op: expired, wantState: HITLOperationStateExpired, wantTerminal: true, wantUpstream: false, wantExpiredReason: "approval_ttl", wantNoRetryEnvelope: true},
		{name: "client disconnected", op: clientDisconnected, wantState: HITLOperationStateClientDisconnected, wantTerminal: true, wantUpstream: false, wantNoRetryEnvelope: true},
		{name: "upstream succeeded", op: succeeded, wantState: HITLOperationStateUpstreamSucceeded, wantTerminal: true, wantUpstream: true, wantCompletedAt: true, wantNoRetryEnvelope: true},
		{name: "upstream failed", op: failed, wantState: HITLOperationStateUpstreamFailed, wantTerminal: true, wantUpstream: true, wantCompletedAt: true, wantNoRetryEnvelope: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := h.poll(t, tc.op.ID, h.ownerToken)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
			}
			if got := rr.Header().Get("Clawpatrol-HITL-State"); got != string(tc.wantState) {
				t.Fatalf("Clawpatrol-HITL-State = %q, want %q", got, tc.wantState)
			}
			if got := rr.Header().Get("Clawpatrol-Upstream-Called"); got != boolHeader(tc.wantUpstream) {
				t.Fatalf("Clawpatrol-Upstream-Called = %q, want %s", got, boolHeader(tc.wantUpstream))
			}
			if got := rr.Header().Get("Retry-After"); tc.wantRetryAfter && got != "5" {
				t.Fatalf("Retry-After = %q, want 5", got)
			} else if !tc.wantRetryAfter && got != "" {
				t.Fatalf("Retry-After = %q, want empty", got)
			}

			body := decodeJSONBody(t, rr)
			if body["operation_id"] != tc.op.ID {
				t.Fatalf("operation_id = %v, want %q", body["operation_id"], tc.op.ID)
			}
			if body["state"] != string(tc.wantState) {
				t.Fatalf("state = %v, want %q", body["state"], tc.wantState)
			}
			if body["terminal"] != tc.wantTerminal {
				t.Fatalf("terminal = %v, want %v", body["terminal"], tc.wantTerminal)
			}
			if body["upstream_called"] != tc.wantUpstream {
				t.Fatalf("upstream_called = %v, want %v", body["upstream_called"], tc.wantUpstream)
			}
			if msg, _ := body["message"].(string); msg == "" {
				t.Fatalf("message is empty: %#v", body)
			}
			if tc.wantRetryEnvelope {
				if body["retry_original_request"] != true {
					t.Fatalf("retry_original_request = %v, want true", body["retry_original_request"])
				}
				if body["retry_header_name"] != hitlRetryOperationHeader {
					t.Fatalf("retry_header_name = %v, want %q", body["retry_header_name"], hitlRetryOperationHeader)
				}
				if body["retry_header_value"] != tc.op.ID {
					t.Fatalf("retry_header_value = %v, want %q", body["retry_header_value"], tc.op.ID)
				}
				if _, ok := body["retry_expires_at"].(string); !ok {
					t.Fatalf("retry_expires_at missing/string mismatch: %#v", body)
				}
			}
			if tc.wantExpiredReason != "" && body["expired_reason"] != tc.wantExpiredReason {
				t.Fatalf("expired_reason = %v, want %q", body["expired_reason"], tc.wantExpiredReason)
			}
			if tc.wantCompletedAt {
				if _, ok := body["completed_at"].(string); !ok {
					t.Fatalf("completed_at missing/string mismatch: %#v", body)
				}
			}
			if _, ok := body["last_error"]; ok {
				t.Fatalf("last_error should never be exposed on status responses: %#v", body)
			}
			if tc.wantNoRetryEnvelope {
				for _, field := range []string{"retry_original_request", "retry_header_name", "retry_header_value", "retry_expires_at"} {
					if _, ok := body[field]; ok {
						t.Fatalf("%s should be absent for %s: %#v", field, tc.wantState, body)
					}
				}
			}
		})
	}
}

func TestHITLOperationStatusEndpointDoesNotExposeReplayableMaterial(t *testing.T) {
	h := newHITLOperationAPITestHarness(t)
	op := h.createOperation(t, HITLOperationCreate{
		ID:                  "hitl_op_no_secrets",
		State:               HITLOperationStateApprovedWaitingForRetry,
		RedactedHeadersJSON: `{"authorization":"Bearer must-not-leak","cookie":"session=must-not-leak","x-safe":"ok"}`,
		AuthBindingID:       "credential-secret-binding-must-not-leak",
		HMACKeyID:           "hmac-key-id-must-not-leak",
		RequestFingerprint:  "raw-body-hmac-must-not-leak",
		RetryExpiresAt:      time.Unix(1_700_003_000, 0).UTC().Add(5 * time.Minute),
	})
	op = h.transitionOperation(t, op, HITLOperationStateUpstreamFailed, time.Unix(1_700_003_000, 0).UTC(), func(tr *HITLOperationTransition) {
		tr.UpstreamCalled = true
		tr.LastError = "Authorization Bearer must-not-leak token=must-not-leak"
	})

	rr := h.poll(t, op.ID, h.ownerToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, forbidden := range []string{
		"Bearer must-not-leak",
		"session=must-not-leak",
		"credential-secret-binding-must-not-leak",
		"hmac-key-id-must-not-leak",
		"raw-body-hmac-must-not-leak",
		"redacted_headers",
		"auth_binding_id",
		"hmac_key_id",
		"request_fingerprint",
		"last_error",
		"Authorization Bearer must-not-leak token=must-not-leak",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("status response leaked %q in body: %s", forbidden, body)
		}
	}
}

type hitlOperationAPITestHarness struct {
	handler    http.Handler
	store      *HITLOperationStore
	ownerToken string
	otherToken string
}

func newHITLOperationAPITestHarness(t *testing.T) hitlOperationAPITestHarness {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ownerToken, err := mintAndPersistPeerAPIToken(db, "100.64.0.2")
	if err != nil {
		t.Fatalf("mint owner token: %v", err)
	}
	otherToken, err := mintAndPersistPeerAPIToken(db, "100.64.0.9")
	if err != nil {
		t.Fatalf("mint other token: %v", err)
	}

	gwCfg := loadHITLOperationAPITestConfig(t)
	g := &Gateway{cfg: gwCfg, db: db, onboard: newOnboardRegistry()}
	w := newWebMux(g, gwCfg.Join(), gwCfg.PublicURL)
	return hitlOperationAPITestHarness{
		handler:    w,
		store:      NewHITLOperationStore(db),
		ownerToken: ownerToken,
		otherToken: otherToken,
	}
}

func loadHITLOperationAPITestConfig(t *testing.T) *config.Gateway {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(`
admin_email = "ops@example.test"
public_url = "https://gateway.example.test"
control = "wireguard"
wg_subnet_cidr = "10.55.0.0/24"

credential "bearer_token" "tok" {}
endpoint "https" "api" {
  hosts      = ["api.example.test"]
  credential = tok
}
profile "agent" {
  endpoints = [api]
  hitl_async_grants = true
}
`), "hitl-api-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load config: %v", diags)
	}
	return gw
}

func (h hitlOperationAPITestHarness) createOperation(t *testing.T, overrides HITLOperationCreate) HITLOperation {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	base := HITLOperationCreate{
		ID:                  "hitl_op_test",
		State:               HITLOperationStatePendingApproval,
		ProfileID:           "agent",
		PrincipalID:         "peer:100.64.0.2",
		EndpointID:          "api",
		ApprovalRuleID:      "rule:dangerous-write",
		ApproverID:          "human_approver.ops",
		Method:              "POST",
		Scheme:              "https",
		Host:                "api.example.test",
		RedactedPath:        "/v1/write",
		RedactedQuery:       "",
		RedactedHeadersJSON: `{"content-type":"application/json"}`,
		AuthBindingID:       "credential:api:v1",
		FingerprintVersion:  HITLFingerprintVersionV1,
		HMACKeyID:           "hitl-hmac:v1",
		RequestFingerprint:  "hmac-sha256:abcdef",
		CreatedAt:           now,
		SyncWaitDeadline:    now.Add(-time.Minute),
		ApprovalExpiresAt:   now.Add(15 * time.Minute),
	}
	applyHITLOperationCreateOverrides(&base, overrides)
	created, err := h.store.Create(context.Background(), base)
	if err != nil {
		t.Fatalf("Create operation: %v", err)
	}
	return created
}

func (h hitlOperationAPITestHarness) transitionOperation(t *testing.T, op HITLOperation, state HITLOperationState, now time.Time, mutate func(*HITLOperationTransition)) HITLOperation {
	t.Helper()
	tr := HITLOperationTransition{
		ID:              op.ID,
		FromState:       op.State,
		ToState:         state,
		ExpectedVersion: op.Version,
		Now:             now,
	}
	if mutate != nil {
		mutate(&tr)
	}
	updated, err := h.store.Transition(context.Background(), tr)
	if err != nil {
		t.Fatalf("Transition operation to %s: %v", state, err)
	}
	return updated
}

func applyHITLOperationCreateOverrides(base *HITLOperationCreate, overrides HITLOperationCreate) {
	if overrides.ID != "" {
		base.ID = overrides.ID
	}
	if overrides.State != "" {
		base.State = overrides.State
	}
	if overrides.ProfileID != "" {
		base.ProfileID = overrides.ProfileID
	}
	if overrides.PrincipalID != "" {
		base.PrincipalID = overrides.PrincipalID
	}
	if overrides.RedactedHeadersJSON != "" {
		base.RedactedHeadersJSON = overrides.RedactedHeadersJSON
	}
	if overrides.AuthBindingID != "" {
		base.AuthBindingID = overrides.AuthBindingID
	}
	if overrides.HMACKeyID != "" {
		base.HMACKeyID = overrides.HMACKeyID
	}
	if overrides.RequestFingerprint != "" {
		base.RequestFingerprint = overrides.RequestFingerprint
	}
	if !overrides.CreatedAt.IsZero() {
		base.CreatedAt = overrides.CreatedAt
	}
	if !overrides.SyncWaitDeadline.IsZero() {
		base.SyncWaitDeadline = overrides.SyncWaitDeadline
	}
	if !overrides.ApprovalExpiresAt.IsZero() {
		base.ApprovalExpiresAt = overrides.ApprovalExpiresAt
	}
	if !overrides.RetryExpiresAt.IsZero() {
		base.RetryExpiresAt = overrides.RetryExpiresAt
	}
}

func (h hitlOperationAPITestHarness) poll(t *testing.T, operationID, token string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/hitl/operations/"+operationID+"/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h.handler.ServeHTTP(rr, req)
	return rr
}

func decodeJSONBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode JSON body: %v\nbody=%s", err, rr.Body.String())
	}
	return body
}

func boolHeader(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
