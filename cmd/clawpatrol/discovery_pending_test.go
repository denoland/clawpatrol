package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestInternalPendingList exercises the parked-action list surface the
// discovery manifest documents (clawpatrol.internal/pending): a device sees
// the requests it has parked awaiting human approval — resolved from the
// connection-derived profile/principal — and never another device's, with
// no async-poll machinery (operation id, status token) in the response.
func TestInternalPendingList(t *testing.T) {
	db := openHITLOperationTestDB(t)
	g := &Gateway{db: db}
	store := NewHITLOperationStore(db)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	const (
		profile   = "ops"
		principal = "peer:100.64.0.2"
	)

	mkOp := func(id string, state HITLOperationState, fp string) HITLOperation {
		op, err := store.Create(ctx, HITLOperationCreate{
			ID:                 id,
			State:              state,
			ProfileID:          profile,
			PrincipalID:        principal,
			EndpointID:         "deploy",
			ApprovalRuleID:     "gated-deploy",
			ApproverID:         "release",
			Method:             "POST",
			Scheme:             "https",
			Host:               "deploy.example",
			RedactedPath:       "/v1/deploy",
			AuthBindingID:      "credential:deploy:v1",
			FingerprintVersion: HITLFingerprintVersionV1,
			HMACKeyID:          "hitl-hmac:v1",
			RequestFingerprint: "hmac-sha256:" + fp,
			CreatedAt:          now,
			SyncWaitDeadline:   now.Add(90 * time.Second),
			ApprovalExpiresAt:  now.Add(15 * time.Minute),
		})
		if err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
		return op
	}

	// One held synchronously, one pending approval — both are parked.
	mkOp("hitl_op_sync", HITLOperationStateSyncWaiting, "sync")
	mkOp("hitl_op_pending", HITLOperationStatePendingApproval, "pending")
	// A denied (terminal) operation must NOT appear in the parked list.
	mkOp("hitl_op_denied", HITLOperationStateDenied, "denied")
	// Another device's parked request must be invisible here.
	if _, err := store.Create(ctx, HITLOperationCreate{
		ID:                 "hitl_op_other",
		State:              HITLOperationStateSyncWaiting,
		ProfileID:          profile,
		PrincipalID:        "peer:100.64.0.9",
		EndpointID:         "deploy",
		ApprovalRuleID:     "gated-deploy",
		ApproverID:         "release",
		Method:             "POST",
		Scheme:             "https",
		Host:               "deploy.example",
		RedactedPath:       "/v1/deploy",
		AuthBindingID:      "credential:deploy:v1",
		FingerprintVersion: HITLFingerprintVersionV1,
		HMACKeyID:          "hitl-hmac:v1",
		RequestFingerprint: "hmac-sha256:other",
		CreatedAt:          now,
		SyncWaitDeadline:   now.Add(90 * time.Second),
		ApprovalExpiresAt:  now.Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("Create other: %v", err)
	}

	decode := func(t *testing.T, prof, prin string) []map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://clawpatrol.internal"+hitlPendingPath, nil)
		g.serveInternalPending(rec, req, prof, prin, strings.TrimPrefix(prin, "peer:"))
		if rec.Code != 200 {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Pending []map[string]any `json:"pending"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body.Pending
	}

	// The owning device sees exactly its two parked actions, not the
	// terminal one and not the other device's.
	t.Run("owner sees parked actions", func(t *testing.T) {
		pending := decode(t, profile, principal)
		if len(pending) != 2 {
			t.Fatalf("pending count = %d, want 2 (sync_waiting + pending_approval)", len(pending))
		}
		for _, p := range pending {
			if p["endpoint"] != "deploy" {
				t.Errorf("endpoint = %v, want deploy", p["endpoint"])
			}
			if p["url"] != "https://deploy.example/v1/deploy" {
				t.Errorf("url = %v", p["url"])
			}
			// No async-poll machinery leaks into the list.
			if _, ok := p["operation_id"]; ok {
				t.Errorf("pending action leaked operation_id: %v", p)
			}
			if _, ok := p["status_url"]; ok {
				t.Errorf("pending action leaked status_url: %v", p)
			}
			if _, ok := p["status_token"]; ok {
				t.Errorf("pending action leaked status_token: %v", p)
			}
		}
	})

	// A device with nothing parked gets an empty (non-null) list.
	t.Run("foreign device sees empty list", func(t *testing.T) {
		pending := decode(t, profile, "peer:100.64.0.42")
		if len(pending) != 0 {
			t.Errorf("pending count = %d, want 0 for a device with nothing parked", len(pending))
		}
	})

	// Non-GET is rejected.
	t.Run("method not allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "https://clawpatrol.internal"+hitlPendingPath, nil)
		g.serveInternalPending(rec, req, profile, principal, "100.64.0.2")
		if rec.Code != 405 {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})
}

// TestInternalPendingListsSyncPool covers the case the manifest actually
// advertises /pending for: a PURE-SYNCHRONOUS human-approval park (a
// `dashboard` / `human_approver` rule with no async grant). Such a park lives
// only in the in-memory HITL pool — it never writes a hitl_operations row — so
// reading the DB alone returns []. /pending must merge the caller's sync-only
// pool entries (OperationID == "", matching AgentIP) so the list reflects what
// is really held. Entries that carry an operation id (the async path) are
// already in the DB and must not be double-listed; another device's pool
// entry must stay invisible.
func TestInternalPendingListsSyncPool(t *testing.T) {
	const agentIP = "100.64.0.2"
	principal := hitlPeerPrincipalID(agentIP)
	g := &Gateway{hitl: newHITLRegistry(nil)}
	now := time.Unix(1_700_000_000, 0).UTC()

	// A pure-sync park by this device — no operation id, so never in the DB.
	g.hitl.Add(runtime.HITLPending{
		AgentIP:   agentIP,
		Host:      "httpbin.org",
		Method:    "GET",
		Path:      "/get?token=shh-secret",
		Endpoint:  "httpbin",
		CreatedAt: now,
	})
	// An async park (operation id set) — already represented by a DB row, so
	// /pending must NOT re-list it from the pool.
	g.hitl.Add(runtime.HITLPending{
		OperationID: "hitl_op_async",
		AgentIP:     agentIP,
		Host:        "httpbin.org",
		Method:      "POST",
		Path:        "/post",
		Endpoint:    "httpbin",
		CreatedAt:   now,
	})
	// Another device's pure-sync park — must stay invisible here.
	g.hitl.Add(runtime.HITLPending{
		AgentIP:   "100.64.0.9",
		Host:      "httpbin.org",
		Method:    "GET",
		Path:      "/headers",
		Endpoint:  "httpbin",
		CreatedAt: now,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://clawpatrol.internal"+hitlPendingPath, nil)
	g.serveInternalPending(rec, req, "ops", principal, agentIP)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Pending []map[string]any `json:"pending"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(body.Pending) != 1 {
		t.Fatalf("pending count = %d, want 1 (only the caller's sync-only park)", len(body.Pending))
	}
	got := body.Pending[0]
	if got["endpoint"] != "httpbin" {
		t.Errorf("endpoint = %v, want httpbin", got["endpoint"])
	}
	if got["method"] != "GET" {
		t.Errorf("method = %v, want GET", got["method"])
	}
	// Query string is dropped, matching the DB path's redaction — the
	// secret-bearing token must not surface in the redacted view.
	if got["url"] != "https://httpbin.org/get" {
		t.Errorf("url = %v, want https://httpbin.org/get (query dropped)", got["url"])
	}
	if _, ok := got["operation_id"]; ok {
		t.Errorf("pending action leaked operation_id: %v", got)
	}
}
