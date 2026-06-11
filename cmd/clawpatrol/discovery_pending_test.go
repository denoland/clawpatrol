package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
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
		g.serveInternalPending(rec, req, prof, prin)
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
		g.serveInternalPending(rec, req, profile, principal)
		if rec.Code != 405 {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})
}
