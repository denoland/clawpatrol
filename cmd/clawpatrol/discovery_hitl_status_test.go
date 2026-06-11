package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// TestInternalHITLStatusPoll exercises the approval-status poll surface
// the discovery manifest documents (clawpatrol.internal/api/hitl/
// operations/{id}/status): a parked operation is returned to the device
// that parked it (resolved from the connection-derived profile/principal),
// hidden from other devices, and reachable by its capability token.
func TestInternalHITLStatusPoll(t *testing.T) {
	db := openHITLOperationTestDB(t)
	g := &Gateway{db: db}
	store := NewHITLOperationStore(db)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	const (
		profile   = "ops"
		principal = "peer:100.64.0.2"
	)
	op, err := store.Create(ctx, HITLOperationCreate{
		ID:                 "hitl_op_poll",
		State:              HITLOperationStatePendingApproval,
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
		RequestFingerprint: "hmac-sha256:abc",
		CreatedAt:          now,
		SyncWaitDeadline:   now.Add(90 * time.Second),
		ApprovalExpiresAt:  now.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	statusPath := hitlOperationStatusPrefix + op.ID + hitlOperationStatusSuffix

	// The device that parked it polls by principal and sees the pending
	// state — no token required.
	t.Run("owner by principal", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://clawpatrol.internal"+statusPath, nil)
		g.serveInternalHITLStatus(rec, req, profile, principal)
		if rec.Code != 200 {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body["operation_id"] != op.ID {
			t.Errorf("operation_id = %v, want %q", body["operation_id"], op.ID)
		}
		if body["state"] != string(HITLOperationStatePendingApproval) {
			t.Errorf("state = %v, want %q", body["state"], HITLOperationStatePendingApproval)
		}
		if body["upstream_called"] != false {
			t.Errorf("upstream_called = %v, want false (parked, not yet forwarded)", body["upstream_called"])
		}
	})

	// A request parked synchronously (the connection is still held open
	// pending approval, state sync_waiting) is pollable on the same endpoint
	// — polling is not limited to the async/handed-back path. The owning
	// device sees it pending, with upstream not yet called.
	t.Run("sync-parked operation pollable", func(t *testing.T) {
		syncOp, err := store.Create(ctx, HITLOperationCreate{
			ID:                 "hitl_op_sync",
			State:              HITLOperationStateSyncWaiting,
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
			RequestFingerprint: "hmac-sha256:sync",
			CreatedAt:          now,
			SyncWaitDeadline:   now.Add(90 * time.Second),
			ApprovalExpiresAt:  now.Add(15 * time.Minute),
		})
		if err != nil {
			t.Fatalf("Create sync op: %v", err)
		}
		path := hitlOperationStatusPrefix + syncOp.ID + hitlOperationStatusSuffix
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://clawpatrol.internal"+path, nil)
		g.serveInternalHITLStatus(rec, req, profile, principal)
		if rec.Code != 200 {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body["state"] != string(HITLOperationStateSyncWaiting) {
			t.Errorf("state = %v, want %q", body["state"], HITLOperationStateSyncWaiting)
		}
		if body["upstream_called"] != false {
			t.Errorf("upstream_called = %v, want false (parked, not yet forwarded)", body["upstream_called"])
		}
		if body["terminal"] != false {
			t.Errorf("terminal = %v, want false (still awaiting a human)", body["terminal"])
		}
	})

	// A different device (wrong principal) must not see another device's
	// parked request.
	t.Run("other device 404", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://clawpatrol.internal"+statusPath, nil)
		g.serveInternalHITLStatus(rec, req, profile, "peer:100.64.0.9")
		if rec.Code != 404 {
			t.Errorf("status = %d, want 404 for foreign principal", rec.Code)
		}
	})

	// The capability token resolves the operation regardless of principal.
	t.Run("by status token", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://clawpatrol.internal"+statusPath+"?token="+op.StatusToken, nil)
		g.serveInternalHITLStatus(rec, req, profile, "peer:100.64.0.9")
		if rec.Code != 200 {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body["operation_id"] != op.ID {
			t.Errorf("operation_id = %v, want %q", body["operation_id"], op.ID)
		}
	})

	// A wrong token does not fall back to leaking the operation.
	t.Run("wrong token 404", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://clawpatrol.internal"+statusPath+"?token=nope", nil)
		g.serveInternalHITLStatus(rec, req, profile, "peer:100.64.0.9")
		if rec.Code != 404 {
			t.Errorf("status = %d, want 404 for wrong token", rec.Code)
		}
	})

	// An unknown operation id is a 404, not a 500.
	t.Run("unknown id 404", func(t *testing.T) {
		rec := httptest.NewRecorder()
		path := hitlOperationStatusPrefix + "does-not-exist" + hitlOperationStatusSuffix
		req := httptest.NewRequest("GET", "https://clawpatrol.internal"+path, nil)
		g.serveInternalHITLStatus(rec, req, profile, principal)
		if rec.Code != 404 {
			t.Errorf("status = %d, want 404 for unknown operation", rec.Code)
		}
	})

	// Non-GET is rejected.
	t.Run("method not allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "https://clawpatrol.internal"+statusPath, nil)
		g.serveInternalHITLStatus(rec, req, profile, principal)
		if rec.Code != 405 {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})
}
