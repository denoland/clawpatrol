package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHITLOperationStoreCreatesMetadataOnlyOperation(t *testing.T) {
	db := openHITLOperationTestDB(t)
	store := NewHITLOperationStore(db)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 123).UTC()

	created, err := store.Create(ctx, HITLOperationCreate{
		ID:                  "hitl_op_create",
		ProfileID:           "agent",
		PrincipalID:         "peer:100.64.0.2",
		EndpointID:          "api",
		ApprovalRuleID:      "rule:dangerous-write",
		ApproverID:          "human_approver.ops",
		Method:              "POST",
		Scheme:              "https",
		Host:                "api.example.test",
		RedactedPath:        "/v1/write",
		RedactedQuery:       "?account=[redacted]",
		RedactedHeadersJSON: `{"content-type":"application/json"}`,
		AuthBindingID:       "credential:api:v1",
		FingerprintVersion:  HITLFingerprintVersionV1,
		HMACKeyID:           "hitl-hmac:v1",
		RequestFingerprint:  "hmac-sha256:abcdef",
		CreatedAt:           now,
		SyncWaitDeadline:    now.Add(90 * time.Second),
		ApprovalExpiresAt:   now.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID != "hitl_op_create" {
		t.Fatalf("created ID = %q", created.ID)
	}
	if created.State != HITLOperationStateSyncWaiting {
		t.Fatalf("state = %q, want %q", created.State, HITLOperationStateSyncWaiting)
	}
	if created.Version != 1 {
		t.Fatalf("version = %d, want 1", created.Version)
	}
	if created.GrantConsumedAt != nil {
		t.Fatalf("GrantConsumedAt = %v, want nil", created.GrantConsumedAt)
	}

	loaded, err := store.GetForPrincipal(ctx, created.ID, "agent", "peer:100.64.0.2")
	if err != nil {
		t.Fatalf("GetForPrincipal: %v", err)
	}
	if loaded.RequestFingerprint != "hmac-sha256:abcdef" || loaded.HMACKeyID != "hitl-hmac:v1" {
		t.Fatalf("loaded fingerprint fields = %#v", loaded)
	}
	if loaded.RedactedQuery != "?account=[redacted]" {
		t.Fatalf("RedactedQuery = %q", loaded.RedactedQuery)
	}

	for _, tc := range []struct {
		name      string
		profileID string
		principal string
	}{
		{name: "wrong profile", profileID: "other", principal: "peer:100.64.0.2"},
		{name: "wrong principal", profileID: "agent", principal: "peer:100.64.0.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.GetForPrincipal(ctx, created.ID, tc.profileID, tc.principal)
			if !errors.Is(err, ErrHITLOperationNotFound) {
				t.Fatalf("GetForPrincipal err = %v, want ErrHITLOperationNotFound", err)
			}
		})
	}

	assertHITLOperationSchemaDoesNotStoreReplayableMaterial(t, db)
}

func TestHITLOperationStoreRejectsUnknownState(t *testing.T) {
	db := openHITLOperationTestDB(t)
	store := NewHITLOperationStore(db)
	now := time.Unix(1_700_000_050, 0).UTC()

	_, err := store.Create(context.Background(), HITLOperationCreate{
		ID:                 "hitl_op_bad_state",
		State:              HITLOperationState("surprising_new_state"),
		ProfileID:          "agent",
		PrincipalID:        "peer:100.64.0.2",
		EndpointID:         "api",
		ApprovalRuleID:     "rule:dangerous-write",
		ApproverID:         "human_approver.ops",
		Method:             "POST",
		Scheme:             "https",
		Host:               "api.example.test",
		RedactedPath:       "/v1/write",
		AuthBindingID:      "credential:api:v1",
		FingerprintVersion: HITLFingerprintVersionV1,
		HMACKeyID:          "hitl-hmac:v1",
		RequestFingerprint: "hmac-sha256:abcdef",
		CreatedAt:          now,
		SyncWaitDeadline:   now.Add(90 * time.Second),
		ApprovalExpiresAt:  now.Add(15 * time.Minute),
	})
	if !errors.Is(err, ErrHITLOperationStoreInvalid) {
		t.Fatalf("Create err = %v, want ErrHITLOperationStoreInvalid", err)
	}
}

func TestHITLOperationStoreTransitionsWithCompareAndSwap(t *testing.T) {
	db := openHITLOperationTestDB(t)
	store := NewHITLOperationStore(db)
	ctx := context.Background()
	now := time.Unix(1_700_000_100, 0).UTC()

	op := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_cas",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now,
		SyncWaitDeadline:  now.Add(-time.Second),
		ApprovalExpiresAt: now.Add(15 * time.Minute),
	})

	updated, err := store.Transition(ctx, HITLOperationTransition{
		ID:              op.ID,
		FromState:       HITLOperationStatePendingApproval,
		ToState:         HITLOperationStateApprovedWaitingForRetry,
		ExpectedVersion: op.Version,
		Now:             now.Add(30 * time.Second),
		RetryExpiresAt:  now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if updated.State != HITLOperationStateApprovedWaitingForRetry {
		t.Fatalf("state = %q", updated.State)
	}
	if updated.Version != op.Version+1 {
		t.Fatalf("version = %d, want %d", updated.Version, op.Version+1)
	}
	if updated.RetryExpiresAt == nil || !updated.RetryExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("RetryExpiresAt = %v", updated.RetryExpiresAt)
	}

	_, err = store.Transition(ctx, HITLOperationTransition{
		ID:              op.ID,
		FromState:       HITLOperationStatePendingApproval,
		ToState:         HITLOperationStateDenied,
		ExpectedVersion: op.Version,
		Now:             now.Add(time.Minute),
	})
	if !errors.Is(err, ErrHITLOperationConflict) {
		t.Fatalf("stale Transition err = %v, want ErrHITLOperationConflict", err)
	}

	loaded, err := store.GetForPrincipal(ctx, op.ID, "agent", "peer:100.64.0.2")
	if err != nil {
		t.Fatalf("reload after stale transition: %v", err)
	}
	if loaded.State != HITLOperationStateApprovedWaitingForRetry || loaded.Version != updated.Version {
		t.Fatalf("stale transition changed operation: %#v", loaded)
	}
}

func TestHITLOperationTransitionCannotConsumeRetryGrant(t *testing.T) {
	if _, ok := reflect.TypeOf(HITLOperationTransition{}).FieldByName("GrantConsumedBy"); ok {
		t.Fatal("generic HITLOperationTransition must not expose retry-grant consumption; use ConsumeRetryGrant")
	}
}

func TestHITLOperationStoreConsumeRetryGrantIsOneShotAndMismatchSafe(t *testing.T) {
	db := openHITLOperationTestDB(t)
	store := NewHITLOperationStore(db)
	ctx := context.Background()
	now := time.Unix(1_700_000_200, 0).UTC()

	op := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_retry",
		State:             HITLOperationStateApprovedWaitingForRetry,
		CreatedAt:         now.Add(-2 * time.Minute),
		SyncWaitDeadline:  now.Add(-90 * time.Second),
		ApprovalExpiresAt: now.Add(10 * time.Minute),
		RetryExpiresAt:    now.Add(5 * time.Minute),
	})

	for _, tc := range []struct {
		name               string
		authBindingID      string
		fingerprintVersion string
		hmacKeyID          string
		requestFingerprint string
	}{
		{
			name:               "auth binding",
			authBindingID:      "credential:other:v1",
			fingerprintVersion: op.FingerprintVersion,
			hmacKeyID:          op.HMACKeyID,
			requestFingerprint: op.RequestFingerprint,
		},
		{
			name:               "fingerprint version",
			authBindingID:      op.AuthBindingID,
			fingerprintVersion: "v2",
			hmacKeyID:          op.HMACKeyID,
			requestFingerprint: op.RequestFingerprint,
		},
		{
			name:               "hmac key id",
			authBindingID:      op.AuthBindingID,
			fingerprintVersion: op.FingerprintVersion,
			hmacKeyID:          "hitl-hmac:v2",
			requestFingerprint: op.RequestFingerprint,
		},
		{
			name:               "request fingerprint",
			authBindingID:      op.AuthBindingID,
			fingerprintVersion: op.FingerprintVersion,
			hmacKeyID:          op.HMACKeyID,
			requestFingerprint: "hmac-sha256:other",
		},
	} {
		t.Run("mismatched "+tc.name, func(t *testing.T) {
			_, err := store.ConsumeRetryGrant(ctx, HITLRetryGrantConsume{
				ID:                 op.ID,
				ProfileID:          "agent",
				PrincipalID:        "peer:100.64.0.2",
				AuthBindingID:      tc.authBindingID,
				FingerprintVersion: tc.fingerprintVersion,
				HMACKeyID:          tc.hmacKeyID,
				RequestFingerprint: tc.requestFingerprint,
				ConsumedBy:         "peer:100.64.0.2",
				Now:                now,
			})
			if !errors.Is(err, ErrHITLRetryMismatch) {
				t.Fatalf("mismatched %s err = %v, want ErrHITLRetryMismatch", tc.name, err)
			}
			unchanged, err := store.GetForPrincipal(ctx, op.ID, "agent", "peer:100.64.0.2")
			if err != nil {
				t.Fatalf("reload after mismatch: %v", err)
			}
			if unchanged.State != HITLOperationStateApprovedWaitingForRetry || unchanged.GrantConsumedAt != nil {
				t.Fatalf("mismatch consumed or changed grant: %#v", unchanged)
			}
		})
	}

	consumed, err := store.ConsumeRetryGrant(ctx, HITLRetryGrantConsume{
		ID:                 op.ID,
		ProfileID:          "agent",
		PrincipalID:        "peer:100.64.0.2",
		AuthBindingID:      op.AuthBindingID,
		FingerprintVersion: op.FingerprintVersion,
		HMACKeyID:          op.HMACKeyID,
		RequestFingerprint: op.RequestFingerprint,
		ConsumedBy:         "peer:100.64.0.2",
		Now:                now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("ConsumeRetryGrant: %v", err)
	}
	if consumed.State != HITLOperationStateExecutingUpstream {
		t.Fatalf("state = %q, want %q", consumed.State, HITLOperationStateExecutingUpstream)
	}
	if !consumed.UpstreamCalled {
		t.Fatal("UpstreamCalled = false, want true after consuming retry grant")
	}
	if consumed.GrantConsumedAt == nil || !consumed.GrantConsumedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("GrantConsumedAt = %v", consumed.GrantConsumedAt)
	}
	if consumed.GrantConsumedBy != "peer:100.64.0.2" {
		t.Fatalf("GrantConsumedBy = %q", consumed.GrantConsumedBy)
	}

	_, err = store.ConsumeRetryGrant(ctx, HITLRetryGrantConsume{
		ID:                 op.ID,
		ProfileID:          "agent",
		PrincipalID:        "peer:100.64.0.2",
		AuthBindingID:      op.AuthBindingID,
		FingerprintVersion: op.FingerprintVersion,
		HMACKeyID:          op.HMACKeyID,
		RequestFingerprint: op.RequestFingerprint,
		ConsumedBy:         "peer:100.64.0.2",
		Now:                now.Add(2 * time.Second),
	})
	if !errors.Is(err, ErrHITLGrantAlreadyConsumed) {
		t.Fatalf("second ConsumeRetryGrant err = %v, want ErrHITLGrantAlreadyConsumed", err)
	}
}

func openHITLOperationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func createTestHITLOperation(t *testing.T, store *HITLOperationStore, overrides HITLOperationCreate) HITLOperation {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	base := HITLOperationCreate{
		ID:                  "hitl_op_test",
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
		SyncWaitDeadline:    now.Add(90 * time.Second),
		ApprovalExpiresAt:   now.Add(15 * time.Minute),
	}
	if overrides.ID != "" {
		base.ID = overrides.ID
	}
	if overrides.State != "" {
		base.State = overrides.State
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

	created, err := store.Create(context.Background(), base)
	if err != nil {
		t.Fatalf("Create test operation: %v", err)
	}
	return created
}

func assertHITLOperationSchemaDoesNotStoreReplayableMaterial(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(hitl_operations)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(hitl_operations): %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		lower := strings.ToLower(name)
		for _, forbidden := range []string{"raw_", "body", "authorization", "cookie", "secret"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("hitl_operations column %q looks like replayable request material", name)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info rows: %v", err)
	}
}
