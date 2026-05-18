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

func TestHITLOperationStoreMaintenanceExpiresDueOperations(t *testing.T) {
	db := openHITLOperationTestDB(t)
	store := NewHITLOperationStore(db)
	ctx := context.Background()
	now := time.Unix(1_700_000_300, 0).UTC()
	retention := 24 * time.Hour

	pendingExpired := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_pending_expired",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now.Add(-30 * time.Minute),
		SyncWaitDeadline:  now.Add(-29 * time.Minute),
		ApprovalExpiresAt: now.Add(-time.Second),
	})
	pendingFuture := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_pending_future",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now.Add(-time.Minute),
		SyncWaitDeadline:  now.Add(-30 * time.Second),
		ApprovalExpiresAt: now.Add(time.Minute),
	})
	retryExpired := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_retry_expired",
		State:             HITLOperationStateApprovedWaitingForRetry,
		CreatedAt:         now.Add(-30 * time.Minute),
		SyncWaitDeadline:  now.Add(-29 * time.Minute),
		ApprovalExpiresAt: now.Add(time.Minute),
		RetryExpiresAt:    now.Add(-time.Second),
	})
	retryFuture := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_retry_future",
		State:             HITLOperationStateApprovedWaitingForRetry,
		CreatedAt:         now.Add(-30 * time.Minute),
		SyncWaitDeadline:  now.Add(-29 * time.Minute),
		ApprovalExpiresAt: now.Add(time.Minute),
		RetryExpiresAt:    now.Add(time.Minute),
	})

	result, err := store.ExpireDueOperations(ctx, now, retention)
	if err != nil {
		t.Fatalf("ExpireDueOperations: %v", err)
	}
	if result.PendingApprovalExpired != 1 || result.ApprovedRetryExpired != 1 {
		t.Fatalf("ExpireDueOperations result = %#v, want one pending and one retry expiration", result)
	}

	assertExpired := func(t *testing.T, op HITLOperation, wantReason string) {
		t.Helper()
		loaded, err := store.GetForPrincipal(ctx, op.ID, op.ProfileID, op.PrincipalID)
		if err != nil {
			t.Fatalf("GetForPrincipal(%s): %v", op.ID, err)
		}
		if loaded.State != HITLOperationStateExpired {
			t.Fatalf("%s state = %q, want expired", op.ID, loaded.State)
		}
		if loaded.ExpiredReason != wantReason {
			t.Fatalf("%s ExpiredReason = %q, want %q", op.ID, loaded.ExpiredReason, wantReason)
		}
		if loaded.TerminalAt == nil || !loaded.TerminalAt.Equal(now) {
			t.Fatalf("%s TerminalAt = %v, want %v", op.ID, loaded.TerminalAt, now)
		}
		if loaded.TerminalRetentionExpiresAt == nil || !loaded.TerminalRetentionExpiresAt.Equal(now.Add(retention)) {
			t.Fatalf("%s TerminalRetentionExpiresAt = %v, want %v", op.ID, loaded.TerminalRetentionExpiresAt, now.Add(retention))
		}
		if loaded.UpstreamCalled {
			t.Fatalf("%s UpstreamCalled = true, want false for expiry", op.ID)
		}
	}
	assertExpired(t, pendingExpired, "approval_ttl_expired")
	assertExpired(t, retryExpired, "approved_retry_ttl_expired")

	for _, op := range []HITLOperation{pendingFuture, retryFuture} {
		loaded, err := store.GetForPrincipal(ctx, op.ID, op.ProfileID, op.PrincipalID)
		if err != nil {
			t.Fatalf("GetForPrincipal(%s): %v", op.ID, err)
		}
		if loaded.State != op.State {
			t.Fatalf("%s state = %q, want unchanged %q", op.ID, loaded.State, op.State)
		}
	}
}

func TestHITLOperationStoreMaintenanceRecoversStaleStartupStates(t *testing.T) {
	db := openHITLOperationTestDB(t)
	store := NewHITLOperationStore(db)
	ctx := context.Background()
	now := time.Unix(1_700_000_400, 0).UTC()
	retention := 24 * time.Hour

	staleSync := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_stale_sync",
		State:             HITLOperationStateSyncWaiting,
		CreatedAt:         now.Add(-10 * time.Minute),
		SyncWaitDeadline:  now.Add(-9 * time.Minute),
		ApprovalExpiresAt: now.Add(5 * time.Minute),
	})
	freshSync := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_fresh_sync",
		State:             HITLOperationStateSyncWaiting,
		CreatedAt:         now.Add(-time.Second),
		SyncWaitDeadline:  now.Add(time.Minute),
		ApprovalExpiresAt: now.Add(5 * time.Minute),
	})
	executing := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_executing",
		State:             HITLOperationStateExecutingUpstream,
		CreatedAt:         now.Add(-10 * time.Minute),
		SyncWaitDeadline:  now.Add(-9 * time.Minute),
		ApprovalExpiresAt: now.Add(5 * time.Minute),
	})

	result, err := store.RecoverStaleInProgressOperations(ctx, now, retention)
	if err != nil {
		t.Fatalf("RecoverStaleInProgressOperations: %v", err)
	}
	if result.SyncWaitingRecovered != 1 || result.ExecutingRecovered != 1 {
		t.Fatalf("RecoverStaleInProgressOperations result = %#v, want one sync and one executing recovery", result)
	}

	loadedSync, err := store.GetForPrincipal(ctx, staleSync.ID, staleSync.ProfileID, staleSync.PrincipalID)
	if err != nil {
		t.Fatalf("GetForPrincipal(stale sync): %v", err)
	}
	if loadedSync.State != HITLOperationStateClientDisconnected || loadedSync.UpstreamCalled {
		t.Fatalf("stale sync = %#v, want client_disconnected without upstream call", loadedSync)
	}

	loadedExecuting, err := store.GetForPrincipal(ctx, executing.ID, executing.ProfileID, executing.PrincipalID)
	if err != nil {
		t.Fatalf("GetForPrincipal(executing): %v", err)
	}
	if loadedExecuting.State != HITLOperationStateUpstreamFailed || !loadedExecuting.UpstreamCalled || loadedExecuting.LastError == "" {
		t.Fatalf("executing = %#v, want upstream_failed with upstream_called and diagnostic", loadedExecuting)
	}

	loadedFresh, err := store.GetForPrincipal(ctx, freshSync.ID, freshSync.ProfileID, freshSync.PrincipalID)
	if err != nil {
		t.Fatalf("GetForPrincipal(fresh sync): %v", err)
	}
	if loadedFresh.State != HITLOperationStateSyncWaiting {
		t.Fatalf("fresh sync state = %q, want unchanged sync_waiting", loadedFresh.State)
	}
}

func TestHITLOperationStartupMaintenanceRunsRecoveryExpiryAndPurge(t *testing.T) {
	db := openHITLOperationTestDB(t)
	store := NewHITLOperationStore(db)
	ctx := context.Background()
	now := time.Now().Add(-time.Hour).UTC()

	staleSync := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_startup_stale_sync",
		State:             HITLOperationStateSyncWaiting,
		CreatedAt:         now.Add(-10 * time.Minute),
		SyncWaitDeadline:  now.Add(-9 * time.Minute),
		ApprovalExpiresAt: now.Add(5 * time.Minute),
	})
	duePending := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_startup_due_pending",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now.Add(-30 * time.Minute),
		SyncWaitDeadline:  now.Add(-29 * time.Minute),
		ApprovalExpiresAt: now.Add(-time.Minute),
	})
	oldTerminal := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_startup_old_terminal",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now.Add(-48 * time.Hour),
		SyncWaitDeadline:  now.Add(-48 * time.Hour),
		ApprovalExpiresAt: now.Add(-47 * time.Hour),
	})
	_, err := store.Transition(ctx, HITLOperationTransition{
		ID:                         oldTerminal.ID,
		FromState:                  HITLOperationStatePendingApproval,
		ToState:                    HITLOperationStateExpired,
		ExpectedVersion:            oldTerminal.Version,
		Now:                        now.Add(-25 * time.Hour),
		ExpiredReason:              "approval_ttl_expired",
		TerminalRetentionExpiresAt: now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("transition old terminal: %v", err)
	}

	result, err := runHITLOperationStartupMaintenance(ctx, db)
	if err != nil {
		t.Fatalf("runHITLOperationStartupMaintenance: %v", err)
	}
	if result.SyncWaitingRecovered != 1 || result.PendingApprovalExpired != 1 || result.PurgedTerminal != 1 {
		t.Fatalf("runHITLOperationStartupMaintenance result = %#v, want recovery, expiry, and purge", result)
	}

	loadedSync, err := store.GetForPrincipal(ctx, staleSync.ID, staleSync.ProfileID, staleSync.PrincipalID)
	if err != nil {
		t.Fatalf("GetForPrincipal(stale sync): %v", err)
	}
	if loadedSync.State != HITLOperationStateClientDisconnected {
		t.Fatalf("stale sync state = %q, want client_disconnected", loadedSync.State)
	}
	loadedPending, err := store.GetForPrincipal(ctx, duePending.ID, duePending.ProfileID, duePending.PrincipalID)
	if err != nil {
		t.Fatalf("GetForPrincipal(due pending): %v", err)
	}
	if loadedPending.State != HITLOperationStateExpired {
		t.Fatalf("due pending state = %q, want expired", loadedPending.State)
	}
	_, err = store.GetForPrincipal(ctx, oldTerminal.ID, oldTerminal.ProfileID, oldTerminal.PrincipalID)
	if !errors.Is(err, ErrHITLOperationNotFound) {
		t.Fatalf("old terminal err = %v, want ErrHITLOperationNotFound", err)
	}
}

func TestHITLOperationStoreMaintenancePurgesTerminalOperations(t *testing.T) {
	db := openHITLOperationTestDB(t)
	store := NewHITLOperationStore(db)
	ctx := context.Background()
	now := time.Unix(1_700_000_500, 0).UTC()

	oldTerminal := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_old_terminal",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now.Add(-48 * time.Hour),
		SyncWaitDeadline:  now.Add(-48 * time.Hour),
		ApprovalExpiresAt: now.Add(-47 * time.Hour),
	})
	_, err := store.Transition(ctx, HITLOperationTransition{
		ID:                         oldTerminal.ID,
		FromState:                  HITLOperationStatePendingApproval,
		ToState:                    HITLOperationStateExpired,
		ExpectedVersion:            oldTerminal.Version,
		Now:                        now.Add(-25 * time.Hour),
		ExpiredReason:              "approval_ttl_expired",
		TerminalRetentionExpiresAt: now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("transition old terminal: %v", err)
	}

	keptTerminal := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_kept_terminal",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now.Add(-48 * time.Hour),
		SyncWaitDeadline:  now.Add(-48 * time.Hour),
		ApprovalExpiresAt: now.Add(-47 * time.Hour),
	})
	_, err = store.Transition(ctx, HITLOperationTransition{
		ID:                         keptTerminal.ID,
		FromState:                  HITLOperationStatePendingApproval,
		ToState:                    HITLOperationStateExpired,
		ExpectedVersion:            keptTerminal.Version,
		Now:                        now.Add(-time.Hour),
		ExpiredReason:              "approval_ttl_expired",
		TerminalRetentionExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("transition kept terminal: %v", err)
	}

	pending := createTestHITLOperation(t, store, HITLOperationCreate{
		ID:                "hitl_op_pending_not_purged",
		State:             HITLOperationStatePendingApproval,
		CreatedAt:         now.Add(-time.Minute),
		SyncWaitDeadline:  now.Add(-30 * time.Second),
		ApprovalExpiresAt: now.Add(time.Minute),
	})

	purged, err := store.PurgeTerminalOperations(ctx, now)
	if err != nil {
		t.Fatalf("PurgeTerminalOperations: %v", err)
	}
	if purged != 1 {
		t.Fatalf("PurgeTerminalOperations purged = %d, want 1", purged)
	}

	_, err = store.GetForPrincipal(ctx, oldTerminal.ID, oldTerminal.ProfileID, oldTerminal.PrincipalID)
	if !errors.Is(err, ErrHITLOperationNotFound) {
		t.Fatalf("old terminal err = %v, want ErrHITLOperationNotFound", err)
	}
	for _, op := range []HITLOperation{keptTerminal, pending} {
		if _, err := store.GetForPrincipal(ctx, op.ID, op.ProfileID, op.PrincipalID); err != nil {
			t.Fatalf("operation %s should remain: %v", op.ID, err)
		}
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
