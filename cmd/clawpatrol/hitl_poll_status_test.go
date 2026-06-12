package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
)

// TestHITLOperationStatusBodyPendingPollsAgain pins the poll-status
// contract an agent relies on: a still-pending operation is non-terminal
// and tells the agent to wait and poll again — never "expired" — while a
// genuinely expired operation is terminal. The vocabulary must let an agent
// distinguish "keep waiting" from "stop" without guessing.
func TestHITLOperationStatusBodyPendingPollsAgain(t *testing.T) {
	const statusURL = "https://gateway.example.test/api/hitl/operations/op/status?token=t"

	t.Run("pending_approval polls again, not expired", func(t *testing.T) {
		op := HITLOperation{
			ID:                "op_pending",
			State:             HITLOperationStatePendingApproval,
			ApprovalExpiresAt: time.Unix(1_700_000_900, 0).UTC(),
		}
		body := hitlOperationStatusBody(op, statusURL, false)

		if body["state"] != string(HITLOperationStatePendingApproval) {
			t.Fatalf("state = %v, want pending_approval", body["state"])
		}
		if body["terminal"] != false {
			t.Fatalf("terminal = %v, want false for a pending op", body["terminal"])
		}
		if body["poll_again"] != true {
			t.Fatalf("poll_again = %v, want true", body["poll_again"])
		}
		if body["retry_after_seconds"] != hitlDefaultRetryAfterSeconds {
			t.Fatalf("retry_after_seconds = %v, want %d", body["retry_after_seconds"], hitlDefaultRetryAfterSeconds)
		}
		if body["retry_original_request"] != true {
			t.Fatalf("retry_original_request = %v, want true", body["retry_original_request"])
		}
		if _, ok := body["expired_reason"]; ok {
			t.Fatalf("pending op must not carry expired_reason: %#v", body)
		}
		msg, _ := body["message"].(string)
		if !strings.Contains(strings.ToLower(msg), "poll") || !strings.Contains(strings.ToLower(msg), "wait") {
			t.Fatalf("pending message should tell the agent to wait and poll: %q", msg)
		}
	})

	t.Run("sync_waiting polls again, not expired", func(t *testing.T) {
		op := HITLOperation{ID: "op_sync", State: HITLOperationStateSyncWaiting}
		body := hitlOperationStatusBody(op, statusURL, false)
		if body["terminal"] != false {
			t.Fatalf("terminal = %v, want false for sync_waiting", body["terminal"])
		}
		if body["poll_again"] != true || body["retry_after_seconds"] != hitlDefaultRetryAfterSeconds {
			t.Fatalf("sync_waiting must instruct poll-again with an interval: %#v", body)
		}
		if body["state"] == string(HITLOperationStateExpired) {
			t.Fatal("sync_waiting must never report state expired")
		}
	})

	t.Run("expired is terminal", func(t *testing.T) {
		op := HITLOperation{
			ID:            "op_expired",
			State:         HITLOperationStateExpired,
			ExpiredReason: "approval_ttl_expired",
		}
		body := hitlOperationStatusBody(op, statusURL, false)
		if body["state"] != string(HITLOperationStateExpired) {
			t.Fatalf("state = %v, want expired", body["state"])
		}
		if body["terminal"] != true {
			t.Fatalf("terminal = %v, want true for an expired op", body["terminal"])
		}
		if _, ok := body["poll_again"]; ok {
			t.Fatalf("expired op must not invite further polling: %#v", body)
		}
		if body["expired_reason"] != "approval_ttl_expired" {
			t.Fatalf("expired_reason = %v, want approval_ttl_expired", body["expired_reason"])
		}
	})

	t.Run("denied is terminal", func(t *testing.T) {
		body := hitlOperationStatusBody(HITLOperation{ID: "op_denied", State: HITLOperationStateDenied}, statusURL, false)
		if body["terminal"] != true {
			t.Fatalf("denied terminal = %v, want true", body["terminal"])
		}
		if _, ok := body["poll_again"]; ok {
			t.Fatalf("denied op must not invite polling: %#v", body)
		}
	})

	t.Run("approved waits for retry, not expired", func(t *testing.T) {
		body := hitlOperationStatusBody(HITLOperation{ID: "op_ok", State: HITLOperationStateApprovedWaitingForRetry}, statusURL, false)
		if body["terminal"] != false {
			t.Fatalf("approved terminal = %v, want false", body["terminal"])
		}
		if body["retry_header_name"] != hitlRetryOperationHeader || body["retry_header_value"] != "op_ok" {
			t.Fatalf("approved op must carry retry headers: %#v", body)
		}
	})
}

// TestHITLAsyncApprovalWindowExcludesSyncWait guards the root cause behind
// "a still-pending operation polls back as expired": the approval window
// must open when the synchronous hold ends, not at creation. With the old
// arithmetic (created_at + approval_ttl) a sync_wait_timeout that rivals the
// approval_ttl left a freshly-parked operation already past its deadline, so
// the first poll after the 202 hand-back returned expired. The window must
// outlive the synchronous hold and grant the full approval_ttl for polling.
func TestHITLAsyncApprovalWindowExcludesSyncWait(t *testing.T) {
	// sync_wait_timeout rivals approval_ttl — the regime where folding the
	// hold into the window would expire a just-parked operation.
	h := newHITLAsyncE2EHarness(t, hitlAsyncE2EOptions{syncWaitTimeout: "10m", approvalTTL: "10m"})

	cr := findApproveRule(t, h.endpoint)
	approverID, approver, ok := h.gateway.asyncHumanApproverFor(cr.Outcome.Approve)
	if !ok {
		t.Fatal("expected an async human approver on the gated rule")
	}

	const body = `{"resource":"r1"}`
	req, err := http.NewRequest(http.MethodPost, "https://"+hitlRetryRelayTestHost+hitlRetryRelayTestPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = hitlRetryRelayTestHost
	req.URL = &url.URL{Scheme: "https", Host: hitlRetryRelayTestHost, Path: hitlRetryRelayTestPath}

	now := time.Unix(1_700_000_000, 0).UTC()
	start, started, err := h.gateway.maybeStartAsyncHITLOperation(context.Background(), hitlAsyncOperationInput{
		ProfileID:   "default",
		PrincipalID: hitlPeerPrincipalID("test"),
		Endpoint:    h.endpoint,
		Rule:        cr,
		ApproverID:  approverID,
		Approver:    approver,
		MatchReq: &match.Request{
			Family:  h.endpoint.Family,
			Method:  req.Method,
			URL:     req.URL,
			Headers: req.Header,
			Body:    []byte(body),
		},
		HTTPRequest: req,
		RawBody:     []byte(body),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("maybeStartAsyncHITLOperation: %v", err)
	}
	if !started {
		t.Fatal("expected an async operation to start for the gated POST")
	}
	op := start.Operation

	// The approval window must open after the hold and run the full TTL
	// past it — never inside or before the synchronous wait.
	if !op.ApprovalExpiresAt.After(op.SyncWaitDeadline) {
		t.Fatalf("approval_expires_at %v must be after sync_wait_deadline %v: the poll window is being eaten by the synchronous hold",
			op.ApprovalExpiresAt, op.SyncWaitDeadline)
	}
	wantApproval := op.SyncWaitDeadline.Add(10 * time.Minute)
	if !op.ApprovalExpiresAt.Equal(wantApproval) {
		t.Fatalf("approval_expires_at = %v, want sync_wait_deadline + approval_ttl = %v", op.ApprovalExpiresAt, wantApproval)
	}

	// Once the operation is pending and being polled, the gateway must not
	// expire it on a sweep run at the moment it becomes pollable.
	pollMoment := op.SyncWaitDeadline
	maint, err := h.store.ExpireDueOperations(context.Background(), pollMoment, time.Minute)
	if err != nil {
		t.Fatalf("ExpireDueOperations: %v", err)
	}
	if maint.PendingApprovalExpired != 0 {
		t.Fatalf("a just-pollable operation was expired by the sweep (%d) — expired must be reserved for a genuinely dead window", maint.PendingApprovalExpired)
	}
}

// findApproveRule returns the endpoint's single gated rule (one whose
// outcome routes through an approve chain).
func findApproveRule(t *testing.T, ep *config.CompiledEndpoint) *config.CompiledRule {
	t.Helper()
	for _, r := range ep.Rules {
		if r != nil && !r.Disabled && len(r.Outcome.Approve) > 0 {
			return r
		}
	}
	t.Fatal("no gated (approve-chain) rule on endpoint")
	return nil
}
