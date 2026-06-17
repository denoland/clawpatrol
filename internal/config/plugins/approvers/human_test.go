package approvers

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type captureHITLPool struct {
	added    chan struct{}
	id       string
	decision chan runtime.HITLDecision

	mu           sync.Mutex
	pending      runtime.HITLPending
	updated      runtime.HITLPending
	cancelResult runtime.HITLResolveResult
	discarded    bool
}

func newCaptureHITLPool() *captureHITLPool {
	return &captureHITLPool{
		added:    make(chan struct{}),
		id:       "pending-1",
		decision: make(chan runtime.HITLDecision, 1),
	}
}

func (p *captureHITLPool) Add(pending runtime.HITLPending) (string, <-chan runtime.HITLDecision) {
	p.mu.Lock()
	p.pending = pending
	p.mu.Unlock()
	close(p.added)
	return p.id, p.decision
}

func (p *captureHITLPool) Discard(string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.discarded = true
}

func (p *captureHITLPool) Update(id string, mutate func(*runtime.HITLPending)) bool {
	if id != p.id {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	mutate(&p.pending)
	p.updated = p.pending
	return true
}

func (p *captureHITLPool) Decide(string, runtime.HITLDecision) bool { return false }

func (p *captureHITLPool) Cancel(_ string, state runtime.HITLState, reason string) runtime.HITLResolveResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancelResult = runtime.HITLResolveResult{OK: true, State: state, Reason: reason}
	return p.cancelResult
}

func (p *captureHITLPool) capturedPending() runtime.HITLPending {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pending
}

func (p *captureHITLPool) capturedCancel() runtime.HITLResolveResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cancelResult
}

func (p *captureHITLPool) capturedUpdate() runtime.HITLPending {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.updated
}

func (p *captureHITLPool) wasDiscarded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discarded
}

type captureNotifier struct {
	notified chan runtime.HITLTarget
}

func (n *captureNotifier) NotifyHITL(_ context.Context, _ runtime.ApproveRequest, target runtime.HITLTarget) error {
	n.notified <- target
	return nil
}

func TestHumanApproverAsyncSyncWaitTimeoutLeavesPromptPendingForRetryGrant(t *testing.T) {
	pool := newCaptureHITLPool()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	verdict, err := (&HumanApprover{Timeout: 60}).Approve(ctx, runtime.ApproveRequest{
		Pool:                      pool,
		ApproverName:              "ops",
		Method:                    "POST",
		Host:                      "api.example.test",
		Path:                      "/v1/write",
		AsyncOperationID:          "op_123",
		AsyncPendingOnSyncTimeout: true,
	})
	if err != nil {
		t.Fatalf("Approve error = %v, want nil async pending verdict", err)
	}
	if verdict.Decision != runtime.ApproveDecisionAsyncPending {
		t.Fatalf("Decision = %q, want %q", verdict.Decision, runtime.ApproveDecisionAsyncPending)
	}
	if pool.wasDiscarded() {
		t.Fatal("pending prompt was discarded on sync wait timeout; want it left for human approval")
	}
	updated := pool.capturedUpdate()
	if updated.OperationID != "op_123" {
		t.Fatalf("updated OperationID = %q, want op_123", updated.OperationID)
	}
	if updated.OperationState != runtime.HITLOperationStatePendingApproval {
		t.Fatalf("updated OperationState = %q, want pending_approval", updated.OperationState)
	}
	if updated.ApprovalEffect != runtime.HITLApprovalEffectCreateRetryGrant {
		t.Fatalf("updated ApprovalEffect = %q, want create_retry_grant", updated.ApprovalEffect)
	}
	if !strings.Contains(updated.ApprovalMessage, "allow the client to retry") {
		t.Fatalf("updated ApprovalMessage = %q, want retry-grant guidance", updated.ApprovalMessage)
	}
}

func TestHumanApproverPendingExpirationUsesApproverTimeout(t *testing.T) {
	pending := captureHumanPending(t, &HumanApprover{Timeout: 17}, &config.CompiledPolicy{HumanTimeout: 600})
	assertPendingLifetime(t, pending, 17*time.Second)
}

func TestHumanApproverPendingExpirationUsesPolicyTimeoutFallback(t *testing.T) {
	pending := captureHumanPending(t, &HumanApprover{}, &config.CompiledPolicy{HumanTimeout: 23})
	assertPendingLifetime(t, pending, 23*time.Second)
}

func TestHumanApproverPendingExpirationUsesDefaultTimeoutFallback(t *testing.T) {
	pending := captureHumanPending(t, &HumanApprover{}, nil)
	assertPendingLifetime(t, pending, 10*time.Minute)
}

func TestHumanApproverAsyncApprovalTTLDerivedFromApproverTimeout(t *testing.T) {
	h := &HumanApprover{Timeout: 600, SyncWaitTimeout: "90s"}
	if got := h.HITLAsyncApprovalTTL(nil); got != 10*time.Minute-90*time.Second {
		t.Fatalf("approval ttl = %v, want %v", got, 10*time.Minute-90*time.Second)
	}
}

func TestHumanApproverAsyncApprovalTTLUsesPolicyTimeoutFallback(t *testing.T) {
	h := &HumanApprover{SyncWaitTimeout: "30s"}
	if got := h.HITLAsyncApprovalTTL(&config.CompiledPolicy{HumanTimeout: 600}); got != 10*time.Minute-30*time.Second {
		t.Fatalf("approval ttl = %v, want %v", got, 10*time.Minute-30*time.Second)
	}
}

func TestHumanApproverAsyncApprovalTTLClampsToZeroWhenSyncWaitExceedsTimeout(t *testing.T) {
	// sync_wait_timeout >= approver timeout leaves no budget for the
	// async grant: clamp to zero rather than a negative lifetime.
	h := &HumanApprover{Timeout: 60, SyncWaitTimeout: "90s"}
	if got := h.HITLAsyncApprovalTTL(nil); got != 0 {
		t.Fatalf("approval ttl = %v, want 0", got)
	}
}

func TestHumanApproverPendingIncludesSyncApprovalGuidance(t *testing.T) {
	pending := captureHumanPending(t, &HumanApprover{Timeout: 17}, &config.CompiledPolicy{HumanTimeout: 600})
	if pending.OperationState != runtime.HITLOperationStateSyncWaiting {
		t.Fatalf("OperationState = %q, want %q", pending.OperationState, runtime.HITLOperationStateSyncWaiting)
	}
	if pending.ApprovalEffect != runtime.HITLApprovalEffectExecuteUpstream {
		t.Fatalf("ApprovalEffect = %q, want %q", pending.ApprovalEffect, runtime.HITLApprovalEffectExecuteUpstream)
	}
	if pending.UpstreamCalled {
		t.Fatal("UpstreamCalled = true, want false before approval")
	}
	if !strings.Contains(pending.ApprovalMessage, "send this request upstream immediately") {
		t.Fatalf("ApprovalMessage = %q, want immediate upstream guidance", pending.ApprovalMessage)
	}
}

func TestHumanApproverForwardsPendingMessageUpdateSinkToNotifier(t *testing.T) {
	pool := newCaptureHITLPool()
	notifier := &captureNotifier{notified: make(chan runtime.HITLTarget, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	sink := runtime.HITLPendingMessageUpdateSink(func(context.Context, string, string) error { return nil })
	go func() {
		_, err := (&HumanApprover{Credential: "slack", Channel: "C123", Timeout: 60}).Approve(ctx, runtime.ApproveRequest{
			Pool:                     pool,
			Policy:                   &config.CompiledPolicy{Credentials: map[string]*config.Entity{"slack": {Body: notifier}}},
			ApproverName:             "ops",
			Method:                   "POST",
			Host:                     "api.example.test",
			Path:                     "/v1/write",
			PendingMessageUpdateSink: sink,
		})
		done <- err
	}()

	select {
	case target := <-notifier.notified:
		if target.PendingID != pool.id {
			t.Fatalf("target PendingID = %q, want %q", target.PendingID, pool.id)
		}
		if target.PendingMessageUpdateSink == nil {
			t.Fatal("target PendingMessageUpdateSink is nil; sync HITL Slack prompts cannot record message refs")
		}
	case <-time.After(time.Second):
		t.Fatal("human approver did not notify credential")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Approve error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("human approver did not return after context cancellation")
	}
}

func TestHumanApproverTimeoutRecordsTimedOutTerminalState(t *testing.T) {
	pool := newCaptureHITLPool()
	done := make(chan struct {
		verdict runtime.ApproveVerdict
		err     error
	}, 1)
	go func() {
		verdict, err := (&HumanApprover{Timeout: 1}).Approve(context.Background(), runtime.ApproveRequest{
			Pool:         pool,
			ApproverName: "ops",
			Method:       "POST",
			Host:         "api.example.test",
			Path:         "/v1/write",
		})
		done <- struct {
			verdict runtime.ApproveVerdict
			err     error
		}{verdict: verdict, err: err}
	}()

	select {
	case <-pool.added:
	case <-time.After(time.Second):
		t.Fatal("human approver did not publish pending entry")
	}

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Approve error = %v, want nil", got.err)
		}
		if got.verdict.Decision != "" {
			t.Fatalf("verdict Decision = %q, want deny/empty timeout verdict", got.verdict.Decision)
		}
		if got.verdict.Reason == "" {
			t.Fatal("timeout verdict Reason is empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("human approver did not time out")
	}

	cancelResult := pool.capturedCancel()
	if cancelResult.State != runtime.HITLStateTimedOut {
		t.Fatalf("Cancel state = %q, want %q", cancelResult.State, runtime.HITLStateTimedOut)
	}
}

func TestTerminalDecisionVerdictUsesQueuedDecisionWhenCancelLosesRace(t *testing.T) {
	ch := make(chan runtime.HITLDecision, 1)
	ch <- runtime.HITLDecision{Allow: true, By: "operator", Reason: "approved in dashboard"}

	verdict, ok := terminalDecisionVerdict(runtime.HITLResolveResult{
		OK:     false,
		State:  runtime.HITLStateApproved,
		Reason: "approved by operator",
	}, ch)
	if !ok {
		t.Fatal("terminalDecisionVerdict ok = false, want true for approved terminal state")
	}
	if verdict.Decision != "allow" {
		t.Fatalf("Decision = %q, want allow", verdict.Decision)
	}
	if verdict.By != "operator" {
		t.Fatalf("By = %q, want operator", verdict.By)
	}
	if verdict.Reason != "approved in dashboard" {
		t.Fatalf("Reason = %q, want queued decision reason", verdict.Reason)
	}
}

func TestHumanApproverContextCancelRecordsClientDisconnected(t *testing.T) {
	pool := newCaptureHITLPool()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (&HumanApprover{Timeout: 60}).Approve(ctx, runtime.ApproveRequest{
			Pool:         pool,
			ApproverName: "ops",
			Method:       "POST",
			Host:         "api.example.test",
			Path:         "/v1/write",
		})
		done <- err
	}()

	select {
	case <-pool.added:
	case <-time.After(time.Second):
		t.Fatal("human approver did not publish pending entry")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Approve error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("human approver did not return after context cancellation")
	}
	cancelResult := pool.capturedCancel()
	if cancelResult.State != runtime.HITLStateClientDisconnected {
		t.Fatalf("Cancel state = %q, want %q", cancelResult.State, runtime.HITLStateClientDisconnected)
	}
	if cancelResult.Reason == "" {
		t.Fatal("Cancel reason is empty")
	}
}

func captureHumanPending(t *testing.T, approver *HumanApprover, policy *config.CompiledPolicy) runtime.HITLPending {
	t.Helper()
	pool := newCaptureHITLPool()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := approver.Approve(ctx, runtime.ApproveRequest{
			Pool:         pool,
			Policy:       policy,
			ApproverName: "ops",
			AgentIP:      "100.64.0.10",
			Method:       "POST",
			Host:         "api.example.test",
			Path:         "/v1/write",
			Reason:       "requires human approval",
		})
		done <- err
	}()

	select {
	case <-pool.added:
	case <-time.After(time.Second):
		t.Fatal("human approver did not publish pending entry")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Approve error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("human approver did not return after context cancellation")
	}
	return pool.capturedPending()
}

func assertPendingLifetime(t *testing.T, pending runtime.HITLPending, want time.Duration) {
	t.Helper()
	if pending.CreatedAt.IsZero() {
		t.Fatal("pending CreatedAt is zero")
	}
	if pending.ExpiresAt.IsZero() {
		t.Fatal("pending ExpiresAt is zero")
	}
	if got := pending.ExpiresAt.Sub(pending.CreatedAt); got != want {
		t.Fatalf("pending lifetime = %s, want %s", got, want)
	}
}
