package main

import (
	"context"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

type fakeHumanCredentialApprover struct{ credential string }

func (a fakeHumanCredentialApprover) HumanApproverCredential() string { return a.credential }

type captureHITLMessageUpdater struct{ updates []runtime.HITLMessageUpdate }

func (c *captureHITLMessageUpdater) UpdateHITLMessage(_ context.Context, _ runtime.SecretStore, update runtime.HITLMessageUpdate) error {
	c.updates = append(c.updates, update)
	return nil
}

func newPendingMessageUpdateGateway(t *testing.T) (*Gateway, *captureHITLMessageUpdater) {
	t.Helper()
	updater := &captureHITLMessageUpdater{}
	g := &Gateway{hitl: newHITLRegistry(nil)}
	g.cfg.Store(&config.Gateway{})
	g.policy.Store(&config.CompiledPolicy{
		Approvers:   map[string]*config.Entity{"ops": {Body: fakeHumanCredentialApprover{credential: "slack-approvals"}}},
		Credentials: map[string]*config.Entity{"slack-approvals": {Body: updater}},
	})
	return g, updater
}

func syncPGPending() runtime.HITLPending {
	p := runtime.HITLPending{
		ID:        "pending-1",
		Host:      "10.0.0.5:5432",
		Method:    "NOTIFY",
		Path:      "NOTIFY reload, 'now'",
		Endpoint:  "pg-prod",
		Family:    "sql",
		Approvers: []string{"ops"},
		CreatedAt: time.Now(),
	}
	runtime.NormalizeHITLPendingApproval(&p)
	return p
}

// A dashboard approval of a still-connected client executes upstream
// immediately, so the channel update must say approved-by, not the
// async "waiting for matching client retry" wording (#843).
func TestUpdatePendingHITLMessageSyncApprovalSaysApprovedBy(t *testing.T) {
	g, updater := newPendingMessageUpdateGateway(t)
	pending := syncPGPending()
	if pending.ApprovalEffect != runtime.HITLApprovalEffectExecuteUpstream {
		t.Fatalf("normalized sync pending effect = %q, want execute_upstream", pending.ApprovalEffect)
	}

	g.updatePendingHITLMessage(context.Background(), pending, `{"type":"slack"}`, runtime.HITLResolveResult{OK: true, State: runtime.HITLStateApproved, Reason: "approved by dashboard:alice"}, "dashboard:alice")

	if len(updater.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(updater.updates))
	}
	got := updater.updates[0]
	if got.State != runtime.HITLOperationStateApproved {
		t.Fatalf("update state = %q, want %q", got.State, runtime.HITLOperationStateApproved)
	}
	if got.DecidedBy != "dashboard:alice" {
		t.Fatalf("update DecidedBy = %q, want dashboard:alice", got.DecidedBy)
	}
	if got.Method != "NOTIFY" || got.Host != "10.0.0.5:5432" || got.Path != "NOTIFY reload, 'now'" {
		t.Fatalf("update request fields = %#v, want the pending request's", got)
	}
}

func TestUpdatePendingHITLMessageSyncDenialSaysDeniedBy(t *testing.T) {
	g, updater := newPendingMessageUpdateGateway(t)

	g.updatePendingHITLMessage(context.Background(), syncPGPending(), `{"type":"slack"}`, runtime.HITLResolveResult{OK: true, State: runtime.HITLStateDenied, Reason: "denied by dashboard:alice"}, "dashboard:alice")

	if len(updater.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(updater.updates))
	}
	got := updater.updates[0]
	if got.State != runtime.HITLOperationStateDenied || got.DecidedBy != "dashboard:alice" {
		t.Fatalf("update = %#v, want denied by dashboard:alice", got)
	}
}

// The retry-grant flavour keeps its wording: approving there does not
// send anything upstream.
func TestUpdatePendingHITLMessageRetryGrantApprovalKeepsWaitingForRetry(t *testing.T) {
	g, updater := newPendingMessageUpdateGateway(t)
	pending := syncPGPending()
	pending.OperationID = "op-1"
	pending.OperationState = runtime.HITLOperationStatePendingApproval
	pending.ApprovalEffect = runtime.HITLApprovalEffectCreateRetryGrant

	g.updatePendingHITLMessage(context.Background(), pending, `{"type":"slack"}`, runtime.HITLResolveResult{OK: true, State: runtime.HITLStateApproved}, "dashboard:alice")

	if len(updater.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(updater.updates))
	}
	if got := updater.updates[0].State; got != runtime.HITLOperationStateApprovedWaitingForRetry {
		t.Fatalf("update state = %q, want %q", got, runtime.HITLOperationStateApprovedWaitingForRetry)
	}
}

func TestUpdatePendingHITLMessageTimeoutHasNoDecider(t *testing.T) {
	g, updater := newPendingMessageUpdateGateway(t)

	g.updatePendingHITLMessage(context.Background(), syncPGPending(), `{"type":"slack"}`, runtime.HITLResolveResult{OK: true, State: runtime.HITLStateTimedOut, Reason: "approver timed out"}, "")

	if len(updater.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(updater.updates))
	}
	got := updater.updates[0]
	if got.State != runtime.HITLOperationStateExpired || got.DecidedBy != "" {
		t.Fatalf("update = %#v, want expired with no decider", got)
	}
}

func TestHITLRegistryDecideWithResultForwardsDeciderToMessageUpdater(t *testing.T) {
	registry := newHITLRegistry(nil)
	var gotResult runtime.HITLResolveResult
	var gotBy string
	updated := make(chan struct{}, 1)
	registry.pendingMessageUpdater = func(_ context.Context, _ runtime.HITLPending, _ string, result runtime.HITLResolveResult, decidedBy string) {
		gotResult = result
		gotBy = decidedBy
		updated <- struct{}{}
	}
	id, ch := registry.Add(syncPGPending())
	if err := registry.RecordMessageRef(context.Background(), id, `{"type":"slack","channel":"C123","ts":"1778764174.925659"}`); err != nil {
		t.Fatalf("RecordMessageRef returned error: %v", err)
	}
	go func() { <-ch }()

	result := registry.DecideWithResult(id, runtime.HITLDecision{Allow: true, By: "dashboard:alice"})
	if !result.OK || result.State != runtime.HITLStateApproved {
		t.Fatalf("DecideWithResult = %#v, want approved", result)
	}
	select {
	case <-updated:
	case <-time.After(time.Second):
		t.Fatal("decision did not update recorded message ref")
	}
	if gotResult.State != runtime.HITLStateApproved || gotBy != "dashboard:alice" {
		t.Fatalf("updater got result=%#v by=%q, want approved by dashboard:alice", gotResult, gotBy)
	}
}

// The notifier can still be posting when the operator decides. The
// late RecordMessageRef must then edit the message with the decision
// and its decider, not silently skip it.
func TestHITLRegistryLateMessageRefAfterDecisionCarriesDecider(t *testing.T) {
	registry := newHITLRegistry(nil)
	var gotPending runtime.HITLPending
	var gotResult runtime.HITLResolveResult
	var gotBy string
	updated := make(chan struct{}, 1)
	registry.pendingMessageUpdater = func(_ context.Context, pending runtime.HITLPending, _ string, result runtime.HITLResolveResult, decidedBy string) {
		gotPending = pending
		gotResult = result
		gotBy = decidedBy
		updated <- struct{}{}
	}
	id, ch := registry.Add(syncPGPending())
	go func() { <-ch }()
	if result := registry.DecideWithResult(id, runtime.HITLDecision{Allow: false, By: "dashboard:alice"}); !result.OK {
		t.Fatalf("DecideWithResult = %#v, want OK", result)
	}

	if err := registry.RecordMessageRef(context.Background(), id, `{"type":"slack","channel":"C123","ts":"1778764174.925659"}`); err != nil {
		t.Fatalf("RecordMessageRef returned error: %v", err)
	}
	select {
	case <-updated:
	case <-time.After(time.Second):
		t.Fatal("late RecordMessageRef did not update the message")
	}
	if gotPending.ID != id || gotPending.Endpoint != "pg-prod" || len(gotPending.Approvers) != 1 {
		t.Fatalf("late update pending = %#v, want the decided entry", gotPending)
	}
	if gotResult.State != runtime.HITLStateDenied || gotBy != "dashboard:alice" {
		t.Fatalf("late update result=%#v by=%q, want denied by dashboard:alice", gotResult, gotBy)
	}
}
