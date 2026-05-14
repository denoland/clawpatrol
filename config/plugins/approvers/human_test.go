package approvers

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type captureHITLPool struct {
	added    chan struct{}
	id       string
	decision chan runtime.HITLDecision

	mu      sync.Mutex
	pending runtime.HITLPending
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

func (p *captureHITLPool) Discard(string) {}

func (p *captureHITLPool) Decide(string, runtime.HITLDecision) bool { return false }

func (p *captureHITLPool) capturedPending() runtime.HITLPending {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pending
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
