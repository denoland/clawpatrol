package main

// HITL — human-in-the-loop request approval. Rules with `approve = [...]`
// pause the upstream call until an operator approves on the dashboard,
// Slack, or another notifier. Decisions arrive over a per-request
// channel; the active request only remains resumable while the original
// client connection/context is alive.
//
// HITLPending and HITLDecision live in config/runtime — declared
// there so approver plugins can produce them without importing main.
//
// HITLRegistry is the pool of pending approvals + per-pending decision
// channel. Approver runtimes (config/plugins/approvers) call Add to
// publish a pending entry and select on the returned channel.
// Dashboard's POST /api/hitl/decide calls DecideWithResult(id, decision)
// to resolve and receive operator-facing terminal-state details.
//
// Implements runtime.HITLPool via Add / Discard and preserves recent
// terminal states so stale Slack/dashboard prompts can explain whether
// a request was already decided, timed out, or lost its client.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const hitlTerminalTTL = 30 * time.Minute

type HITLRegistry struct {
	mu                    sync.Mutex
	pending               map[string]*pendingEntry
	terminal              map[string]terminalHITLEntry
	sink                  *Sink // SSE fan-out for the dashboard
	asyncGrantResolver    func(operationID string, d runtime.HITLDecision) runtime.HITLResolveResult
	pendingMessageUpdater func(ctx context.Context, pending runtime.HITLPending, ref string, result runtime.HITLResolveResult)
}

type pendingEntry struct {
	p           runtime.HITLPending
	decision    chan runtime.HITLDecision
	messageRefs []string
}

type terminalHITLEntry struct {
	result    runtime.HITLResolveResult
	pending   runtime.HITLPending
	refs      []string
	expiresAt time.Time
}

func newHITLRegistry(sink *Sink) *HITLRegistry {
	return &HITLRegistry{
		pending:  map[string]*pendingEntry{},
		terminal: map[string]terminalHITLEntry{},
		sink:     sink,
	}
}

// Add publishes a pending entry and returns its assigned id + a
// decision channel. Caller selects on the channel and calls Discard
// when ctx fires before the channel.
func (r *HITLRegistry) Add(p runtime.HITLPending) (string, <-chan runtime.HITLDecision) {
	p.ID = randomString(16)
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	if p.ExpiresAt.IsZero() {
		p.ExpiresAt = p.CreatedAt.Add(30 * time.Minute)
	}
	ch := make(chan runtime.HITLDecision, 1)
	r.mu.Lock()
	r.pruneTerminalLocked(time.Now())
	r.pending[p.ID] = &pendingEntry{p: p, decision: ch}
	delete(r.terminal, p.ID)
	r.mu.Unlock()
	if r.sink != nil {
		r.sink.Emit(Event{
			Mode: "hitl_pending", Host: p.Host, Method: p.Method,
			Path: p.Path, AgentIP: p.AgentIP, Reason: p.Reason, Action: "pending",
		})
	}
	return p.ID, ch
}

func (r *HITLRegistry) Discard(id string) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
}

func (r *HITLRegistry) Update(id string, mutate func(*runtime.HITLPending)) bool {
	if mutate == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.pending[id]
	if e == nil {
		return false
	}
	mutate(&e.p)
	runtime.NormalizeHITLPendingApproval(&e.p)
	return true
}

// List returns pending entries sorted by CreatedAt ascending (oldest
// first), tiebroken on ID. The dashboard polls this endpoint once per
// second; Go's randomized map iteration would otherwise shuffle rows
// on every render and make the table flicker. Sort key is invariant
// across the sync_waiting → pending_approval Update transition (same
// ID, same CreatedAt), so a row keeps its position when its approval
// mode changes.
func (r *HITLRegistry) List() []runtime.HITLPending {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneTerminalLocked(time.Now())
	out := make([]runtime.HITLPending, 0, len(r.pending))
	for _, e := range r.pending {
		out = append(out, e.p)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Decide fires the pending entry's channel. Returns false when the
// id is unknown (already discarded / never existed).
func (r *HITLRegistry) Decide(id string, d runtime.HITLDecision) bool {
	return r.DecideWithResult(id, d).OK
}

// DecideWithResult resolves a pending entry and records the terminal
// state. Duplicate/stale clicks get the stored state back with OK=false.
func (r *HITLRegistry) DecideWithResult(id string, d runtime.HITLDecision) runtime.HITLResolveResult {
	state := runtime.HITLStateDenied
	if d.Allow {
		state = runtime.HITLStateApproved
	}
	reason := strings.TrimSpace(d.Reason)
	if reason == "" {
		verb := string(state)
		if d.By != "" {
			reason = fmt.Sprintf("%s by %s", verb, d.By)
		} else {
			reason = verb
		}
	}
	now := time.Now()
	r.mu.Lock()
	r.pruneTerminalLocked(now)
	e := r.pending[id]
	if e == nil {
		if terminal, ok := r.terminal[id]; ok {
			r.mu.Unlock()
			return terminal.result
		}
		r.mu.Unlock()
		return runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: "unknown or expired HITL request"}
	}
	if e.p.OperationID != "" && e.p.OperationState == runtime.HITLOperationStatePendingApproval && e.p.ApprovalEffect == runtime.HITLApprovalEffectCreateRetryGrant {
		resolver := r.asyncGrantResolver
		if resolver == nil {
			r.mu.Unlock()
			return runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: "async HITL retry-grant resolver is unavailable"}
		}
		delete(r.pending, id)
		r.mu.Unlock()

		result := resolver(e.p.OperationID, d)
		r.mu.Lock()
		r.terminal[id] = terminalHITLEntry{result: staleHITLResolveResult(result), expiresAt: now.Add(hitlTerminalTTL)}
		r.mu.Unlock()
		return result
	}
	e.decision <- d
	delete(r.pending, id)
	r.terminal[id] = terminalHITLEntry{
		result:    runtime.HITLResolveResult{OK: false, State: state, Reason: reason},
		expiresAt: now.Add(hitlTerminalTTL),
	}
	r.mu.Unlock()
	return runtime.HITLResolveResult{OK: true, State: state, Reason: reason}
}

func staleHITLResolveResult(result runtime.HITLResolveResult) runtime.HITLResolveResult {
	result.OK = false
	return result
}

// Cancel resolves a pending entry without delivering a human decision.
// It is used when the original synchronous request times out or the
// client connection disappears before approval.
func (r *HITLRegistry) Cancel(id string, state runtime.HITLState, reason string) runtime.HITLResolveResult {
	if state == "" || state == runtime.HITLStatePending || state == runtime.HITLStateUnknown {
		state = runtime.HITLStateCanceled
	}
	if strings.TrimSpace(reason) == "" {
		reason = string(state)
	}
	e, result := r.resolve(id, state, reason)
	if e != nil && result.OK {
		r.updateRecordedMessageRefs(context.Background(), e.p, e.messageRefs, result)
	}
	return result
}

func (r *HITLRegistry) resolve(id string, state runtime.HITLState, reason string) (*pendingEntry, runtime.HITLResolveResult) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneTerminalLocked(now)
	e := r.pending[id]
	if e == nil {
		if terminal, ok := r.terminal[id]; ok {
			return nil, terminal.result
		}
		return nil, runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: "unknown or expired HITL request"}
	}
	delete(r.pending, id)
	terminal := runtime.HITLResolveResult{OK: false, State: state, Reason: reason}
	r.terminal[id] = terminalHITLEntry{result: terminal, pending: e.p, refs: append([]string(nil), e.messageRefs...), expiresAt: now.Add(hitlTerminalTTL)}
	return e, runtime.HITLResolveResult{OK: true, State: state, Reason: reason}
}

// RecordMessageRef records the channel-specific message id for a pending sync
// HITL prompt so terminal states (timeout/client disconnect) can proactively
// update the original Slack message. If the request already reached a terminal
// state before the notifier returned, use a fresh context to update immediately:
// the caller's request context is often canceled by then.
func (r *HITLRegistry) RecordMessageRef(_ context.Context, pendingID, ref string) error {
	if strings.TrimSpace(pendingID) == "" || strings.TrimSpace(ref) == "" {
		return nil
	}
	var pending runtime.HITLPending
	var result runtime.HITLResolveResult
	var shouldUpdate bool
	now := time.Now()
	r.mu.Lock()
	r.pruneTerminalLocked(now)
	if e := r.pending[pendingID]; e != nil {
		e.messageRefs = append(e.messageRefs, ref)
		r.mu.Unlock()
		return nil
	}
	if terminal, ok := r.terminal[pendingID]; ok {
		terminal.refs = append(terminal.refs, ref)
		r.terminal[pendingID] = terminal
		pending = terminal.pending
		result = terminal.result
		shouldUpdate = true
	}
	r.mu.Unlock()
	if shouldUpdate {
		r.updateRecordedMessageRefs(context.Background(), pending, []string{ref}, result)
	}
	return nil
}

func (r *HITLRegistry) updateRecordedMessageRefs(ctx context.Context, pending runtime.HITLPending, refs []string, result runtime.HITLResolveResult) {
	if r == nil || r.pendingMessageUpdater == nil {
		return
	}
	for _, ref := range refs {
		if strings.TrimSpace(ref) == "" {
			continue
		}
		r.pendingMessageUpdater(ctx, pending, ref, result)
	}
}

func (r *HITLRegistry) pruneTerminalLocked(now time.Time) {
	for id, entry := range r.terminal {
		if !entry.expiresAt.After(now) {
			delete(r.terminal, id)
		}
	}
}
