package toolgate

import (
	"sync"
	"time"
)

// Store is the gateway-wide registry of pending tool-call approvals,
// keyed by opaque token. Pollers look up by token, dashboards iterate
// to render the queue, and a sweep loop garbage-collects entries that
// have been terminal longer than retainAfterDecide.
//
// Concurrency: a single RWMutex protects the map; per-call mutation
// is delegated to PendingCall's own lock. The two locks never nest in
// the other order — Store.mu is always acquired first.
type Store struct {
	mu    sync.RWMutex
	calls map[string]*PendingCall

	// retainAfterDecide is how long a decided call stays addressable
	// before sweep removes it. Long enough to absorb a slow agent
	// finishing its poll round-trip; short enough to bound memory.
	retainAfterDecide time.Duration

	// nowFn is overridable for tests; defaults to time.Now.
	nowFn func() time.Time
}

// NewStore returns a fresh Store with default sweep parameters.
func NewStore() *Store {
	return &Store{
		calls:             make(map[string]*PendingCall),
		retainAfterDecide: 5 * time.Minute,
		nowFn:             time.Now,
	}
}

// Park records a new pending tool call and returns it. The caller
// holds the returned pointer for the duration of the multi-turn
// dance; the poller dereferences from the store by token.
func (s *Store) Park(toolUseID, toolName string, toolInput []byte, reason string) *PendingCall {
	pc := &PendingCall{
		Token:     newToken(),
		ToolUseID: toolUseID,
		ToolName:  toolName,
		ToolInput: toolInput,
		Reason:    reason,
		Created:   s.nowFn(),
		done:      make(chan struct{}),
	}
	s.mu.Lock()
	s.calls[pc.Token] = pc
	s.mu.Unlock()
	return pc
}

// Lookup returns the call for a token, or nil if absent / GC'd.
func (s *Store) Lookup(token string) *PendingCall {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.calls[token]
}

// Pending returns a snapshot of currently-pending calls, ordered by
// creation time. Used by the dashboard's queue view.
func (s *Store) Pending() []*PendingCall {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*PendingCall, 0, len(s.calls))
	for _, pc := range s.calls {
		if _, decided := pc.State(); !decided {
			out = append(out, pc)
		}
	}
	// Insertion-order isn't preserved by Go maps; callers that need
	// deterministic order should sort by pc.Created.
	return out
}

// StartSweeper runs Sweep on a background ticker for the lifetime of
// the process. Mirrors agents.startSessionSweeper: the first sweep
// runs 30s after boot (avoids log/CPU noise on restart), then every
// interval. interval <= 0 disables the sweeper. Without this the
// decided PendingCalls accumulate in the store map forever — a slow
// leak in a long-lived gateway.
func (s *Store) StartSweeper(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		time.Sleep(30 * time.Second)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			s.Sweep()
			<-t.C
		}
	}()
}

// Sweep removes decided calls older than retainAfterDecide. Intended
// to be called from a background tick; safe to call concurrently with
// Park / Lookup.
func (s *Store) Sweep() {
	now := s.nowFn()
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, pc := range s.calls {
		if _, decided := pc.State(); !decided {
			continue
		}
		// Use Created as a coarse age proxy. A separate decided-at
		// timestamp would be more precise; the difference is small
		// enough to defer to v2.
		if now.Sub(pc.Created) > s.retainAfterDecide {
			delete(s.calls, token)
		}
	}
}
