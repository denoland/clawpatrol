package config

// Token pools — operator-declared groups of same-(kind,type) credentials
// that share traffic for a single endpoint. Endpoints reference a pool
// the same way they reference a credential; at request time, the
// dispatcher asks the pool which underlying member should service the
// call. The pool's strategy decides:
//
//   round_robin   — atomic counter, even distribution
//   least_loaded  — fewest in-window requests wins
//
// Use case: an operator with N personal Claude OAuth subscriptions
// (each capped at a per-month quota) declares them as a pool so agent
// traffic spreads across all N rather than hammering one. Pooling is
// strictly intra-operator — there is no marketplace, no cross-operator
// transfer, no money handling.

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/denoland/clawpatrol/config/match"
)

// PoolStrategy identifies how a pool selects a member per request.
type PoolStrategy string

// Recognized pool dispatch strategies.
const (
	PoolStrategyRoundRobin  PoolStrategy = "round_robin"
	PoolStrategyLeastLoaded PoolStrategy = "least_loaded"
)

// DefaultPoolStrategy is the strategy applied when an operator omits
// the `strategy = ...` attribute.
const DefaultPoolStrategy = PoolStrategyRoundRobin

// CompiledTokenPool is the runtime-friendly view of a token_pool block.
// Members are the resolved credential Entity records (in declaration
// order); strategy decides which member services a given request.
//
// State is per-process and reference-stable across the pool's
// lifetime — the round-robin counter and per-member request counts
// accumulate across requests. State does not persist across gateway
// restarts; that is intentional v1 scope (the bead leaves persisted
// quota tracking to v2).
type CompiledTokenPool struct {
	Name     string
	Strategy PoolStrategy
	Members  []*Entity

	// PluginType is the (Kind, Type) string shared by every member,
	// captured for diagnostics and dashboard display. The compile
	// pass enforces same-type membership; this field documents which
	// type was chosen.
	PluginType string

	rr      atomic.Uint64
	mu      sync.Mutex
	counts  []uint64    // index-aligned with Members
	lastUse []time.Time // index-aligned with Members
}

// initState lazily allocates the per-member bookkeeping slices when
// they are first needed. Compile constructs the pool with empty state
// so the zero value is usable.
func (p *CompiledTokenPool) initState() {
	if p.counts == nil {
		p.counts = make([]uint64, len(p.Members))
		p.lastUse = make([]time.Time, len(p.Members))
	}
}

// Pick returns the credential entity that should service req per the
// pool's strategy, and increments the chosen member's request count
// so subsequent least_loaded picks have current data.
//
// Returns nil only when the pool has zero members — a state the
// compile pass already rejects, so callers in practice always get a
// non-nil entity back.
//
// The req argument is currently unused — strategies are stateless
// across requests and pick by global pool state — but kept on the
// signature so future strategies (e.g. session-affinity) can route
// based on the agent's identity without breaking callers.
func (p *CompiledTokenPool) Pick(req *match.Request) *Entity {
	if p == nil || len(p.Members) == 0 {
		return nil
	}
	idx := p.pick()
	p.mu.Lock()
	p.initState()
	p.counts[idx]++
	p.lastUse[idx] = time.Now()
	p.mu.Unlock()
	return p.Members[idx]
}

func (p *CompiledTokenPool) pick() int {
	switch p.Strategy {
	case PoolStrategyLeastLoaded:
		return p.pickLeastLoaded()
	default:
		return p.pickRoundRobin()
	}
}

func (p *CompiledTokenPool) pickRoundRobin() int {
	n := uint64(len(p.Members))
	// Subtract 1 so the first call returns index 0; atomic.AddUint64
	// is one-based by default. Modulo on the post-increment value
	// keeps the counter monotonic forever — uint64 wrap is far enough
	// out we don't care.
	v := p.rr.Add(1) - 1
	return int(v % n)
}

func (p *CompiledTokenPool) pickLeastLoaded() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initState()
	bestIdx := 0
	bestCount := p.counts[0]
	for i := 1; i < len(p.Members); i++ {
		if p.counts[i] < bestCount {
			bestCount = p.counts[i]
			bestIdx = i
		}
	}
	return bestIdx
}

// MemberStats is one member's request-time bookkeeping snapshot. The
// dashboard reads this via Stats() to render per-member usage.
type MemberStats struct {
	Name      string    `json:"name"`
	Requests  uint64    `json:"requests"`
	LastUseNs int64     `json:"last_use_ns,omitempty"`
	LastUse   time.Time `json:"-"`
}

// Stats returns a per-member snapshot in declaration order. Used by
// the dashboard to surface pool activity.
func (p *CompiledTokenPool) Stats() []MemberStats {
	if p == nil {
		return nil
	}
	out := make([]MemberStats, len(p.Members))
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initState()
	for i, m := range p.Members {
		name := ""
		if m != nil && m.Symbol != nil {
			name = m.Symbol.Name
		}
		ms := MemberStats{Name: name, Requests: p.counts[i]}
		if !p.lastUse[i].IsZero() {
			ms.LastUse = p.lastUse[i]
			ms.LastUseNs = p.lastUse[i].UnixNano()
		}
		out[i] = ms
	}
	return out
}

// MemberNames returns the bare names of the pool's members in
// declaration order. Cheap helper for dashboard / emit consumers
// that don't need full stats.
func (p *CompiledTokenPool) MemberNames() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Members))
	for _, m := range p.Members {
		if m != nil && m.Symbol != nil {
			out = append(out, m.Symbol.Name)
		}
	}
	return out
}
