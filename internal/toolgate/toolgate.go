// Package toolgate is an exploratory implementation of LLM tool-call
// gating: rules applied to a model's tool_use blocks before the
// agent ever sees them. Three verdicts are recognised — allow, deny,
// and human-approval — and the gateway mutates the response stream
// to drive the appropriate downstream behaviour:
//
//   - allow / unmatched: response forwarded untouched.
//   - deny: the tool_use is replaced with a text block carrying the
//     refusal reason, and stop_reason is flipped to "end_turn", so the
//     model sees why it can't proceed and finishes the turn cleanly.
//     (Synthesising a tool_result the model reads next turn is the
//     alternative design — see design note #5 in the PR and
//     doc/tool-call-gating.md — deferred to v2.)
//   - hitl (human-in-the-loop): the tool_use is replaced with a
//     polling tool_use that asks the agent to long-poll clawpatrol
//     for the verdict. A pending entry, keyed by an opaque token,
//     is stored in the gateway. Once the human approves or denies
//     in the dashboard, the polling endpoint wakes up and returns
//     the verdict to the agent. The original tool call's args are
//     either released to the agent (approve) or substituted with a
//     deny tool_result (deny) via the model's next turn.
//
// This is a draft: Anthropic /v1/messages only. Both response shapes
// are handled — buffered JSON (GateAnthropicResponse) and streaming SSE
// (GateAnthropicSSE, per-block buffering so non-tool content keeps its
// time-to-first-token). The streaming path fails CLOSED: a tool_use it
// can't evaluate is blocked, never forwarded raw. Multi-tool-call
// turns work but the mixed-verdict failure modes are lightly tested;
// per-provider parsing for OpenAI/Codex/OpenRouter is flagged as TODO.
//
// Rules are evaluated by a tiny in-process matcher (Rule.Matches);
// the production design intent is to fold this into the unmerged
// cl-1yh llm_rule HCL plugin once that work lands on main. For the
// draft, rules are programmatically registered on the Gate.
package toolgate

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Verdict is the outcome of evaluating a tool call against the rule
// set. Allow short-circuits to "forward untouched"; Deny replaces the
// tool_use with a text block carrying the refusal reason (and flips
// stop_reason to "end_turn"); HITL pauses the call on a polling token
// until a human decides.
type Verdict string

// The three verdicts a rule can carry. See the Verdict type doc for
// what each one does to the tool_use block.
const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
	VerdictHITL  Verdict = "hitl"
)

// Rule is a single match-and-verdict. ToolName is glob-free in this
// draft — exact match against the tool_use block's `name`. ArgsContains
// is a substring check against the JSON-serialised input map, a
// blunt-but-useful primitive while the llm_rule CEL surface is still
// being designed.
//
// Reason rides into the synthesised tool_result on deny / the
// dashboard prompt on HITL so the model and the operator both see
// the same explanation.
type Rule struct {
	Name         string
	ToolName     string
	ArgsContains string
	Verdict      Verdict
	Reason       string
}

// Matches reports whether the call matches the rule's facets.
func (r Rule) Matches(toolName, argsJSON string) bool {
	if r.ToolName != "" && r.ToolName != toolName {
		return false
	}
	if r.ArgsContains != "" && !contains(argsJSON, r.ArgsContains) {
		return false
	}
	return true
}

// RuleSet is an ordered list of rules — first match wins. An empty
// set defaults to allow.
type RuleSet []Rule

// Evaluate walks the rules in order and returns the first matching
// rule. Returns (Rule{}, false) when no rule matches — caller treats
// that as allow.
func (rs RuleSet) Evaluate(toolName, argsJSON string) (Rule, bool) {
	for _, r := range rs {
		if r.Matches(toolName, argsJSON) {
			return r, true
		}
	}
	return Rule{}, false
}

// PendingCall is the gateway-side state for a tool_use awaiting
// human approval. The opaque Token is what the agent's polling call
// presents; the gateway's dashboard signals decision through Decide.
//
// State transitions are linear: pending → approved / denied. Once
// terminal, polling returns the verdict and the entry is GC'd by
// the store's sweep loop.
type PendingCall struct {
	Token     string
	ToolUseID string
	ToolName  string
	ToolInput []byte // raw JSON of the original tool_use's input
	Reason    string // operator-facing reason from the matched rule
	Created   time.Time

	// done is closed once a verdict is set. Pollers select on this
	// channel under their own deadline; many pollers can wait on the
	// same call (multiple agents, retry races) since close() is fan-out.
	done   chan struct{}
	mu     sync.Mutex
	state  Verdict // VerdictAllow ("approved") or VerdictDeny once decided
	by     string  // who decided, for audit
	noteOK bool
}

// State returns the current verdict and whether the call has been
// decided yet. While pending, returns ("", false).
func (p *PendingCall) State() (Verdict, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state, p.noteOK
}

// Decided returns a channel that closes once the call has a verdict.
// Pollers wait on this channel under their own deadline.
func (p *PendingCall) Decided() <-chan struct{} { return p.done }

// Decide records a verdict and wakes any waiting pollers. Idempotent:
// the second call is a no-op. The verdict must be VerdictAllow ("agent
// may execute") or VerdictDeny ("agent must not execute").
func (p *PendingCall) Decide(v Verdict, by string) {
	p.mu.Lock()
	first := !p.noteOK
	if first {
		p.state = v
		p.by = by
		p.noteOK = true
	}
	p.mu.Unlock()
	if first {
		close(p.done)
	}
}

// By returns the decider identifier (dashboard operator, in this
// draft). Only meaningful once Decided() has fired.
func (p *PendingCall) By() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.by
}

// newToken generates an unguessable 32-byte hex token. Random source
// is crypto/rand; a panic here means the OS entropy pool is broken,
// which is a fail-stop condition for any auth-bearing token.
func newToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("toolgate: crypto/rand: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// contains is a tiny substring helper to keep the rule matcher
// import-free (avoids pulling strings into the matcher's hot path
// from tests).
func contains(hay, needle string) bool {
	if needle == "" {
		return true
	}
	hayLen, nLen := len(hay), len(needle)
	if nLen > hayLen {
		return false
	}
	for i := 0; i+nLen <= hayLen; i++ {
		if hay[i:i+nLen] == needle {
			return true
		}
	}
	return false
}
