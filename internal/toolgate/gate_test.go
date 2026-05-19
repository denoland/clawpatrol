package toolgate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Fixture: a realistic Anthropic /v1/messages response carrying a
// single tool_use block plus a leading text rationale block. Keeping
// the fixture inline (instead of testdata/) gives the test some
// self-documentation value for someone reviewing the draft PR.
const fixtureAnthropicSingleToolUse = `{
  "id": "msg_01ABC",
  "type": "message",
  "role": "assistant",
  "model": "claude-3-5-sonnet-20241022",
  "stop_reason": "tool_use",
  "stop_sequence": null,
  "usage": {"input_tokens": 12, "output_tokens": 34},
  "content": [
    {"type": "text", "text": "I'll run the command for you."},
    {"type": "tool_use",
     "id": "toolu_01XYZ",
     "name": "bash",
     "input": {"command": "rm -rf /important/data"}}
  ]
}`

// fixtureAnthropicAllowedToolUse exercises the no-rewrite path: the
// tool the model wants to call has no matching rule, so the response
// must come back byte-equivalent to upstream.
const fixtureAnthropicAllowedToolUse = `{
  "id": "msg_02DEF",
  "type": "message",
  "role": "assistant",
  "model": "claude-3-5-sonnet-20241022",
  "stop_reason": "tool_use",
  "stop_sequence": null,
  "usage": {"input_tokens": 5, "output_tokens": 10},
  "content": [
    {"type": "tool_use",
     "id": "toolu_02ALLOWED",
     "name": "read_file",
     "input": {"path": "/etc/hostname"}}
  ]
}`

// TestGate_DenyPath: a rule denies the `bash` tool. The rewritten
// body must drop the tool_use, add a text block carrying the reason,
// flip stop_reason to end_turn, and preserve every untouched sibling
// field.
func TestGate_DenyPath(t *testing.T) {
	rules := RuleSet{
		{Name: "no-bash", ToolName: "bash", Verdict: VerdictDeny, Reason: "no shell execution"},
	}
	store := NewStore()
	outcome, err := GateAnthropicResponse(rules, store, []byte(fixtureAnthropicSingleToolUse))
	if err != nil {
		t.Fatalf("GateAnthropicResponse: %v", err)
	}
	if !outcome.Rewrote {
		t.Fatalf("expected body rewrite on deny, got Rewrote=false")
	}
	if outcome.ToolUsesSeen != 1 {
		t.Errorf("ToolUsesSeen = %d, want 1", outcome.ToolUsesSeen)
	}
	if len(outcome.Parked) != 0 {
		t.Errorf("deny path parked %d calls, want 0", len(outcome.Parked))
	}

	var got map[string]any
	if err := json.Unmarshal(outcome.Body, &got); err != nil {
		t.Fatalf("rewritten body unmarshal: %v", err)
	}
	if got["stop_reason"] != "end_turn" {
		t.Errorf("stop_reason = %v, want end_turn", got["stop_reason"])
	}
	if got["id"] != "msg_01ABC" {
		t.Errorf("id mutated: got %v, want msg_01ABC", got["id"])
	}
	blocks := got["content"].([]any)
	if len(blocks) != 2 {
		t.Fatalf("content len = %d, want 2 (text + deny-text)", len(blocks))
	}
	denyBlock := blocks[1].(map[string]any)
	if denyBlock["type"] != "text" {
		t.Errorf("post-deny block type = %v, want text", denyBlock["type"])
	}
	if !strings.Contains(denyBlock["text"].(string), "no shell execution") {
		t.Errorf("deny text missing reason: %q", denyBlock["text"])
	}
}

// TestGate_AllowPath: response carries a tool_use with no matching
// rule. Body comes back unchanged byte-for-byte and ToolUsesSeen=1.
func TestGate_AllowPath(t *testing.T) {
	rules := RuleSet{
		{ToolName: "bash", Verdict: VerdictDeny},
	}
	store := NewStore()
	original := []byte(fixtureAnthropicAllowedToolUse)
	outcome, err := GateAnthropicResponse(rules, store, original)
	if err != nil {
		t.Fatalf("GateAnthropicResponse: %v", err)
	}
	if outcome.Rewrote {
		t.Errorf("unexpected rewrite on allow path")
	}
	if outcome.ToolUsesSeen != 1 {
		t.Errorf("ToolUsesSeen = %d, want 1", outcome.ToolUsesSeen)
	}
	if !bytes.Equal(outcome.Body, original) {
		t.Errorf("body mutated on allow path")
	}
}

// TestE2E_HITLDance is the spec's "hard part" — the full multi-turn
// approval dance, exercised end-to-end with the live HTTP poll
// endpoint. Sequence:
//
//  1. Upstream returns a response with a tool_use the rule HITLs.
//  2. Gate rewrites the response, swapping the tool_use for a
//     clawpatrol_poll tool_use with an opaque token.
//  3. Agent (simulated) calls POST /api/approval/poll with the token,
//     blocking under DefaultPollTimeout.
//  4. Dashboard (simulated) calls POST /api/approval/decide to
//     approve the call.
//  5. The agent's poll wakes up and gets {state:"approved",...}.
//
// The test asserts that the polling call returns within the test's
// own ~1s deadline (not the 30s DefaultPollTimeout) — proving the
// wake-up channel actually fires.
func TestE2E_HITLDance(t *testing.T) {
	rules := RuleSet{
		{Name: "exec-needs-approval",
			ToolName: "bash",
			Verdict:  VerdictHITL,
			Reason:   "shell execution requires operator approval"},
	}
	store := NewStore()

	outcome, err := GateAnthropicResponse(rules, store, []byte(fixtureAnthropicSingleToolUse))
	if err != nil {
		t.Fatalf("GateAnthropicResponse: %v", err)
	}
	if len(outcome.Parked) != 1 {
		t.Fatalf("expected 1 parked call, got %d", len(outcome.Parked))
	}
	pc := outcome.Parked[0]
	if pc.Token == "" {
		t.Fatal("parked call has empty token")
	}

	// Sanity: rewritten body advertises clawpatrol_poll as the tool
	// the agent will execute next.
	var rewritten struct {
		Content []map[string]any `json:"content"`
	}
	if err := json.Unmarshal(outcome.Body, &rewritten); err != nil {
		t.Fatalf("rewritten body parse: %v", err)
	}
	var pollBlock map[string]any
	for _, b := range rewritten.Content {
		if b["type"] == "tool_use" {
			pollBlock = b
			break
		}
	}
	if pollBlock == nil {
		t.Fatal("rewritten body missing polling tool_use")
	}
	if pollBlock["name"] != PollingToolName {
		t.Errorf("polling tool name = %v, want %s", pollBlock["name"], PollingToolName)
	}
	pollInput := pollBlock["input"].(map[string]any)
	if pollInput["token"] != pc.Token {
		t.Errorf("polling tool token = %v, want %s", pollInput["token"], pc.Token)
	}

	// Spin up the HTTP mux backed by the store.
	srv := httptest.NewServer(Mux(store))
	defer srv.Close()

	// Agent goroutine: long-polls for the verdict. Short header
	// timeout so the goroutine doesn't sit on the default 30s.
	type pollResult struct {
		status int
		resp   PollResponse
		err    error
	}
	pollCh := make(chan pollResult, 1)
	go func() {
		body := fmt.Sprintf(`{"token":%q}`, pc.Token)
		req, err := http.NewRequest(http.MethodPost,
			srv.URL+"/api/approval/poll",
			strings.NewReader(body))
		if err != nil {
			pollCh <- pollResult{err: err}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Poll-Timeout-Seconds", "5")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := http.DefaultClient.Do(req.WithContext(ctx))
		if err != nil {
			pollCh <- pollResult{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		var pr PollResponse
		if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
			pollCh <- pollResult{err: err}
			return
		}
		pollCh <- pollResult{status: resp.StatusCode, resp: pr}
	}()

	// Give the agent a beat to actually block on the channel rather
	// than racing the decide before the select. Without this, the
	// test sometimes hits the synchronous early-return path in
	// handlePoll and never exercises the wake-up edge — which is
	// the whole point of the assertion.
	time.Sleep(50 * time.Millisecond)

	// Dashboard goroutine: approves the call.
	decideBody := fmt.Sprintf(`{"token":%q,"decision":"approve","by":"test-operator"}`, pc.Token)
	resp, err := http.Post(srv.URL+"/api/approval/decide",
		"application/json",
		strings.NewReader(decideBody))
	if err != nil {
		t.Fatalf("decide call: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decide status = %d, want 200", resp.StatusCode)
	}

	select {
	case got := <-pollCh:
		if got.err != nil {
			t.Fatalf("agent poll: %v", got.err)
		}
		if got.status != http.StatusOK {
			t.Errorf("poll status = %d, want 200", got.status)
		}
		if got.resp.State != "approved" {
			t.Errorf("poll state = %q, want approved", got.resp.State)
		}
		if got.resp.By != "test-operator" {
			t.Errorf("poll by = %q, want test-operator", got.resp.By)
		}
		if got.resp.Token != pc.Token {
			t.Errorf("poll token = %q, want %s", got.resp.Token, pc.Token)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent poll did not wake up after dashboard approval")
	}

	// Re-poll after decide: should return synchronously, not block.
	start := time.Now()
	resp, err = http.Post(srv.URL+"/api/approval/poll",
		"application/json",
		strings.NewReader(fmt.Sprintf(`{"token":%q}`, pc.Token)))
	if err != nil {
		t.Fatalf("re-poll: %v", err)
	}
	elapsed := time.Since(start)
	_ = resp.Body.Close()
	if elapsed > 500*time.Millisecond {
		t.Errorf("re-poll after decide took %v, want <500ms (terminal state should short-circuit)", elapsed)
	}
}

// TestE2E_DenyDecision exercises the operator-deny half of the HITL
// dance: park, deny, poller sees "denied".
func TestE2E_DenyDecision(t *testing.T) {
	store := NewStore()
	pc := store.Park("toolu_test", "bash", []byte(`{"command":"rm -rf /"}`), "destructive")
	srv := httptest.NewServer(Mux(store))
	defer srv.Close()

	pollCh := make(chan PollResponse, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/approval/poll",
			strings.NewReader(fmt.Sprintf(`{"token":%q}`, pc.Token)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Poll-Timeout-Seconds", "5")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			pollCh <- PollResponse{State: "error"}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		var pr PollResponse
		_ = json.NewDecoder(resp.Body).Decode(&pr)
		pollCh <- pr
	}()

	time.Sleep(50 * time.Millisecond)
	body := fmt.Sprintf(`{"token":%q,"decision":"deny","by":"op"}`, pc.Token)
	resp, err := http.Post(srv.URL+"/api/approval/decide", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case pr := <-pollCh:
		if pr.State != "denied" {
			t.Errorf("state = %q, want denied", pr.State)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("deny path did not wake poller")
	}
}

// TestE2E_PollTimeout: with no decision and a short configured
// timeout, the poll endpoint returns state="pending" so the agent
// can re-poll.
func TestE2E_PollTimeout(t *testing.T) {
	store := NewStore()
	pc := store.Park("toolu_x", "x", []byte(`{}`), "")
	srv := httptest.NewServer(Mux(store))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/approval/poll",
		strings.NewReader(fmt.Sprintf(`{"token":%q}`, pc.Token)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Poll-Timeout-Seconds", "1")
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond {
		t.Errorf("poll returned too fast (%v) — should have held ~1s", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("poll held too long (%v) — should have bailed after ~1s", elapsed)
	}
	var pr PollResponse
	_ = json.NewDecoder(resp.Body).Decode(&pr)
	if pr.State != "pending" {
		t.Errorf("state = %q, want pending", pr.State)
	}
}

// TestStore_Sweep: a decided call older than retainAfterDecide is
// reaped; a pending call of any age survives.
func TestStore_Sweep(t *testing.T) {
	store := NewStore()
	store.retainAfterDecide = 100 * time.Millisecond
	old := store.Park("toolu_old", "x", nil, "")
	old.Decide(VerdictAllow, "op")
	young := store.Park("toolu_young", "y", nil, "")
	// Simulate old age — backdate Created instead of sleeping.
	old.Created = time.Now().Add(-1 * time.Second)
	store.Sweep()
	if store.Lookup(old.Token) != nil {
		t.Errorf("Sweep didn't reap aged decided call")
	}
	if store.Lookup(young.Token) == nil {
		t.Errorf("Sweep reaped a pending call")
	}
}
