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

// fixtureAnthropicRequest is a realistic agent /v1/messages request: a
// short conversation plus a tools[] array advertising tools the agent
// can actually dispatch — including http_request, which the model is
// expected to pick for polling under the gateway-initiated follow-up.
const fixtureAnthropicRequest = `{
  "model": "claude-3-5-sonnet-20241022",
  "max_tokens": 1024,
  "system": "You are a helpful agent.",
  "tools": [
    {"name": "bash", "description": "run a shell command",
     "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}}},
    {"name": "http_request", "description": "make an HTTP request",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "method": {"type": "string"}, "body": {"type": "object"}}}}
  ],
  "messages": [
    {"role": "user", "content": "List the files in the current directory."}
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
	outcome, err := GateAnthropicResponse(context.Background(), rules, store, []byte(fixtureAnthropicSingleToolUse), nil)
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
	outcome, err := GateAnthropicResponse(context.Background(), rules, store, original, nil)
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
// approval dance under "option 2" (gateway-initiated LLM choice),
// exercised end-to-end with the live HTTP poll endpoint. Sequence:
//
//  1. Upstream returns a response with a tool_use the rule HITLs.
//  2. The gate parks the call, then runs a gateway-initiated follow-up
//     LLM call (fake here) so the model picks a polling tool from the
//     agent's own tools[]. The follow-up's response — naming a real
//     agent tool (http_request) — becomes the gated body.
//  3. Agent (simulated) calls POST /api/approval/poll with the token,
//     blocking under DefaultPollTimeout.
//  4. Dashboard (simulated) calls POST /api/approval/decide to approve.
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

	// Fake follow-up: stands in for clawpatrol's own upstream LLM call.
	// It asserts the rebuilt conversation and returns a turn that picks
	// http_request — a tool the agent actually advertises.
	var capturedReq []byte
	fc := &FollowupConfig{
		ReqBody:     []byte(fixtureAnthropicRequest),
		ApprovalURL: "https://clawpatrol.test",
		Caller: func(_ context.Context, reqBody []byte) ([]byte, error) {
			capturedReq = reqBody
			return []byte(`{
              "id": "msg_followup",
              "type": "message",
              "role": "assistant",
              "model": "claude-3-5-sonnet-20241022",
              "stop_reason": "tool_use",
              "content": [
                {"type": "text", "text": "I'll poll for the approval decision."},
                {"type": "tool_use", "id": "toolu_followup",
                 "name": "http_request",
                 "input": {"url": "https://clawpatrol.test/api/approval/poll", "method": "POST"}}
              ]
            }`), nil
		},
	}

	outcome, err := GateAnthropicResponse(context.Background(), rules, store, []byte(fixtureAnthropicSingleToolUse), fc)
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

	// The follow-up request must carry the rebuilt conversation: the
	// original user turn, the parked tool name + token in the fabricated
	// instruction, the agent's tools[], and stream:false.
	if capturedReq == nil {
		t.Fatal("gateway-initiated follow-up was never called")
	}
	var fr map[string]any
	if err := json.Unmarshal(capturedReq, &fr); err != nil {
		t.Fatalf("follow-up request parse: %v", err)
	}
	if fr["stream"] != false {
		t.Errorf("follow-up stream = %v, want false", fr["stream"])
	}
	if fr["tools"] == nil {
		t.Errorf("follow-up dropped the agent's tools[]")
	}
	reqMsgs, _ := fr["messages"].([]any)
	if len(reqMsgs) != 3 {
		t.Fatalf("follow-up messages = %d, want 3 (orig user + assistant + poll instruction)", len(reqMsgs))
	}
	lastMsg := reqMsgs[2].(map[string]any)
	if lastMsg["role"] != "user" {
		t.Errorf("last follow-up message role = %v, want user", lastMsg["role"])
	}
	if instr, _ := lastMsg["content"].(string); !strings.Contains(instr, pc.Token) || !strings.Contains(instr, "bash") {
		t.Errorf("poll instruction missing token/tool name: %q", lastMsg["content"])
	}

	// The gated body is the follow-up response, forwarded verbatim: it
	// names http_request (a real agent tool), NOT a clawpatrol-invented
	// tool the agent can't dispatch.
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
		t.Fatal("gated body missing the model-chosen polling tool_use")
	}
	if pollBlock["name"] != "http_request" {
		t.Errorf("polling tool name = %v, want http_request (a real agent tool)", pollBlock["name"])
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

// TestGate_HITLFollowupUnavailable: HITL with no follow-up caller wired
// must drop the raw tool_use and degrade to a "pending approval" text
// block (stop_reason end_turn), never leaking the original call.
func TestGate_HITLFollowupUnavailable(t *testing.T) {
	rules := RuleSet{{Name: "approve-bash", ToolName: "bash", Verdict: VerdictHITL, Reason: "needs approval"}}
	store := NewStore()
	outcome, err := GateAnthropicResponse(context.Background(), rules, store, []byte(fixtureAnthropicSingleToolUse), nil)
	if err != nil {
		t.Fatalf("GateAnthropicResponse: %v", err)
	}
	if !outcome.Rewrote {
		t.Fatalf("expected rewrite on hitl fallback")
	}
	if len(outcome.Parked) != 1 {
		t.Fatalf("expected 1 parked call, got %d", len(outcome.Parked))
	}
	var got map[string]any
	if err := json.Unmarshal(outcome.Body, &got); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if got["stop_reason"] != "end_turn" {
		t.Errorf("stop_reason = %v, want end_turn", got["stop_reason"])
	}
	for _, b := range got["content"].([]any) {
		if b.(map[string]any)["type"] == "tool_use" {
			t.Errorf("fail-closed violated: raw tool_use survived the fallback")
		}
	}
	if !strings.Contains(string(outcome.Body), "requires human approval") {
		t.Errorf("expected pending-approval text; body: %s", outcome.Body)
	}
}

// TestGate_HITLFollowupError: a follow-up caller that errors must also
// fall back to the pending-approval text block (not leak, not crash).
func TestGate_HITLFollowupError(t *testing.T) {
	rules := RuleSet{{Name: "approve-bash", ToolName: "bash", Verdict: VerdictHITL, Reason: "needs approval"}}
	store := NewStore()
	fc := &FollowupConfig{
		ReqBody: []byte(fixtureAnthropicRequest),
		Caller: func(_ context.Context, _ []byte) ([]byte, error) {
			return nil, fmt.Errorf("upstream 529 overloaded")
		},
	}
	outcome, err := GateAnthropicResponse(context.Background(), rules, store, []byte(fixtureAnthropicSingleToolUse), fc)
	if err != nil {
		t.Fatalf("GateAnthropicResponse: %v", err)
	}
	if len(outcome.Parked) != 1 {
		t.Fatalf("expected 1 parked call, got %d", len(outcome.Parked))
	}
	var got map[string]any
	if err := json.Unmarshal(outcome.Body, &got); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	for _, b := range got["content"].([]any) {
		if b.(map[string]any)["type"] == "tool_use" {
			t.Errorf("fail-closed violated: raw tool_use survived a follow-up error")
		}
	}
	if !strings.Contains(string(outcome.Body), "requires human approval") {
		t.Errorf("expected pending-approval text on follow-up error; body: %s", outcome.Body)
	}
}

// TestBuildFollowupRequest checks the rebuilt conversation shape: the
// parked tool_use is stripped from the assistant turn, the original text
// rationale is kept, a polling instruction user turn is appended, tools
// carry over, and stream is forced false.
func TestBuildFollowupRequest(t *testing.T) {
	store := NewStore()
	pc := store.Park("toolu_01XYZ", "bash", []byte(`{"command":"ls"}`), "needs approval")
	out, err := buildFollowupRequest([]byte(fixtureAnthropicRequest),
		[]byte(fixtureAnthropicSingleToolUse), []*PendingCall{pc}, "https://clawpatrol.test")
	if err != nil {
		t.Fatalf("buildFollowupRequest: %v", err)
	}
	var req map[string]any
	if err := json.Unmarshal(out, &req); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req["stream"] != false {
		t.Errorf("stream = %v, want false", req["stream"])
	}
	if req["tools"] == nil {
		t.Errorf("tools[] dropped")
	}
	msgs := req["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("messages = %d, want 3", len(msgs))
	}
	asst := msgs[1].(map[string]any)
	if asst["role"] != "assistant" {
		t.Errorf("msg[1] role = %v, want assistant", asst["role"])
	}
	// The assistant turn keeps the text rationale and drops the tool_use.
	asstContent := asst["content"].([]any)
	for _, b := range asstContent {
		if b.(map[string]any)["type"] == "tool_use" {
			t.Errorf("assistant turn still carries the parked tool_use")
		}
	}
	if len(asstContent) != 1 || asstContent[0].(map[string]any)["type"] != "text" {
		t.Errorf("assistant content = %v, want a single surviving text block", asstContent)
	}
	user := msgs[2].(map[string]any)
	instr, _ := user["content"].(string)
	if !strings.Contains(instr, pc.Token) || !strings.Contains(instr, "/api/approval/poll") {
		t.Errorf("instruction missing token or poll URL: %q", instr)
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
