package toolgate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// sseEvent is a parsed SSE frame: the event name and the decoded data
// payload as a generic map.
type sseEvent struct {
	event string
	data  map[string]any
}

// parseSSE splits a rendered SSE stream into its events for assertions.
// Comment lines and frames with non-JSON data are skipped.
func parseSSE(t *testing.T, s string) []sseEvent {
	t.Helper()
	var out []sseEvent
	for _, block := range strings.Split(s, "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var ev sseEvent
		var dataLines []string
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "event:"):
				ev.event = strings.TrimSpace(line[len("event:"):])
			case strings.HasPrefix(line, "data:"):
				dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line[len("data:"):], " "), ""))
			}
		}
		if len(dataLines) > 0 {
			payload := strings.Join(dataLines, "\n")
			if err := json.Unmarshal([]byte(payload), &ev.data); err != nil {
				t.Fatalf("parseSSE: bad data %q: %v", payload, err)
			}
		}
		out = append(out, ev)
	}
	return out
}

// frame renders a single Anthropic-style SSE event.
func frame(event, data string) string {
	return "event: " + event + "\ndata: " + data + "\n\n"
}

// sseStreamToolUse builds a realistic streaming /v1/messages response
// with one leading text block and one tool_use block whose input is
// split across two input_json_delta frames, then a trailing
// message_delta carrying stop_reason "tool_use".
func sseStreamToolUse(toolName, inputPart1, inputPart2 string) string {
	var b strings.Builder
	b.WriteString(frame("message_start", `{"type":"message_start","message":{"id":"msg_01","role":"assistant","content":[],"stop_reason":null}}`))
	b.WriteString(frame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`))
	b.WriteString(frame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"working"}}`))
	b.WriteString(frame("content_block_stop", `{"type":"content_block_stop","index":0}`))
	b.WriteString(frame("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01XYZ","name":"`+toolName+`","input":{}}}`))
	b.WriteString(frame("ping", `{"type":"ping"}`))
	b.WriteString(frame("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":`+jsonStr(inputPart1)+`}}`))
	b.WriteString(frame("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":`+jsonStr(inputPart2)+`}}`))
	b.WriteString(frame("content_block_stop", `{"type":"content_block_stop","index":1}`))
	b.WriteString(frame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":20}}`))
	b.WriteString(frame("message_stop", `{"type":"message_stop"}`))
	return b.String()
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// findToolUse returns the first tool_use content_block_start in the
// parsed stream, or nil.
func findToolUse(evs []sseEvent) map[string]any {
	for _, ev := range evs {
		if ev.event != "content_block_start" {
			continue
		}
		cb, _ := ev.data["content_block"].(map[string]any)
		if cb != nil && cb["type"] == "tool_use" {
			return cb
		}
	}
	return nil
}

// stopReason returns the stop_reason carried by the message_delta frame.
func stopReason(evs []sseEvent) string {
	for _, ev := range evs {
		if ev.event != "message_delta" {
			continue
		}
		delta, _ := ev.data["delta"].(map[string]any)
		if delta != nil {
			if sr, ok := delta["stop_reason"].(string); ok {
				return sr
			}
		}
	}
	return ""
}

// TestSSE_AllowReplaysVerbatim: a tool_use with no matching rule must
// stream through byte-for-byte identical to upstream.
func TestSSE_AllowReplaysVerbatim(t *testing.T) {
	rules := RuleSet{{ToolName: "bash", Verdict: VerdictDeny}}
	store := NewStore()
	in := sseStreamToolUse("read_file", `{"path":`, `"/etc/hostname"}`)

	var dst bytes.Buffer
	out := &SSEOutcome{}
	if err := GateAnthropicSSE(rules, store, strings.NewReader(in), &dst, out); err != nil {
		t.Fatalf("GateAnthropicSSE: %v", err)
	}
	if out.Rewrote {
		t.Errorf("allow path reported Rewrote=true")
	}
	if out.ToolUsesSeen != 1 {
		t.Errorf("ToolUsesSeen = %d, want 1", out.ToolUsesSeen)
	}
	if dst.String() != in {
		t.Errorf("allow path mutated the stream.\n got: %q\nwant: %q", dst.String(), in)
	}
}

// TestSSE_DenyRewrites: a denied tool_use is replaced with a text block
// carrying the reason, no tool_use survives, and stop_reason flips to
// end_turn.
func TestSSE_DenyRewrites(t *testing.T) {
	rules := RuleSet{{Name: "no-bash", ToolName: "bash", Verdict: VerdictDeny, Reason: "no shell execution"}}
	store := NewStore()
	in := sseStreamToolUse("bash", `{"command":`, `"rm -rf /"}`)

	var dst bytes.Buffer
	out := &SSEOutcome{}
	if err := GateAnthropicSSE(rules, store, strings.NewReader(in), &dst, out); err != nil {
		t.Fatalf("GateAnthropicSSE: %v", err)
	}
	if !out.Rewrote {
		t.Fatalf("deny path reported Rewrote=false")
	}
	evs := parseSSE(t, dst.String())
	if tu := findToolUse(evs); tu != nil {
		t.Errorf("deny path leaked a tool_use: %v", tu)
	}
	if sr := stopReason(evs); sr != "end_turn" {
		t.Errorf("stop_reason = %q, want end_turn", sr)
	}
	// The synthesised text block must carry the reason.
	var sawReason bool
	for _, ev := range evs {
		if ev.event == "content_block_delta" {
			if delta, ok := ev.data["delta"].(map[string]any); ok {
				if txt, ok := delta["text"].(string); ok && strings.Contains(txt, "no shell execution") {
					sawReason = true
				}
			}
		}
	}
	if !sawReason {
		t.Errorf("deny text block missing reason; stream:\n%s", dst.String())
	}
	// The leading text block ("working") must survive untouched.
	if !strings.Contains(dst.String(), `"text":"working"`) {
		t.Errorf("deny path dropped the leading text block")
	}
}

// TestSSE_HITLParksAndEmitsPoll: a hitl tool_use parks a call and emits
// a clawpatrol_poll tool_use carrying the token; stop_reason stays
// tool_use (the poll IS a tool_use).
func TestSSE_HITLParksAndEmitsPoll(t *testing.T) {
	rules := RuleSet{{Name: "approve-bash", ToolName: "bash", Verdict: VerdictHITL, Reason: "operator approval"}}
	store := NewStore()
	in := sseStreamToolUse("bash", `{"command":`, `"ls -la"}`)

	var dst bytes.Buffer
	out := &SSEOutcome{}
	if err := GateAnthropicSSE(rules, store, strings.NewReader(in), &dst, out); err != nil {
		t.Fatalf("GateAnthropicSSE: %v", err)
	}
	if len(out.Parked) != 1 {
		t.Fatalf("parked %d calls, want 1", len(out.Parked))
	}
	pc := out.Parked[0]
	if string(pc.ToolInput) != `{"command":"ls -la"}` {
		t.Errorf("parked input = %q, want the reassembled model args", pc.ToolInput)
	}
	if store.Lookup(pc.Token) == nil {
		t.Errorf("parked call not registered in store")
	}
	evs := parseSSE(t, dst.String())
	tu := findToolUse(evs)
	if tu == nil {
		t.Fatalf("hitl path emitted no tool_use")
	}
	if tu["name"] != PollingToolName {
		t.Errorf("emitted tool name = %v, want %s", tu["name"], PollingToolName)
	}
	if sr := stopReason(evs); sr != "tool_use" {
		t.Errorf("stop_reason = %q, want tool_use (poll is still a tool_use)", sr)
	}
	// The poll token must ride in the input_json_delta partial_json.
	if !strings.Contains(dst.String(), pc.Token) {
		t.Errorf("poll token missing from emitted stream")
	}
}

// TestSSE_FailClosedOnMalformedDelta: a malformed delta frame on a held
// tool_use block must NOT forward the raw tool call — the block is
// blocked with a refusal text block instead (fail closed).
func TestSSE_FailClosedOnMalformedDelta(t *testing.T) {
	rules := RuleSet{{ToolName: "bash", Verdict: VerdictAllow}} // would allow if evaluable
	store := NewStore()

	var b strings.Builder
	b.WriteString(frame("message_start", `{"type":"message_start","message":{"content":[]}}`))
	b.WriteString(frame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_x","name":"bash","input":{}}}`))
	// Malformed data payload (truncated JSON) for a delta on the held block.
	b.WriteString(frame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{`))
	b.WriteString(frame("content_block_stop", `{"type":"content_block_stop","index":0}`))
	b.WriteString(frame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{}}`))
	in := b.String()

	var dst bytes.Buffer
	out := &SSEOutcome{}
	if err := GateAnthropicSSE(rules, store, strings.NewReader(in), &dst, out); err != nil {
		t.Fatalf("GateAnthropicSSE: %v", err)
	}
	evs := parseSSE(t, dst.String())
	if tu := findToolUse(evs); tu != nil {
		t.Errorf("fail-closed violated: raw tool_use leaked: %v", tu)
	}
	if !out.Rewrote {
		t.Errorf("expected Rewrote=true on fail-closed block")
	}
	if !strings.Contains(dst.String(), "could not evaluate") {
		t.Errorf("expected blocking refusal text; stream:\n%s", dst.String())
	}
	// No tool_use survived → stop_reason flipped.
	if sr := stopReason(evs); sr != "end_turn" {
		t.Errorf("stop_reason = %q, want end_turn", sr)
	}
}

// TestSSE_FailClosedOnBadBlockStart: an unparseable content_block_start
// (which could be announcing a tool_use) terminates the stream with an
// error rather than passing the frame through — the strongest fail-
// closed posture.
func TestSSE_FailClosedOnBadBlockStart(t *testing.T) {
	rules := RuleSet{{ToolName: "bash", Verdict: VerdictDeny}}
	store := NewStore()

	var b strings.Builder
	b.WriteString(frame("message_start", `{"type":"message_start","message":{"content":[]}}`))
	// content_block_start whose data declares the type but is otherwise
	// broken JSON — cannot be introspected for tool_use.
	b.WriteString(frame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{`))
	in := b.String()

	var dst bytes.Buffer
	out := &SSEOutcome{}
	err := GateAnthropicSSE(rules, store, strings.NewReader(in), &dst, out)
	if err == nil {
		t.Fatalf("expected an error terminating the stream, got nil")
	}
	if findToolUse(parseSSE(t, dst.String())) != nil {
		t.Errorf("fail-closed violated: tool_use present in partial output")
	}
}

// TestSSE_TruncatedMidToolUse: a stream that ends before
// content_block_stop must drop the held tool_use (never emit it) and
// report the truncation as an error.
func TestSSE_TruncatedMidToolUse(t *testing.T) {
	rules := RuleSet{{ToolName: "bash", Verdict: VerdictAllow}}
	store := NewStore()

	var b strings.Builder
	b.WriteString(frame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_x","name":"bash","input":{}}}`))
	b.WriteString(frame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}`))
	// stream ends here, no content_block_stop
	in := b.String()

	var dst bytes.Buffer
	out := &SSEOutcome{}
	err := GateAnthropicSSE(rules, store, strings.NewReader(in), &dst, out)
	if err == nil {
		t.Fatalf("expected truncation error, got nil")
	}
	if findToolUse(parseSSE(t, dst.String())) != nil {
		t.Errorf("fail-closed violated: held tool_use emitted on truncated stream")
	}
}

// TestSSE_MixedKeepsStopReason: when one tool_use is allowed and another
// denied in the same turn, a tool_use survives, so stop_reason must NOT
// be flipped.
func TestSSE_MixedKeepsStopReason(t *testing.T) {
	rules := RuleSet{{Name: "no-bash", ToolName: "bash", Verdict: VerdictDeny, Reason: "nope"}}
	store := NewStore()

	var b strings.Builder
	b.WriteString(frame("message_start", `{"type":"message_start","message":{"content":[]}}`))
	// allowed tool_use (read_file)
	b.WriteString(frame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_a","name":"read_file","input":{}}}`))
	b.WriteString(frame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"/x\"}"}}`))
	b.WriteString(frame("content_block_stop", `{"type":"content_block_stop","index":0}`))
	// denied tool_use (bash)
	b.WriteString(frame("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_b","name":"bash","input":{}}}`))
	b.WriteString(frame("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm\"}"}}`))
	b.WriteString(frame("content_block_stop", `{"type":"content_block_stop","index":1}`))
	b.WriteString(frame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{}}`))
	in := b.String()

	var dst bytes.Buffer
	out := &SSEOutcome{}
	if err := GateAnthropicSSE(rules, store, strings.NewReader(in), &dst, out); err != nil {
		t.Fatalf("GateAnthropicSSE: %v", err)
	}
	if out.ToolUsesSeen != 2 {
		t.Errorf("ToolUsesSeen = %d, want 2", out.ToolUsesSeen)
	}
	evs := parseSSE(t, dst.String())
	if sr := stopReason(evs); sr != "tool_use" {
		t.Errorf("stop_reason = %q, want tool_use (read_file survived)", sr)
	}
	// read_file must still be present; bash must be gone.
	if !strings.Contains(dst.String(), `"name":"read_file"`) {
		t.Errorf("allowed read_file tool_use was dropped")
	}
	if strings.Contains(dst.String(), `"name":"bash"`) {
		t.Errorf("denied bash tool_use leaked")
	}
}
