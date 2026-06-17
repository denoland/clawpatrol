package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/denoland/clawpatrol/internal/config"
)

func newRecordingTracer(t *testing.T) (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	return sr, tp
}

func attrMap(kvs []attribute.KeyValue) map[string]attribute.Value {
	m := make(map[string]attribute.Value, len(kvs))
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value
	}
	return m
}

func TestEmitGenAISpanAttributesNoContent(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	turn := genAITurn{
		System:         "anthropic",
		Operation:      "chat",
		ConversationID: "s_abc123",
		RequestModel:   "claude-3-5-sonnet-20241022",
		ResponseModel:  "claude-3-5-sonnet-20241022",
		InputTokens:    42,
		OutputTokens:   17,
		FinishReason:   "end_turn",
		Messages:       []genAIMessage{{Role: "user", Parts: []genAIPart{{Type: "text", Content: "secret prompt"}}}},
		Output:         []genAIPart{{Type: "text", Content: "secret completion"}},
	}
	emitGenAISpan(tp.Tracer("test"), turn, false)

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Name() != "chat claude-3-5-sonnet-20241022" {
		t.Errorf("span name = %q", s.Name())
	}
	m := attrMap(s.Attributes())
	if m["gen_ai.system"].AsString() != "anthropic" {
		t.Errorf("gen_ai.system = %q", m["gen_ai.system"].AsString())
	}
	if m["gen_ai.operation.name"].AsString() != "chat" {
		t.Errorf("gen_ai.operation.name = %q", m["gen_ai.operation.name"].AsString())
	}
	if m["gen_ai.conversation.id"].AsString() != "s_abc123" {
		t.Errorf("gen_ai.conversation.id = %q, want s_abc123", m["gen_ai.conversation.id"].AsString())
	}
	if m["gen_ai.request.model"].AsString() != "claude-3-5-sonnet-20241022" {
		t.Errorf("gen_ai.request.model = %q", m["gen_ai.request.model"].AsString())
	}
	if got := m["gen_ai.usage.input_tokens"].AsInt64(); got != 42 {
		t.Errorf("gen_ai.usage.input_tokens = %d, want 42", got)
	}
	if got := m["gen_ai.usage.output_tokens"].AsInt64(); got != 17 {
		t.Errorf("gen_ai.usage.output_tokens = %d, want 17", got)
	}
	if fr := m["gen_ai.response.finish_reasons"].AsStringSlice(); len(fr) != 1 || fr[0] != "end_turn" {
		t.Errorf("gen_ai.response.finish_reasons = %v", fr)
	}
	// Content flag off: no events, and no message content anywhere.
	if len(s.Events()) != 0 {
		t.Errorf("got %d events with content off, want 0", len(s.Events()))
	}
}

func TestEmitGenAISpanWithContent(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	turn := genAITurn{
		System:       "anthropic",
		Operation:    "chat",
		RequestModel: "claude-3-5-sonnet-20241022",
		FinishReason: "end_turn",
		Messages: []genAIMessage{
			{Role: "system", Parts: []genAIPart{{Type: "text", Content: "you are helpful"}}},
			{Role: "user", Parts: []genAIPart{{Type: "text", Content: "hello there"}}},
		},
		Output: []genAIPart{{Type: "text", Content: "general kenobi"}},
	}
	emitGenAISpan(tp.Tracer("test"), turn, true)

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	// Content rides span attributes now, not events.
	if n := len(spans[0].Events()); n != 0 {
		t.Errorf("got %d events, want 0 (content is on attributes)", n)
	}
	m := attrMap(spans[0].Attributes())

	// System message → gen_ai.system_instructions (separate from input).
	var sysParts []genAIPart
	if err := json.Unmarshal([]byte(m["gen_ai.system_instructions"].AsString()), &sysParts); err != nil {
		t.Fatalf("gen_ai.system_instructions: %v (raw %q)", err, m["gen_ai.system_instructions"].AsString())
	}
	wantSys := []genAIPart{{Type: "text", Content: "you are helpful"}}
	if !reflect.DeepEqual(sysParts, wantSys) {
		t.Errorf("gen_ai.system_instructions = %+v, want %+v", sysParts, wantSys)
	}

	// Non-system messages → gen_ai.input.messages.
	var input []genAIChatMessage
	if err := json.Unmarshal([]byte(m["gen_ai.input.messages"].AsString()), &input); err != nil {
		t.Fatalf("gen_ai.input.messages: %v (raw %q)", err, m["gen_ai.input.messages"].AsString())
	}
	wantInput := []genAIChatMessage{
		{Role: "user", Parts: []genAIPart{{Type: "text", Content: "hello there"}}},
	}
	if !reflect.DeepEqual(input, wantInput) {
		t.Errorf("gen_ai.input.messages = %+v, want %+v", input, wantInput)
	}

	// Completion → gen_ai.output.messages with finish reason.
	var output []genAIChatMessage
	if err := json.Unmarshal([]byte(m["gen_ai.output.messages"].AsString()), &output); err != nil {
		t.Fatalf("gen_ai.output.messages: %v (raw %q)", err, m["gen_ai.output.messages"].AsString())
	}
	wantOutput := []genAIChatMessage{
		{Role: "assistant", Parts: []genAIPart{{Type: "text", Content: "general kenobi"}}, FinishReason: "end_turn"},
	}
	if !reflect.DeepEqual(output, wantOutput) {
		t.Errorf("gen_ai.output.messages = %+v, want %+v", output, wantOutput)
	}
}

func TestEmitGenAISpanNilTracerNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("emitGenAISpan(nil) panicked: %v", r)
		}
	}()
	emitGenAISpan(nil, genAITurn{System: "anthropic", Operation: "chat"}, true)
}

func TestClaudeContentMessages(t *testing.T) {
	body := []byte(`{
		"model":"claude-3-5-sonnet-20241022",
		"system":"be terse",
		"messages":[
			{"role":"user","content":"first"},
			{"role":"assistant","content":[{"type":"text","text":"reply"}]},
			{"role":"user","content":[{"type":"text","text":"second"}]}
		]
	}`)
	msgs := claudeContentMessages(body)
	want := []genAIMessage{
		{Role: "system", Parts: []genAIPart{{Type: "text", Content: "be terse"}}},
		{Role: "user", Parts: []genAIPart{{Type: "text", Content: "first"}}},
		{Role: "assistant", Parts: []genAIPart{{Type: "text", Content: "reply"}}},
		{Role: "user", Parts: []genAIPart{{Type: "text", Content: "second"}}},
	}
	if !reflect.DeepEqual(msgs, want) {
		t.Errorf("claudeContentMessages = %+v, want %+v", msgs, want)
	}
}

// TestClaudeContentMessagesAllBlockTypes covers the reviewer's request:
// every block kind in a request — not just text — is mapped to a GenAI
// message part. tool_use → tool_call, tool_result → tool_call_response,
// thinking → reasoning, and an unknown block (image) → a generic part
// that preserves the type without carrying its raw payload.
func TestClaudeContentMessagesAllBlockTypes(t *testing.T) {
	body := []byte(`{
		"system":[{"type":"text","text":"sys one"},{"type":"text","text":"sys two"}],
		"messages":[
			{"role":"user","content":[
				{"type":"text","text":"look at this"},
				{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}
			]},
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"let me check the weather"},
				{"type":"text","text":"calling a tool"},
				{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{"location":"Paris"}}
			]},
			{"role":"user","content":[
				{"type":"tool_result","tool_use_id":"toolu_1","content":"rainy, 57F"}
			]}
		]
	}`)
	msgs := claudeContentMessages(body)
	want := []genAIMessage{
		{Role: "system", Parts: []genAIPart{
			{Type: "text", Content: "sys one"},
			{Type: "text", Content: "sys two"},
		}},
		{Role: "user", Parts: []genAIPart{
			{Type: "text", Content: "look at this"},
			{Type: "image"},
		}},
		{Role: "assistant", Parts: []genAIPart{
			{Type: "reasoning", Content: "let me check the weather"},
			{Type: "text", Content: "calling a tool"},
			{Type: "tool_call", ID: "toolu_1", Name: "get_weather", Arguments: json.RawMessage(`{"location":"Paris"}`)},
		}},
		{Role: "user", Parts: []genAIPart{
			{Type: "tool_call_response", ID: "toolu_1", Response: json.RawMessage(`"rainy, 57F"`)},
		}},
	}
	if !reflect.DeepEqual(msgs, want) {
		t.Errorf("claudeContentMessages = %#v\nwant %#v", msgs, want)
	}
}

func TestClaudeResponseContentJSON(t *testing.T) {
	body := []byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"line one"},{"type":"text","text":"line two"}]}`)
	parts, finish := claudeResponseContent(body)
	want := []genAIPart{
		{Type: "text", Content: "line one"},
		{Type: "text", Content: "line two"},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %+v, want %+v", parts, want)
	}
	if finish != "end_turn" {
		t.Errorf("finish = %q", finish)
	}
}

// TestClaudeResponseContentJSONToolUse asserts a non-streaming response
// carrying a tool call (and reasoning) is captured as tool_call /
// reasoning parts, not dropped.
func TestClaudeResponseContentJSONToolUse(t *testing.T) {
	body := []byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"tool_use","content":[
		{"type":"thinking","thinking":"need the weather"},
		{"type":"text","text":"let me check"},
		{"type":"tool_use","id":"toolu_9","name":"get_weather","input":{"location":"Paris"}}
	]}`)
	parts, finish := claudeResponseContent(body)
	want := []genAIPart{
		{Type: "reasoning", Content: "need the weather"},
		{Type: "text", Content: "let me check"},
		{Type: "tool_call", ID: "toolu_9", Name: "get_weather", Arguments: json.RawMessage(`{"location":"Paris"}`)},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v\nwant %#v", parts, want)
	}
	if finish != "tool_use" {
		t.Errorf("finish = %q, want tool_use", finish)
	}
}

func TestClaudeResponseContentSSE(t *testing.T) {
	body := []byte(`event: message_start
data: {"type":"message_start","message":{"model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":5}}}

event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":", world"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}
`)
	parts, finish := claudeResponseContent(body)
	want := []genAIPart{{Type: "text", Content: "Hello, world"}}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %+v, want %+v", parts, want)
	}
	if finish != "end_turn" {
		t.Errorf("finish = %q, want end_turn", finish)
	}
}

// TestClaudeResponseContentSSEToolUse asserts a streamed response with a
// tool call reconstructs the tool_call part (id, name, and arguments
// accumulated from input_json_delta fragments) plus any text/reasoning
// blocks, indexed correctly.
func TestClaudeResponseContentSSEToolUse(t *testing.T) {
	body := []byte(`event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"on it"}}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_5","name":"get_weather"}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\":"}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"Paris\"}"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}
`)
	parts, finish := claudeResponseContent(body)
	want := []genAIPart{
		{Type: "text", Content: "on it"},
		{Type: "tool_call", ID: "toolu_5", Name: "get_weather", Arguments: json.RawMessage(`{"location":"Paris"}`)},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v\nwant %#v", parts, want)
	}
	if finish != "tool_use" {
		t.Errorf("finish = %q, want tool_use", finish)
	}
}

func TestRecordGenAITurnDisabled(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	prev := genaiTracer
	genaiTracer = tp.Tracer("test")
	defer func() { genaiTracer = prev }()

	// No genai_telemetry block → disabled.
	gw, diags := config.LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
`), "off.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	g := &Gateway{}
	g.cfg.Store(gw)

	g.recordGenAITurn("anthropic", "s_abc123", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 1, 2,
		[]byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		[]byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"yo"}]}`),
		time.Time{})

	if n := len(sr.Ended()); n != 0 {
		t.Fatalf("got %d spans with telemetry disabled, want 0", n)
	}
}

func TestRecordGenAITurnEnabledNoContent(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	prev := genaiTracer
	genaiTracer = tp.Tracer("test")
	defer func() { genaiTracer = prev }()

	gw, diags := config.LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
  genai_telemetry {}
}
`), "base.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	g := &Gateway{}
	g.cfg.Store(gw)

	g.recordGenAITurn("anthropic", "s_abc123", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 10, 20,
		[]byte(`{"messages":[{"role":"user","content":"hi there"}]}`),
		[]byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"secret"}]}`),
		time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	if m["gen_ai.system"].AsString() != "anthropic" {
		t.Errorf("gen_ai.system = %q", m["gen_ai.system"].AsString())
	}
	if m["gen_ai.conversation.id"].AsString() != "s_abc123" {
		t.Errorf("gen_ai.conversation.id = %q, want s_abc123", m["gen_ai.conversation.id"].AsString())
	}
	if got := m["gen_ai.usage.input_tokens"].AsInt64(); got != 10 {
		t.Errorf("input_tokens = %d, want 10", got)
	}
	// finish_reason rides the base span (no content flag needed).
	if fr := m["gen_ai.response.finish_reasons"].AsStringSlice(); len(fr) != 1 || fr[0] != "end_turn" {
		t.Errorf("finish_reasons = %v", fr)
	}
	// Content off → no events, prompt/completion text never captured.
	if n := len(spans[0].Events()); n != 0 {
		t.Errorf("got %d events with content disabled, want 0", n)
	}
}

func TestRecordGenAITurnEnabledWithContent(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	prev := genaiTracer
	genaiTracer = tp.Tracer("test")
	defer func() { genaiTracer = prev }()

	gw, diags := config.LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
  genai_telemetry { include_message_content = true }
}
`), "content.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	g := &Gateway{}
	g.cfg.Store(gw)

	g.recordGenAITurn("anthropic", "s_abc123", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 10, 20,
		[]byte(`{"system":"be terse","messages":[{"role":"user","content":"hi there"}]}`),
		[]byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"hello back"}]}`),
		time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if n := len(spans[0].Events()); n != 0 {
		t.Errorf("got %d events, want 0 (content is on attributes)", n)
	}
	m := attrMap(spans[0].Attributes())

	var sysParts []genAIPart
	if err := json.Unmarshal([]byte(m["gen_ai.system_instructions"].AsString()), &sysParts); err != nil {
		t.Fatalf("gen_ai.system_instructions: %v", err)
	}
	if len(sysParts) != 1 || sysParts[0].Content != "be terse" {
		t.Errorf("gen_ai.system_instructions = %+v", sysParts)
	}

	var input []genAIChatMessage
	if err := json.Unmarshal([]byte(m["gen_ai.input.messages"].AsString()), &input); err != nil {
		t.Fatalf("gen_ai.input.messages: %v", err)
	}
	if len(input) != 1 || input[0].Role != "user" || len(input[0].Parts) != 1 || input[0].Parts[0].Content != "hi there" {
		t.Errorf("gen_ai.input.messages = %+v", input)
	}

	var output []genAIChatMessage
	if err := json.Unmarshal([]byte(m["gen_ai.output.messages"].AsString()), &output); err != nil {
		t.Fatalf("gen_ai.output.messages: %v", err)
	}
	if len(output) != 1 || output[0].Parts[0].Content != "hello back" || output[0].FinishReason != "end_turn" {
		t.Errorf("gen_ai.output.messages = %+v", output)
	}
}
