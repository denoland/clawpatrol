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
		Provider:       "anthropic",
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
	if m["gen_ai.provider.name"].AsString() != "anthropic" {
		t.Errorf("gen_ai.provider.name = %q", m["gen_ai.provider.name"].AsString())
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
		Provider:     "anthropic",
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
	emitGenAISpan(nil, genAITurn{Provider: "anthropic", Operation: "chat"}, true)
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

	g.recordGenAITurn("anthropic", "s_abc123", "api.anthropic.com", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 1, 2,
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

	g.recordGenAITurn("anthropic", "s_abc123", "api.anthropic.com", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 10, 20,
		[]byte(`{"messages":[{"role":"user","content":"hi there"}]}`),
		[]byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"secret"}]}`),
		time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	if m["gen_ai.provider.name"].AsString() != "anthropic" {
		t.Errorf("gen_ai.provider.name = %q", m["gen_ai.provider.name"].AsString())
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

	g.recordGenAITurn("anthropic", "s_abc123", "api.anthropic.com", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 10, 20,
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

func TestParseClaudeRequestParams(t *testing.T) {
	stream := true
	temp := 0.0 // a real zero must round-trip, not read as "unset".
	topP := 0.95
	topK := int64(40)
	p := parseClaudeRequestParams([]byte(`{
		"model":"claude-3-5-sonnet-20241022",
		"max_tokens":1024,
		"stream":true,
		"temperature":0.0,
		"top_p":0.95,
		"top_k":40,
		"stop_sequences":["STOP","END"]
	}`))
	if p.Stream == nil || *p.Stream != stream {
		t.Errorf("stream = %v, want %v", p.Stream, stream)
	}
	if p.MaxTokens != 1024 {
		t.Errorf("max_tokens = %d, want 1024", p.MaxTokens)
	}
	if p.Temperature == nil || *p.Temperature != temp {
		t.Errorf("temperature = %v, want %v", p.Temperature, temp)
	}
	if p.TopP == nil || *p.TopP != topP {
		t.Errorf("top_p = %v, want %v", p.TopP, topP)
	}
	if p.TopK == nil || *p.TopK != topK {
		t.Errorf("top_k = %v, want %v", p.TopK, topK)
	}
	if !reflect.DeepEqual(p.StopSequences, []string{"STOP", "END"}) {
		t.Errorf("stop_sequences = %v", p.StopSequences)
	}

	// Absent optional fields stay unset (nil), distinguishable from zero.
	empty := parseClaudeRequestParams([]byte(`{"model":"x","max_tokens":10}`))
	if empty.Stream != nil || empty.Temperature != nil || empty.TopP != nil || empty.TopK != nil {
		t.Errorf("absent optionals should be nil, got %+v", empty)
	}
	if len(empty.StopSequences) != 0 {
		t.Errorf("stop_sequences should be empty, got %v", empty.StopSequences)
	}
}

// Tool definitions: name+type are captured even without content; the
// description and JSON schema appear only when content capture is on.
// An absent Anthropic type defaults to "function"; a built-in tool's
// declared type is kept.
func TestParseClaudeToolDefs(t *testing.T) {
	body := []byte(`{
		"model":"claude-3-5-sonnet-20241022",
		"tools":[
			{"name":"get_weather","description":"Look up the weather","input_schema":{"type":"object","properties":{"location":{"type":"string"}}}},
			{"type":"web_search_20250305","name":"web_search"}
		]
	}`)

	// Without content: name+type only, no description/parameters.
	base := parseClaudeToolDefs(body, false)
	want := []genAIToolDef{
		{Type: "function", Name: "get_weather"},
		{Type: "web_search_20250305", Name: "web_search"},
	}
	if !reflect.DeepEqual(base, want) {
		t.Errorf("base defs = %+v, want %+v", base, want)
	}

	// With content: description + JSON-schema parameters ride along.
	full := parseClaudeToolDefs(body, true)
	if len(full) != 2 {
		t.Fatalf("got %d defs, want 2", len(full))
	}
	if full[0].Description != "Look up the weather" {
		t.Errorf("description = %q", full[0].Description)
	}
	if !reflect.DeepEqual(full[0].Parameters, json.RawMessage(`{"type":"object","properties":{"location":{"type":"string"}}}`)) {
		t.Errorf("parameters = %s", full[0].Parameters)
	}
	// A tool with no schema leaves Parameters nil even under content.
	if full[1].Parameters != nil {
		t.Errorf("schemaless tool parameters = %s, want nil", full[1].Parameters)
	}

	// No tools / malformed → nil.
	if got := parseClaudeToolDefs([]byte(`{"model":"x"}`), true); got != nil {
		t.Errorf("no tools = %+v, want nil", got)
	}
	if got := parseClaudeToolDefs([]byte(`not json`), true); got != nil {
		t.Errorf("malformed = %+v, want nil", got)
	}
}

// gen_ai.tool.definitions rides the base span even with content off,
// carrying name+type but neither description nor schema.
func TestRecordGenAITurnToolDefsNoContent(t *testing.T) {
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
`), "tools.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	g := &Gateway{}
	g.cfg.Store(gw)

	g.recordGenAITurn("anthropic", "s_abc123", "api.anthropic.com", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 10, 20,
		[]byte(`{"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"get_weather","description":"secret","input_schema":{"type":"object"}}]}`),
		[]byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"ok"}]}`),
		time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	var defs []genAIToolDef
	if err := json.Unmarshal([]byte(m["gen_ai.tool.definitions"].AsString()), &defs); err != nil {
		t.Fatalf("gen_ai.tool.definitions: %v (raw %q)", err, m["gen_ai.tool.definitions"].AsString())
	}
	want := []genAIToolDef{{Type: "function", Name: "get_weather"}}
	if !reflect.DeepEqual(defs, want) {
		t.Errorf("tool defs = %+v, want %+v (description/schema must stay off without content)", defs, want)
	}
}

// With content on, gen_ai.tool.definitions also carries the description
// and JSON schema.
func TestRecordGenAITurnToolDefsWithContent(t *testing.T) {
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
`), "tools-content.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	g := &Gateway{}
	g.cfg.Store(gw)

	g.recordGenAITurn("anthropic", "s_abc123", "api.anthropic.com", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 10, 20,
		[]byte(`{"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"get_weather","description":"Look up the weather","input_schema":{"type":"object","properties":{"location":{"type":"string"}}}}]}`),
		[]byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"ok"}]}`),
		time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	var defs []genAIToolDef
	if err := json.Unmarshal([]byte(m["gen_ai.tool.definitions"].AsString()), &defs); err != nil {
		t.Fatalf("gen_ai.tool.definitions: %v", err)
	}
	if len(defs) != 1 || defs[0].Name != "get_weather" || defs[0].Type != "function" {
		t.Fatalf("tool defs = %+v", defs)
	}
	if defs[0].Description != "Look up the weather" {
		t.Errorf("description = %q", defs[0].Description)
	}
	if !reflect.DeepEqual(defs[0].Parameters, json.RawMessage(`{"type":"object","properties":{"location":{"type":"string"}}}`)) {
		t.Errorf("parameters = %s", defs[0].Parameters)
	}
}

func TestClaudeResponseMetaJSON(t *testing.T) {
	meta := claudeResponseMeta([]byte(`{
		"id":"msg_01ABC",
		"model":"claude-3-5-sonnet-20241022",
		"stop_reason":"end_turn",
		"usage":{"input_tokens":5,"output_tokens":7,"cache_read_input_tokens":100,"cache_creation_input_tokens":40}
	}`))
	if meta.ID != "msg_01ABC" {
		t.Errorf("id = %q, want msg_01ABC", meta.ID)
	}
	if meta.CacheReadTokens != 100 {
		t.Errorf("cache_read = %d, want 100", meta.CacheReadTokens)
	}
	if meta.CacheCreationTokens != 40 {
		t.Errorf("cache_creation = %d, want 40", meta.CacheCreationTokens)
	}
	if meta.ErrorType != "" {
		t.Errorf("error_type = %q, want empty", meta.ErrorType)
	}
}

func TestClaudeResponseMetaError(t *testing.T) {
	meta := claudeResponseMeta([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"slow down"}}`))
	if meta.ErrorType != "overloaded_error" {
		t.Errorf("error_type = %q, want overloaded_error", meta.ErrorType)
	}
	if meta.ID != "" {
		t.Errorf("id = %q, want empty on error", meta.ID)
	}
}

func TestClaudeResponseMetaSSE(t *testing.T) {
	body := []byte(`event: message_start
data: {"type":"message_start","message":{"id":"msg_stream1","usage":{"input_tokens":3,"cache_read_input_tokens":12,"cache_creation_input_tokens":8}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}
`)
	meta := claudeResponseMeta(body)
	if meta.ID != "msg_stream1" {
		t.Errorf("id = %q, want msg_stream1", meta.ID)
	}
	if meta.CacheReadTokens != 12 || meta.CacheCreationTokens != 8 {
		t.Errorf("cache tokens = read %d / create %d, want 12 / 8", meta.CacheReadTokens, meta.CacheCreationTokens)
	}
}

func TestClaudeResponseMetaSSEError(t *testing.T) {
	body := []byte(`event: error
data: {"type":"error","error":{"type":"overloaded_error","message":"slow down"}}
`)
	if meta := claudeResponseMeta(body); meta.ErrorType != "overloaded_error" {
		t.Errorf("error_type = %q, want overloaded_error", meta.ErrorType)
	}
}

// TestRecordGenAITurnRichAttributes drives the full recordGenAITurn path
// and asserts every newly added GenAI attribute lands on the span:
// provider name, server address/port, request sampling params, response
// id, and the Anthropic prompt-cache token breakdown.
func TestRecordGenAITurnRichAttributes(t *testing.T) {
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
`), "rich.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	g := &Gateway{}
	g.cfg.Store(gw)

	g.recordGenAITurn("anthropic", "s_abc123", "api.anthropic.com",
		"claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 10, 20,
		[]byte(`{"model":"claude-3-5-sonnet-20241022","max_tokens":2048,"stream":false,"temperature":0.7,"top_p":0.9,"top_k":50,"stop_sequences":["STOP"],"messages":[{"role":"user","content":"hi"}]}`),
		[]byte(`{"id":"msg_01XYZ","model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":256,"cache_creation_input_tokens":64},"content":[{"type":"text","text":"hello"}]}`),
		time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())

	if m["gen_ai.provider.name"].AsString() != "anthropic" {
		t.Errorf("provider.name = %q", m["gen_ai.provider.name"].AsString())
	}
	if m["server.address"].AsString() != "api.anthropic.com" {
		t.Errorf("server.address = %q", m["server.address"].AsString())
	}
	if got := m["server.port"].AsInt64(); got != 443 {
		t.Errorf("server.port = %d, want 443", got)
	}
	if got := m["gen_ai.request.max_tokens"].AsInt64(); got != 2048 {
		t.Errorf("request.max_tokens = %d, want 2048", got)
	}
	if m["gen_ai.request.stream"].AsBool() != false {
		t.Errorf("request.stream = %v, want false", m["gen_ai.request.stream"].AsBool())
	}
	if got := m["gen_ai.request.temperature"].AsFloat64(); got != 0.7 {
		t.Errorf("request.temperature = %v, want 0.7", got)
	}
	if got := m["gen_ai.request.top_p"].AsFloat64(); got != 0.9 {
		t.Errorf("request.top_p = %v, want 0.9", got)
	}
	if got := m["gen_ai.request.top_k"].AsInt64(); got != 50 {
		t.Errorf("request.top_k = %d, want 50", got)
	}
	if ss := m["gen_ai.request.stop_sequences"].AsStringSlice(); len(ss) != 1 || ss[0] != "STOP" {
		t.Errorf("request.stop_sequences = %v", ss)
	}
	if m["gen_ai.response.id"].AsString() != "msg_01XYZ" {
		t.Errorf("response.id = %q", m["gen_ai.response.id"].AsString())
	}
	if got := m["gen_ai.usage.cache_read.input_tokens"].AsInt64(); got != 256 {
		t.Errorf("cache_read.input_tokens = %d, want 256", got)
	}
	if got := m["gen_ai.usage.cache_creation.input_tokens"].AsInt64(); got != 64 {
		t.Errorf("cache_creation.input_tokens = %d, want 64", got)
	}
}
