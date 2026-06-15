package main

import (
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
		System:        "anthropic",
		Operation:     "chat",
		RequestModel:  "claude-3-5-sonnet-20241022",
		ResponseModel: "claude-3-5-sonnet-20241022",
		InputTokens:   42,
		OutputTokens:  17,
		FinishReason:  "end_turn",
		Messages:      []genAIMessage{{Role: "user", Content: "secret prompt"}},
		Completion:    "secret completion",
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
			{Role: "system", Content: "you are helpful"},
			{Role: "user", Content: "hello there"},
		},
		Completion: "general kenobi",
	}
	emitGenAISpan(tp.Tracer("test"), turn, true)

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	events := spans[0].Events()
	if len(events) != 3 { // system message, user message, choice
		t.Fatalf("got %d events, want 3: %+v", len(events), events)
	}
	if events[0].Name != "gen_ai.system.message" {
		t.Errorf("event[0].Name = %q", events[0].Name)
	}
	if events[1].Name != "gen_ai.user.message" {
		t.Errorf("event[1].Name = %q", events[1].Name)
	}
	if got := attrMap(events[1].Attributes)["content"].AsString(); got != "hello there" {
		t.Errorf("user message content = %q", got)
	}
	if events[2].Name != "gen_ai.choice" {
		t.Errorf("event[2].Name = %q", events[2].Name)
	}
	choice := attrMap(events[2].Attributes)
	if got := choice["content"].AsString(); got != "general kenobi" {
		t.Errorf("choice content = %q", got)
	}
	if got := choice["finish_reason"].AsString(); got != "end_turn" {
		t.Errorf("choice finish_reason = %q", got)
	}
}

func TestEmitGenAISpanNilTracerNoPanic(t *testing.T) {
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
		{Role: "system", Content: "be terse"},
		{Role: "user", Content: "first"},
		{Role: "assistant", Content: "reply"},
		{Role: "user", Content: "second"},
	}
	if len(msgs) != len(want) {
		t.Fatalf("got %d messages, want %d: %+v", len(msgs), len(want), msgs)
	}
	for i := range want {
		if msgs[i] != want[i] {
			t.Errorf("message[%d] = %+v, want %+v", i, msgs[i], want[i])
		}
	}
}

func TestClaudeResponseContentJSON(t *testing.T) {
	body := []byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"line one"},{"type":"text","text":"line two"}]}`)
	text, finish := claudeResponseContent(body)
	if text != "line one\nline two" {
		t.Errorf("text = %q", text)
	}
	if finish != "end_turn" {
		t.Errorf("finish = %q", finish)
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
	text, finish := claudeResponseContent(body)
	if text != "Hello, world" {
		t.Errorf("text = %q, want %q", text, "Hello, world")
	}
	if finish != "end_turn" {
		t.Errorf("finish = %q, want end_turn", finish)
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

	g.recordGenAITurn("anthropic", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 1, 2,
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

	g.recordGenAITurn("anthropic", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 10, 20,
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

	g.recordGenAITurn("anthropic", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022", 10, 20,
		[]byte(`{"system":"be terse","messages":[{"role":"user","content":"hi there"}]}`),
		[]byte(`{"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","content":[{"type":"text","text":"hello back"}]}`),
		time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	events := spans[0].Events()
	if len(events) != 3 { // system + user message + choice
		t.Fatalf("got %d events, want 3: %+v", len(events), events)
	}
	if got := attrMap(events[2].Attributes)["content"].AsString(); got != "hello back" {
		t.Errorf("completion content = %q", got)
	}
}
