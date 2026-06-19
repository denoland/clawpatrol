package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

// newGenAIGateway builds a Gateway whose config enables GenAI telemetry,
// optionally with message-content capture, for driving recordGenAITurn.
func newGenAIGateway(t *testing.T, content bool) *Gateway {
	t.Helper()
	block := "genai_telemetry {}"
	if content {
		block = "genai_telemetry { include_message_content = true }"
	}
	src := `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
  ` + block + `
}
`
	gw, diags := config.LoadBytes([]byte(src), "openai.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	g := &Gateway{}
	g.cfg.Store(gw)
	return g
}

func TestParseOpenAIRequestParams(t *testing.T) {
	// Chat Completions: max_tokens, stop as array, no top_k.
	p := parseOpenAIRequestParams([]byte(`{
		"model":"gpt-4o","stream":true,"max_tokens":256,
		"temperature":0.2,"top_p":0.9,"stop":["STOP","END"]
	}`))
	if p.Stream == nil || !*p.Stream {
		t.Errorf("stream = %v, want true", p.Stream)
	}
	if p.MaxTokens != 256 {
		t.Errorf("max_tokens = %d, want 256", p.MaxTokens)
	}
	if p.Temperature == nil || *p.Temperature != 0.2 {
		t.Errorf("temperature = %v, want 0.2", p.Temperature)
	}
	if p.TopP == nil || *p.TopP != 0.9 {
		t.Errorf("top_p = %v, want 0.9", p.TopP)
	}
	if !reflect.DeepEqual(p.StopSequences, []string{"STOP", "END"}) {
		t.Errorf("stop = %v", p.StopSequences)
	}

	// Responses API: max_output_tokens, stop as single string.
	r := parseOpenAIRequestParams([]byte(`{"model":"gpt-4o","max_output_tokens":99,"stop":"###"}`))
	if r.MaxTokens != 99 {
		t.Errorf("max_output_tokens → max_tokens = %d, want 99", r.MaxTokens)
	}
	if !reflect.DeepEqual(r.StopSequences, []string{"###"}) {
		t.Errorf("stop = %v, want [###]", r.StopSequences)
	}

	// max_completion_tokens (newer Chat Completions).
	c := parseOpenAIRequestParams([]byte(`{"max_completion_tokens":42}`))
	if c.MaxTokens != 42 {
		t.Errorf("max_completion_tokens → max_tokens = %d, want 42", c.MaxTokens)
	}

	// temperature 0 is a real value, not "unset".
	z := parseOpenAIRequestParams([]byte(`{"temperature":0}`))
	if z.Temperature == nil || *z.Temperature != 0 {
		t.Errorf("temperature 0 not captured: %v", z.Temperature)
	}
}

func TestParseOpenAIToolDefsChatAndResponses(t *testing.T) {
	// Chat Completions: spec nested under "function".
	chat := `{"tools":[
		{"type":"function","function":{"name":"get_weather","description":"d","parameters":{"type":"object"}}}
	]}`
	base := parseOpenAIToolDefs([]byte(chat), false)
	want := []genAIToolDef{{Type: "function", Name: "get_weather"}}
	if !reflect.DeepEqual(base, want) {
		t.Errorf("chat base = %#v, want %#v", base, want)
	}
	full := parseOpenAIToolDefs([]byte(chat), true)
	if len(full) != 1 || full[0].Description != "d" || string(full[0].Parameters) != `{"type":"object"}` {
		t.Errorf("chat full = %#v", full)
	}

	// Responses API: flat name/parameters + a built-in tool with no name.
	resp := `{"tools":[
		{"type":"function","name":"lookup","description":"x","parameters":{"a":1}},
		{"type":"web_search_preview"}
	]}`
	defs := parseOpenAIToolDefs([]byte(resp), false)
	want2 := []genAIToolDef{
		{Type: "function", Name: "lookup"},
		{Type: "web_search_preview", Name: "web_search_preview"},
	}
	if !reflect.DeepEqual(defs, want2) {
		t.Errorf("responses defs = %#v, want %#v", defs, want2)
	}

	if got := parseOpenAIToolDefs([]byte(`{"model":"x"}`), true); got != nil {
		t.Errorf("no tools should be nil, got %#v", got)
	}
}

func TestOpenAIResponseContentChatJSON(t *testing.T) {
	body := `{"id":"chatcmpl-1","model":"gpt-4o","choices":[
		{"index":0,"message":{"role":"assistant","content":"hello world"},"finish_reason":"stop"}
	],"usage":{"prompt_tokens":1,"completion_tokens":2}}`
	parts, finish := openAIResponseContent([]byte(body))
	if finish != "stop" {
		t.Errorf("finish = %q, want stop", finish)
	}
	want := []genAIPart{{Type: "text", Content: "hello world"}}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v, want %#v", parts, want)
	}
}

func TestOpenAIResponseContentChatToolCall(t *testing.T) {
	body := `{"id":"chatcmpl-2","choices":[{"index":0,"message":{"role":"assistant","content":null,
		"tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{\"x\":1}"}}]},
		"finish_reason":"tool_calls"}]}`
	parts, finish := openAIResponseContent([]byte(body))
	if finish != "tool_calls" {
		t.Errorf("finish = %q", finish)
	}
	want := []genAIPart{{Type: "tool_call", ID: "call_1", Name: "f", Arguments: json.RawMessage(`{"x":1}`)}}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v, want %#v", parts, want)
	}
}

func TestOpenAIResponseContentChatSSE(t *testing.T) {
	body := "data: {\"id\":\"chatcmpl-3\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-3\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-3\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	parts, finish := openAIResponseContent([]byte(body))
	if finish != "stop" {
		t.Errorf("finish = %q, want stop", finish)
	}
	want := []genAIPart{{Type: "text", Content: "Hello"}}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v, want %#v", parts, want)
	}
}

func TestOpenAIResponseContentChatSSEToolCall(t *testing.T) {
	body := "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_9\",\"function\":{\"name\":\"f\",\"arguments\":\"{\\\"a\\\":\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"1}\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n"
	parts, finish := openAIResponseContent([]byte(body))
	if finish != "tool_calls" {
		t.Errorf("finish = %q", finish)
	}
	want := []genAIPart{{Type: "tool_call", ID: "call_9", Name: "f", Arguments: json.RawMessage(`{"a":1}`)}}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v, want %#v", parts, want)
	}
}

func TestOpenAIResponseContentResponsesJSON(t *testing.T) {
	body := `{"id":"resp_1","object":"response","model":"gpt-4o","status":"completed","output":[
		{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi there"}]},
		{"type":"function_call","call_id":"fc_1","name":"f","arguments":"{\"q\":\"x\"}"}
	],"usage":{"input_tokens":3,"output_tokens":4}}`
	parts, finish := openAIResponseContent([]byte(body))
	if finish != "completed" {
		t.Errorf("finish = %q, want completed", finish)
	}
	want := []genAIPart{
		{Type: "text", Content: "hi there"},
		{Type: "tool_call", ID: "fc_1", Name: "f", Arguments: json.RawMessage(`{"q":"x"}`)},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v, want %#v", parts, want)
	}
}

func TestOpenAIResponseContentResponsesIncomplete(t *testing.T) {
	body := `{"id":"resp_2","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},
		"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"partial"}]}]}`
	_, finish := openAIResponseContent([]byte(body))
	if finish != "max_output_tokens" {
		t.Errorf("finish = %q, want max_output_tokens", finish)
	}
}

func TestOpenAIResponseContentResponsesSSE(t *testing.T) {
	// Responses streams end with a terminal event carrying the full
	// response object; the content parser reads it like a full body.
	body := "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_3\",\"status\":\"in_progress\",\"output\":[]}}\n\n" +
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"par\"}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_3\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"done\"}]}]}}\n\n"
	parts, finish := openAIResponseContent([]byte(body))
	if finish != "completed" {
		t.Errorf("finish = %q, want completed", finish)
	}
	want := []genAIPart{{Type: "text", Content: "done"}}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v, want %#v", parts, want)
	}
}

func TestOpenAIResponseMeta(t *testing.T) {
	if id, et := openAIResponseMeta([]byte(`{"id":"chatcmpl-x","choices":[]}`)); id != "chatcmpl-x" || et != "" {
		t.Errorf("chat meta = %q/%q", id, et)
	}
	if id, et := openAIResponseMeta([]byte(`{"id":"resp_x","object":"response"}`)); id != "resp_x" || et != "" {
		t.Errorf("responses meta = %q/%q", id, et)
	}
	// HTTP error body.
	if _, et := openAIResponseMeta([]byte(`{"error":{"message":"bad","type":"invalid_request_error"}}`)); et != "invalid_request_error" {
		t.Errorf("error type = %q", et)
	}
	// SSE: chat chunk id.
	sse := "data: {\"id\":\"chatcmpl-s\",\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n"
	if id, _ := openAIResponseMeta([]byte(sse)); id != "chatcmpl-s" {
		t.Errorf("sse id = %q", id)
	}
}

func TestOpenAIContentMessagesChat(t *testing.T) {
	body := `{"messages":[
		{"role":"system","content":"be terse"},
		{"role":"user","content":"hi"},
		{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"k\":1}"}}]},
		{"role":"tool","tool_call_id":"c1","content":"42"}
	]}`
	msgs := openAIContentMessages([]byte(body))
	want := []genAIMessage{
		{Role: "system", Parts: []genAIPart{{Type: "text", Content: "be terse"}}},
		{Role: "user", Parts: []genAIPart{{Type: "text", Content: "hi"}}},
		{Role: "assistant", Parts: []genAIPart{{Type: "tool_call", ID: "c1", Name: "f", Arguments: json.RawMessage(`{"k":1}`)}}},
		{Role: "tool", Parts: []genAIPart{{Type: "tool_call_response", ID: "c1", Response: json.RawMessage(`"42"`)}}},
	}
	if !reflect.DeepEqual(msgs, want) {
		t.Errorf("msgs = %#v\nwant %#v", msgs, want)
	}
}

func TestOpenAIContentMessagesResponses(t *testing.T) {
	body := `{"instructions":"be terse","input":[
		{"role":"user","content":[{"type":"input_text","text":"hi"}]},
		{"type":"function_call","call_id":"fc1","name":"f","arguments":"{\"k\":1}"},
		{"type":"function_call_output","call_id":"fc1","output":"ok"}
	]}`
	msgs := openAIContentMessages([]byte(body))
	want := []genAIMessage{
		{Role: "system", Parts: []genAIPart{{Type: "text", Content: "be terse"}}},
		{Role: "user", Parts: []genAIPart{{Type: "text", Content: "hi"}}},
		{Role: "assistant", Parts: []genAIPart{{Type: "tool_call", ID: "fc1", Name: "f", Arguments: json.RawMessage(`{"k":1}`)}}},
		{Role: "tool", Parts: []genAIPart{{Type: "tool_call_response", ID: "fc1", Response: json.RawMessage(`"ok"`)}}},
	}
	if !reflect.DeepEqual(msgs, want) {
		t.Errorf("msgs = %#v\nwant %#v", msgs, want)
	}

	// Responses `input` as a plain string → single user message.
	one := openAIContentMessages([]byte(`{"input":"just text"}`))
	wantOne := []genAIMessage{{Role: "user", Parts: []genAIPart{{Type: "text", Content: "just text"}}}}
	if !reflect.DeepEqual(one, wantOne) {
		t.Errorf("string input = %#v, want %#v", one, wantOne)
	}
}

// TestRecordGenAITurnOpenAINoContent drives the full path for an OpenAI
// Chat Completions turn: provider/model/usage/finish/tooldefs ride the
// base span, no prompt/completion text without the content opt-in.
func TestRecordGenAITurnOpenAINoContent(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	prev := genaiTracer
	genaiTracer = tp.Tracer("test")
	defer func() { genaiTracer = prev }()

	g := newGenAIGateway(t, false)
	req := `{"model":"gpt-4o","temperature":0.5,"max_tokens":100,
		"tools":[{"type":"function","function":{"name":"f","description":"secret","parameters":{"p":1}}}],
		"messages":[{"role":"user","content":"secret prompt"}]}`
	resp := `{"id":"chatcmpl-1","model":"gpt-4o","choices":[{"index":0,
		"message":{"role":"assistant","content":"secret completion"},"finish_reason":"stop"}],
		"usage":{"prompt_tokens":10,"completion_tokens":20}}`
	g.recordGenAITurn("openai", "s_oai", "api.openai.com", "gpt-4o", "gpt-4o", 10, 20,
		[]byte(req), []byte(resp), time.Time{}, "")

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	if m["gen_ai.provider.name"].AsString() != "openai" {
		t.Errorf("provider = %q", m["gen_ai.provider.name"].AsString())
	}
	if m["gen_ai.request.model"].AsString() != "gpt-4o" {
		t.Errorf("model = %q", m["gen_ai.request.model"].AsString())
	}
	if m["gen_ai.response.id"].AsString() != "chatcmpl-1" {
		t.Errorf("response.id = %q", m["gen_ai.response.id"].AsString())
	}
	if got := m["gen_ai.usage.input_tokens"].AsInt64(); got != 10 {
		t.Errorf("input_tokens = %d", got)
	}
	if got := m["gen_ai.request.max_tokens"].AsInt64(); got != 100 {
		t.Errorf("max_tokens = %d", got)
	}
	if m["gen_ai.request.temperature"].AsFloat64() != 0.5 {
		t.Errorf("temperature = %v", m["gen_ai.request.temperature"].AsFloat64())
	}
	if fr := m["gen_ai.response.finish_reasons"].AsStringSlice(); len(fr) != 1 || fr[0] != "stop" {
		t.Errorf("finish_reasons = %v", fr)
	}
	// Tool name+type ride the base span; schema must NOT (content off).
	var defs []genAIToolDef
	if err := json.Unmarshal([]byte(m["gen_ai.tool.definitions"].AsString()), &defs); err != nil {
		t.Fatalf("tool.definitions: %v", err)
	}
	if len(defs) != 1 || defs[0].Name != "f" || defs[0].Description != "" || defs[0].Parameters != nil {
		t.Errorf("tool defs leaked schema with content off: %#v", defs)
	}
	// No content attributes when content capture is off.
	if _, ok := m["gen_ai.input.messages"]; ok {
		t.Error("input.messages present with content off")
	}
}

// TestRecordGenAITurnOpenAIWithContent verifies prompt/completion content
// and tool schemas are attached under the content opt-in.
func TestRecordGenAITurnOpenAIWithContent(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	prev := genaiTracer
	genaiTracer = tp.Tracer("test")
	defer func() { genaiTracer = prev }()

	g := newGenAIGateway(t, true)
	req := `{"model":"gpt-4o",
		"tools":[{"type":"function","function":{"name":"f","description":"the desc","parameters":{"p":1}}}],
		"messages":[{"role":"system","content":"be terse"},{"role":"user","content":"hello there"}]}`
	resp := `{"id":"chatcmpl-2","model":"gpt-4o","choices":[{"index":0,
		"message":{"role":"assistant","content":"general kenobi"},"finish_reason":"stop"}],
		"usage":{"prompt_tokens":1,"completion_tokens":2}}`
	g.recordGenAITurn("openai", "s_oai", "api.openai.com", "gpt-4o", "gpt-4o", 1, 2,
		[]byte(req), []byte(resp), time.Time{}, "")

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())

	var sysParts []genAIPart
	if err := json.Unmarshal([]byte(m["gen_ai.system_instructions"].AsString()), &sysParts); err != nil {
		t.Fatalf("system_instructions: %v", err)
	}
	if !reflect.DeepEqual(sysParts, []genAIPart{{Type: "text", Content: "be terse"}}) {
		t.Errorf("system_instructions = %#v", sysParts)
	}

	var input []genAIChatMessage
	if err := json.Unmarshal([]byte(m["gen_ai.input.messages"].AsString()), &input); err != nil {
		t.Fatalf("input.messages: %v", err)
	}
	if len(input) != 1 || input[0].Role != "user" || len(input[0].Parts) != 1 || input[0].Parts[0].Content != "hello there" {
		t.Errorf("input.messages = %#v", input)
	}

	var output []genAIChatMessage
	if err := json.Unmarshal([]byte(m["gen_ai.output.messages"].AsString()), &output); err != nil {
		t.Fatalf("output.messages: %v", err)
	}
	if len(output) != 1 || output[0].Parts[0].Content != "general kenobi" || output[0].FinishReason != "stop" {
		t.Errorf("output.messages = %#v", output)
	}

	// Tool schema present under content opt-in.
	var defs []genAIToolDef
	if err := json.Unmarshal([]byte(m["gen_ai.tool.definitions"].AsString()), &defs); err != nil {
		t.Fatalf("tool.definitions: %v", err)
	}
	if len(defs) != 1 || defs[0].Description != "the desc" || string(defs[0].Parameters) != `{"p":1}` {
		t.Errorf("tool defs = %#v", defs)
	}
}

// TestTrackLLMUsageCodexModelFromRequest covers the Codex
// /backend-api/codex/responses path: its SSE response body carries
// neither the model (it rides the OpenAI-Model response header) nor
// token usage, so sourcing the model only from the response left
// recordGenAITurn's guard unsatisfied and the GenAI span was dropped.
// The model must fall back to the request body so the turn is recorded.
func TestTrackLLMUsageCodexModelFromRequest(t *testing.T) {
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
	g.agents = NewAgentRegistry()

	// Request carries the model; the SSE response has no model and no
	// parseable usage — exactly the shape that produced no span before.
	reqBody := []byte(`{"model":"gpt-5-codex","input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}`)
	respBody := []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n")

	g.trackLLMUsage(nil, "codex_ws_usage", "chatgpt.com",
		"/backend-api/codex/responses", reqBody, respBody, "sess-1", time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1 (codex turn dropped — model not sourced from request)", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	if got := m["gen_ai.provider.name"].AsString(); got != "openai" {
		t.Errorf("gen_ai.provider.name = %q, want openai", got)
	}
	if got := m["gen_ai.request.model"].AsString(); got != "gpt-5-codex" {
		t.Errorf("gen_ai.request.model = %q, want gpt-5-codex", got)
	}
}

// TestCodexWSTurnAssembly covers the production Codex transport: the
// /backend-api/codex/responses request is a WebSocket upgrade, so the turn
// arrives as separate frames (client→server request envelope, then a
// server→client response.completed frame) routed through handleWSUpgrade —
// the HTTP-path trackLLMUsage never fires. The codexWSTurn assembler must
// pair the frames and produce a completion that records a correct gen_ai
// span with model, usage, and (under the content opt-in) prompt/output.
func TestCodexWSTurnAssembly(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	prev := genaiTracer
	genaiTracer = tp.Tracer("test")
	defer func() { genaiTracer = prev }()

	g := newGenAIGateway(t, true)

	// client→server: the full request envelope (prompt + model + tools).
	reqEnvelope := []byte(`{"model":"gpt-5-codex","instructions":"be terse",` +
		`"tools":[{"type":"function","name":"shell","description":"run a shell command","parameters":{"p":1}}],` +
		`"input":[{"role":"user","content":[{"type":"input_text","text":"list files"}]}]}`)
	// server→client: response.completed carries usage + output nested under
	// `response` — no model and no token usage live at the frame top level,
	// which is why a single-frame parse dropped the span before.
	completed := []byte(`{"type":"response.completed","response":{` +
		`"id":"resp_ws_1","model":"gpt-5-codex-2026","status":"completed",` +
		`"usage":{"input_tokens":11,"output_tokens":7},` +
		`"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}}`)

	turn := &codexWSTurn{}
	turn.observeRequest(reqEnvelope, time.Time{})
	// A non-terminal server frame must not emit anything.
	if c := turn.observeResponse([]byte(`{"type":"response.created","response":{"id":"resp_ws_1"}}`)); c != nil {
		t.Fatalf("response.created should not produce a completion")
	}
	c := turn.observeResponse(completed)
	if c == nil {
		t.Fatal("response.completed produced no completion (WS turn dropped)")
	}
	g.recordGenAITurn("openai", "s_ws", "chatgpt.com", c.reqModel, c.respModel,
		c.in, c.out, c.reqBody, c.respBody, c.start, "100.64.0.1")

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	if got := m["gen_ai.provider.name"].AsString(); got != "openai" {
		t.Errorf("gen_ai.provider.name = %q, want openai", got)
	}
	if got := m["gen_ai.request.model"].AsString(); got != "gpt-5-codex" {
		t.Errorf("gen_ai.request.model = %q, want gpt-5-codex", got)
	}
	if got := m["gen_ai.response.model"].AsString(); got != "gpt-5-codex-2026" {
		t.Errorf("gen_ai.response.model = %q, want gpt-5-codex-2026", got)
	}
	if got := m["gen_ai.response.id"].AsString(); got != "resp_ws_1" {
		t.Errorf("gen_ai.response.id = %q, want resp_ws_1", got)
	}
	if got := m["gen_ai.usage.input_tokens"].AsInt64(); got != 11 {
		t.Errorf("input_tokens = %d, want 11", got)
	}
	if got := m["gen_ai.usage.output_tokens"].AsInt64(); got != 7 {
		t.Errorf("output_tokens = %d, want 7", got)
	}
	if fr := m["gen_ai.response.finish_reasons"].AsStringSlice(); len(fr) != 1 || fr[0] != "completed" {
		t.Errorf("finish_reasons = %v, want [completed]", fr)
	}
	// Content opt-in: the user prompt and assistant output ride the span.
	var input []genAIChatMessage
	if err := json.Unmarshal([]byte(m["gen_ai.input.messages"].AsString()), &input); err != nil {
		t.Fatalf("input.messages: %v", err)
	}
	if len(input) != 1 || input[0].Role != "user" || len(input[0].Parts) != 1 || input[0].Parts[0].Content != "list files" {
		t.Errorf("input.messages = %#v", input)
	}
	var output []genAIChatMessage
	if err := json.Unmarshal([]byte(m["gen_ai.output.messages"].AsString()), &output); err != nil {
		t.Fatalf("output.messages: %v", err)
	}
	if len(output) != 1 || len(output[0].Parts) != 1 || output[0].Parts[0].Content != "ok" {
		t.Errorf("output.messages = %#v", output)
	}
	// Tool definition (name+type) rides the span.
	var defs []genAIToolDef
	if err := json.Unmarshal([]byte(m["gen_ai.tool.definitions"].AsString()), &defs); err != nil {
		t.Fatalf("tool.definitions: %v", err)
	}
	if len(defs) != 1 || defs[0].Name != "shell" {
		t.Errorf("tool defs = %#v", defs)
	}
}

// TestCodexWSTurnFallsBackToResponseModel verifies a completion seen with no
// preceding request frame (e.g. connection observed mid-turn) still records a
// span, sourcing the model from the response.
func TestCodexWSTurnFallsBackToResponseModel(t *testing.T) {
	turn := &codexWSTurn{}
	c := turn.observeResponse([]byte(`{"type":"response.completed","response":{` +
		`"id":"r1","model":"gpt-5-codex","usage":{"input_tokens":3,"output_tokens":2}}}`))
	if c == nil {
		t.Fatal("completion dropped when no request frame was seen")
	}
	if c.reqBody != nil {
		t.Errorf("reqBody = %q, want nil", c.reqBody)
	}
	if c.reqModel != "gpt-5-codex" {
		t.Errorf("reqModel = %q, want gpt-5-codex (response fallback)", c.reqModel)
	}
	if c.in != 3 || c.out != 2 {
		t.Errorf("usage in/out = %d/%d, want 3/2", c.in, c.out)
	}
}

// TestOpenAIResponseContentCodexSSEEmptyTerminal mirrors the real Codex
// /backend-api/codex/responses stream: the terminal response.completed
// frame carries output:[] (empty), while the finished output items —
// reasoning + assistant message — ride per-item response.output_item.done
// events. The reconstruction must fall back to those items so the output is
// not lost. Payload shapes are taken verbatim from a captured Codex turn.
func TestOpenAIResponseContentCodexSSEEmptyTerminal(t *testing.T) {
	body := "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_x\",\"status\":\"in_progress\",\"output\":[]}}\n\n" +
		"data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"reasoning\",\"summary\":[{\"type\":\"summary_text\",\"text\":\"thinking\"}]}}\n\n" +
		"data: {\"type\":\"response.output_text.delta\",\"content_index\":0,\"delta\":\"ban\",\"output_index\":1}\n\n" +
		"data: {\"type\":\"response.output_text.done\",\"content_index\":0,\"output_index\":1,\"text\":\"banana\"}\n\n" +
		"data: {\"type\":\"response.output_item.done\",\"output_index\":1,\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"banana\"}]}}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_x\",\"status\":\"completed\",\"output\":[],\"usage\":{\"output_tokens\":5}}}\n\n"
	parts, finish := openAIResponseContent([]byte(body))
	if finish != "completed" {
		t.Errorf("finish = %q, want completed", finish)
	}
	want := []genAIPart{
		{Type: "reasoning", Content: "thinking"},
		{Type: "text", Content: "banana"},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v, want %#v", parts, want)
	}
}

// TestOpenAIResponseSSECodexTruncated covers a Codex stream cut off before
// the terminal frame: the output items seen so far must still reconstruct
// the output rather than yielding nothing.
func TestOpenAIResponseSSECodexTruncated(t *testing.T) {
	body := "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_y\",\"status\":\"in_progress\",\"output\":[]}}\n\n" +
		"data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}]}}\n\n"
	parts, _ := openAIResponseContent([]byte(body))
	want := []genAIPart{{Type: "text", Content: "hi"}}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("parts = %#v, want %#v", parts, want)
	}
}

// TestCodexWSTurnOutputFromItemDoneFrames covers the production Codex WS
// transport with realistic frames: the assistant output rides a
// response.output_item.done frame and the terminal response.completed frame
// carries output:[] (empty) plus usage. The assembler must splice the
// per-item output into the response so the recorded span carries
// gen_ai.output.messages.
func TestCodexWSTurnOutputFromItemDoneFrames(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	prev := genaiTracer
	genaiTracer = tp.Tracer("test")
	defer func() { genaiTracer = prev }()

	g := newGenAIGateway(t, true)

	reqEnvelope := []byte(`{"model":"gpt-5-codex",` +
		`"input":[{"role":"user","content":[{"type":"input_text","text":"say banana"}]}]}`)
	// Real Codex frame ordering: a finished output item, then a terminal
	// response.completed whose output is empty.
	itemDone := []byte(`{"type":"response.output_item.done","output_index":0,"item":{` +
		`"id":"msg_1","type":"message","status":"completed","role":"assistant",` +
		`"content":[{"type":"output_text","text":"banana"}]}}`)
	completed := []byte(`{"type":"response.completed","response":{` +
		`"id":"resp_ws_2","model":"gpt-5-codex","status":"completed",` +
		`"usage":{"input_tokens":24950,"output_tokens":5},"output":[]}}`)

	turn := &codexWSTurn{}
	turn.observeRequest(reqEnvelope, time.Time{})
	if c := turn.observeResponse(itemDone); c != nil {
		t.Fatalf("response.output_item.done should not produce a completion")
	}
	c := turn.observeResponse(completed)
	if c == nil {
		t.Fatal("response.completed produced no completion (WS turn dropped)")
	}
	g.recordGenAITurn("openai", "s_ws", "chatgpt.com", c.reqModel, c.respModel,
		c.in, c.out, c.reqBody, c.respBody, c.start, "100.64.0.1")

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	if got := m["gen_ai.usage.output_tokens"].AsInt64(); got != 5 {
		t.Errorf("output_tokens = %d, want 5", got)
	}
	var output []genAIChatMessage
	raw := m["gen_ai.output.messages"].AsString()
	if raw == "" {
		t.Fatal("gen_ai.output.messages missing — output not spliced from item.done frame")
	}
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		t.Fatalf("output.messages: %v (raw %q)", err, raw)
	}
	if len(output) != 1 || output[0].Role != "assistant" ||
		len(output[0].Parts) != 1 || output[0].Parts[0].Content != "banana" {
		t.Errorf("output.messages = %#v", output)
	}
}

// TestCodexSpliceOutputPrefersExisting verifies the splice is a no-op when
// the terminal response already carries a populated output (e.g. the
// standard OpenAI Responses API, or a future Codex change) — the verbatim
// response is returned and the accumulated items are ignored.
func TestCodexSpliceOutputPrefersExisting(t *testing.T) {
	response := json.RawMessage(`{"id":"r","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"real"}]}]}`)
	items := map[int]json.RawMessage{0: json.RawMessage(`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"stale"}]}`)}
	got := codexSpliceOutput(response, items, []int{0})
	if !reflect.DeepEqual([]byte(response), got) {
		t.Errorf("splice mutated a populated response: %s", got)
	}
}
