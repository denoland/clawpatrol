// OpenTelemetry GenAI semantic-convention export for intercepted LLM
// turns. Targets the GenAI semantic conventions
// (https://opentelemetry.io/docs/specs/semconv/gen-ai/): one span per
// model invocation carrying gen_ai.* attributes (provider name,
// conversation id, server address, models, request sampling params,
// token usage incl. the Anthropic cache-token breakdown, response id,
// finish reason, error type) and — only when the operator
// opts in — the prompt/completion message content as the
// gen_ai.input.messages / gen_ai.output.messages /
// gen_ai.system_instructions span attributes. Content blocks of every
// kind are mapped to GenAI message parts (text, reasoning, tool_call,
// tool_call_response, plus a generic fallback), not just text.
//
// The request's tool catalogue rides gen_ai.tool.definitions: each
// tool's name and type are on the base span, while its description and
// JSON-schema parameters are attached only under the content opt-in
// (a schema can be large and may carry proprietary detail).
//
// Opt-in is two independent switches (internal/config GenAITelemetry):
// the `genai_telemetry {}` block presence enables the attribute span;
// `include_message_content` additionally attaches the message-content
// attributes. Disabled is the zero-overhead default — recordGenAITurn
// returns before parsing anything.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// genAIMessage is one input message (system/user/assistant/tool)
// captured for the GenAI content convention, carrying its content parts
// (text, tool_call, tool_call_response, reasoning, …).
type genAIMessage struct {
	Role  string
	Parts []genAIPart
}

// genAIPart is a single content part within a GenAI message, following
// the GenAI message-part conventions. The fields are a superset across
// the part types we emit; `omitempty` keeps each serialized part to the
// keys its type actually defines:
//
//   - text               → {type, content}
//   - reasoning          → {type, content}            (Anthropic "thinking")
//   - tool_call          → {type, id, name, arguments}
//   - tool_call_response → {type, id, response}
//   - any other block    → {type}                     (generic part)
//
// Mapping every Anthropic block to one of these — rather than flattening
// to text and dropping the rest — means tool calls, tool results, and
// reasoning are captured too.
type genAIPart struct {
	Type      string          `json:"type"`
	Content   string          `json:"content,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Response  json.RawMessage `json:"response,omitempty"`
}

// genAIChatMessage is one message in the gen_ai.input.messages /
// gen_ai.output.messages span attributes: a role, its content parts,
// and (output messages only) the finish reason for that message.
type genAIChatMessage struct {
	Role         string      `json:"role"`
	Parts        []genAIPart `json:"parts"`
	FinishReason string      `json:"finish_reason,omitempty"`
}

// genAIToolDef is one entry in the gen_ai.tool.definitions span
// attribute: a tool the model was offered for this turn. Type and Name
// ride the base span; Description and Parameters (the tool's JSON
// schema) are populated only when message-content capture is opted in,
// since a schema can be large and may expose proprietary detail.
// `omitempty` keeps a base-span entry to just {type, name}.
type genAIToolDef struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// genAITurn is one intercepted LLM request/response mapped to OTel
// GenAI semantic-convention terms.
type genAITurn struct {
	Provider       string // gen_ai.provider.name: "anthropic" | "openai" (replaces the removed gen_ai.system)
	Operation      string // gen_ai.operation.name: "chat"
	ConversationID string // gen_ai.conversation.id: correlates a multi-turn session
	RequestModel   string // gen_ai.request.model
	ResponseModel  string // gen_ai.response.model
	ResponseID     string // gen_ai.response.id
	InputTokens    int64  // gen_ai.usage.input_tokens
	OutputTokens   int64  // gen_ai.usage.output_tokens
	FinishReason   string // gen_ai.response.finish_reasons[0]
	ErrorType      string // error.type: set when the turn carried a provider error

	// Anthropic-specific prompt-cache token breakdown. Both are already
	// folded into InputTokens for billing; the GenAI convention also
	// surfaces them separately as gen_ai.usage.cache_read.input_tokens /
	// gen_ai.usage.cache_creation.input_tokens.
	CacheReadTokens     int64
	CacheCreationTokens int64

	// ServerAddress / ServerPort identify the upstream the turn went to
	// (server.address / server.port). Port is 0 when unknown.
	ServerAddress string
	ServerPort    int

	// Request sampling parameters (gen_ai.request.*). Pointers/zero-checks
	// distinguish "not set in the request" from a real zero value
	// (temperature 0 is valid and common).
	Stream        *bool    // gen_ai.request.stream
	MaxTokens     int64    // gen_ai.request.max_tokens (0 → unset)
	Temperature   *float64 // gen_ai.request.temperature
	TopP          *float64 // gen_ai.request.top_p
	TopK          *int64   // gen_ai.request.top_k
	StopSequences []string // gen_ai.request.stop_sequences

	// Tools is the request's tool catalogue (gen_ai.tool.definitions).
	// Name+type are always populated; the schema/description ride only
	// the content opt-in. Empty when the request offered no tools.
	Tools []genAIToolDef

	// Start, when non-zero, sets the span start time so its duration
	// reflects the real upstream round-trip latency. Zero → span is
	// stamped at emission time.
	Start time.Time

	// Messages and Output populate the content attributes; filled only
	// when message-content capture is enabled. Messages are the input
	// (request) messages; Output is the assistant response's parts.
	Messages []genAIMessage
	Output   []genAIPart
}

// emitGenAISpan records one GenAI span on the provided tracer. When
// includeContent is true, message content is attached as the
// gen_ai.input.messages / gen_ai.output.messages /
// gen_ai.system_instructions span attributes per the GenAI semantic
// conventions. A free function (not a method) so tests can drive it
// with an in-memory tracer.
func emitGenAISpan(tracer trace.Tracer, t genAITurn, includeContent bool) {
	if tracer == nil {
		return
	}
	// Span name convention: "{operation} {request.model}".
	name := t.Operation
	if t.RequestModel != "" {
		name = t.Operation + " " + t.RequestModel
	}
	startOpts := []trace.SpanStartOption{trace.WithSpanKind(trace.SpanKindClient)}
	if !t.Start.IsZero() {
		startOpts = append(startOpts, trace.WithTimestamp(t.Start))
	}
	_, span := tracer.Start(context.Background(), name, startOpts...)

	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.provider.name", t.Provider),
		attribute.String("gen_ai.operation.name", t.Operation),
	}
	if t.ConversationID != "" {
		attrs = append(attrs, attribute.String("gen_ai.conversation.id", t.ConversationID))
	}
	if t.ServerAddress != "" {
		attrs = append(attrs, attribute.String("server.address", t.ServerAddress))
	}
	if t.ServerPort > 0 {
		attrs = append(attrs, attribute.Int("server.port", t.ServerPort))
	}
	if t.RequestModel != "" {
		attrs = append(attrs, attribute.String("gen_ai.request.model", t.RequestModel))
	}
	if t.Stream != nil {
		attrs = append(attrs, attribute.Bool("gen_ai.request.stream", *t.Stream))
	}
	if t.MaxTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.request.max_tokens", t.MaxTokens))
	}
	if t.Temperature != nil {
		attrs = append(attrs, attribute.Float64("gen_ai.request.temperature", *t.Temperature))
	}
	if t.TopP != nil {
		attrs = append(attrs, attribute.Float64("gen_ai.request.top_p", *t.TopP))
	}
	if t.TopK != nil {
		attrs = append(attrs, attribute.Int64("gen_ai.request.top_k", *t.TopK))
	}
	if len(t.StopSequences) > 0 {
		attrs = append(attrs, attribute.StringSlice("gen_ai.request.stop_sequences", t.StopSequences))
	}
	// Tool definitions ride the base span (name+type always; schema and
	// description only when content capture filled them in). The value is
	// JSON-serialized since OTel attribute values are primitives.
	if len(t.Tools) > 0 {
		if js, err := json.Marshal(t.Tools); err == nil {
			attrs = append(attrs, attribute.String("gen_ai.tool.definitions", string(js)))
		}
	}
	if t.ResponseModel != "" {
		attrs = append(attrs, attribute.String("gen_ai.response.model", t.ResponseModel))
	}
	if t.ResponseID != "" {
		attrs = append(attrs, attribute.String("gen_ai.response.id", t.ResponseID))
	}
	if t.InputTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.usage.input_tokens", t.InputTokens))
	}
	if t.OutputTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.usage.output_tokens", t.OutputTokens))
	}
	if t.CacheReadTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.usage.cache_read.input_tokens", t.CacheReadTokens))
	}
	if t.CacheCreationTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.usage.cache_creation.input_tokens", t.CacheCreationTokens))
	}
	if t.FinishReason != "" {
		attrs = append(attrs, attribute.StringSlice("gen_ai.response.finish_reasons", []string{t.FinishReason}))
	}
	if t.ErrorType != "" {
		attrs = append(attrs, attribute.String("error.type", t.ErrorType))
	}
	span.SetAttributes(attrs...)

	if includeContent {
		if content := genAIContentAttrs(t); len(content) > 0 {
			span.SetAttributes(content...)
		}
	}
	span.End()
}

// genAIContentAttrs builds the message-content span attributes for one
// turn following the GenAI semantic conventions:
//
//   - gen_ai.system_instructions — system messages, as content parts
//   - gen_ai.input.messages      — the user/assistant input messages
//   - gen_ai.output.messages     — the assistant completion + finish reason
//
// Each value is JSON-serialized because OTel attribute values are
// primitives; the convention models these fields as structured data
// carried as a JSON string. Returns nil when there is no content.
func genAIContentAttrs(t genAITurn) []attribute.KeyValue {
	var sysParts []genAIPart
	var input []genAIChatMessage
	for _, m := range t.Messages {
		if len(m.Parts) == 0 {
			continue
		}
		if m.Role == "system" {
			sysParts = append(sysParts, m.Parts...)
			continue
		}
		role := m.Role
		if role == "" {
			role = "user"
		}
		input = append(input, genAIChatMessage{Role: role, Parts: m.Parts})
	}

	var attrs []attribute.KeyValue
	if len(sysParts) > 0 {
		if js, err := json.Marshal(sysParts); err == nil {
			attrs = append(attrs, attribute.String("gen_ai.system_instructions", string(js)))
		}
	}
	if len(input) > 0 {
		if js, err := json.Marshal(input); err == nil {
			attrs = append(attrs, attribute.String("gen_ai.input.messages", string(js)))
		}
	}
	if len(t.Output) > 0 {
		output := []genAIChatMessage{{
			Role:         "assistant",
			Parts:        t.Output,
			FinishReason: t.FinishReason,
		}}
		if js, err := json.Marshal(output); err == nil {
			attrs = append(attrs, attribute.String("gen_ai.output.messages", string(js)))
		}
	}
	return attrs
}

// recordGenAITurn emits a GenAI span for a completed LLM turn when the
// feature is enabled and the trace exporter is live. provider is the
// gen_ai.provider.name value ("anthropic"/"openai"); convID is the
// session correlation key emitted as gen_ai.conversation.id (empty when
// the turn carries no session info); serverAddr is the upstream host the
// turn went to (server.address, port 443). Content is parsed from the
// bodies only when content capture is opted in, so the disabled and
// no-content paths stay cheap.
func (g *Gateway) recordGenAITurn(provider, convID, serverAddr, reqModel, respModel string, in, out int64, reqBody, respBody []byte, start time.Time) {
	cfg := g.cfg.Load()
	if genaiTracer == nil || !cfg.GenAITelemetryEnabled() {
		return
	}
	model := reqModel
	if model == "" {
		model = respModel
	}
	// Nothing meaningful parsed (e.g. a non-model response that slipped
	// the path gate) — skip rather than emit an empty span.
	if model == "" && in == 0 && out == 0 {
		return
	}
	turn := genAITurn{
		Provider:       provider,
		Operation:      "chat",
		ConversationID: convID,
		ServerAddress:  serverAddr,
		RequestModel:   model,
		ResponseModel:  respModel,
		InputTokens:    in,
		OutputTokens:   out,
		Start:          start,
	}
	// All intercepted LLM endpoints are HTTPS (the MITM only handles TLS).
	if serverAddr != "" {
		turn.ServerPort = 443
	}
	includeContent := cfg.GenAITelemetryIncludeContent()
	if provider == "anthropic" {
		// Request sampling params and response metadata (id, cache-token
		// breakdown, error/stop reason) ride the span regardless of
		// content capture — they carry no prompt/completion text.
		p := parseClaudeRequestParams(reqBody)
		turn.Stream = p.Stream
		turn.MaxTokens = p.MaxTokens
		turn.Temperature = p.Temperature
		turn.TopP = p.TopP
		turn.TopK = p.TopK
		turn.StopSequences = p.StopSequences
		// Tool name+type ride the base span; the schema/description are
		// gated behind the same content opt-in as message content.
		turn.Tools = parseClaudeToolDefs(reqBody, includeContent)

		meta := claudeResponseMeta(respBody)
		turn.ResponseID = meta.ID
		turn.CacheReadTokens = meta.CacheReadTokens
		turn.CacheCreationTokens = meta.CacheCreationTokens
		turn.ErrorType = meta.ErrorType

		parts, finish := claudeResponseContent(respBody)
		turn.FinishReason = finish
		if includeContent {
			turn.Messages = claudeContentMessages(reqBody)
			turn.Output = parts
		}
	}
	emitGenAISpan(genaiTracer, turn, includeContent)
}

// claudeRequestParams holds the GenAI request sampling parameters parsed
// from an Anthropic /v1/messages request body. Optional scalar fields are
// pointers so a real zero (e.g. temperature 0) is distinguished from
// "absent in the request".
type claudeRequestParams struct {
	Stream        *bool
	MaxTokens     int64
	Temperature   *float64
	TopP          *float64
	TopK          *int64
	StopSequences []string
}

// parseClaudeRequestParams pulls the sampling parameters
// (stream/max_tokens/temperature/top_p/top_k/stop_sequences) from an
// Anthropic /v1/messages request body for the gen_ai.request.* span
// attributes. A malformed body yields the zero value (all unset).
func parseClaudeRequestParams(reqBody []byte) claudeRequestParams {
	var req struct {
		Stream        *bool    `json:"stream"`
		MaxTokens     int64    `json:"max_tokens"`
		Temperature   *float64 `json:"temperature"`
		TopP          *float64 `json:"top_p"`
		TopK          *int64   `json:"top_k"`
		StopSequences []string `json:"stop_sequences"`
	}
	if json.Unmarshal(reqBody, &req) != nil {
		return claudeRequestParams{}
	}
	return claudeRequestParams{
		Stream:        req.Stream,
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		TopK:          req.TopK,
		StopSequences: req.StopSequences,
	}
}

// parseClaudeToolDefs extracts the tool catalogue from an Anthropic
// /v1/messages request body for the gen_ai.tool.definitions span
// attribute. A tool's name and type are always captured (they ride the
// base span); its description and JSON-schema parameters are captured
// only when includeContent is set, since a schema can be large and may
// carry proprietary detail. Anthropic custom tools omit a type, so an
// absent type maps to the GenAI default "function"; built-in tools
// (e.g. type "web_search_20250305") keep their declared type. A
// malformed body, or one offering no tools, yields nil.
func parseClaudeToolDefs(reqBody []byte, includeContent bool) []genAIToolDef {
	var req struct {
		Tools []struct {
			Type        string          `json:"type"`
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"input_schema"`
		} `json:"tools"`
	}
	if json.Unmarshal(reqBody, &req) != nil || len(req.Tools) == 0 {
		return nil
	}
	defs := make([]genAIToolDef, 0, len(req.Tools))
	for _, tl := range req.Tools {
		if tl.Name == "" {
			continue
		}
		typ := tl.Type
		if typ == "" {
			typ = "function"
		}
		d := genAIToolDef{Type: typ, Name: tl.Name}
		if includeContent {
			d.Description = tl.Description
			d.Parameters = rawOrNil(tl.InputSchema)
		}
		defs = append(defs, d)
	}
	if len(defs) == 0 {
		return nil
	}
	return defs
}

// claudeResponseMetadata is the non-content response metadata mapped to
// GenAI span attributes: the message id, the Anthropic prompt-cache token
// breakdown, and the error type when the turn carried a provider error.
type claudeResponseMetadata struct {
	ID                  string
	CacheReadTokens     int64
	CacheCreationTokens int64
	ErrorType           string
}

// claudeResponseMeta extracts the response id, prompt-cache token
// breakdown, and any error type from an Anthropic /v1/messages response,
// handling both non-streaming JSON and streaming SSE bodies. An error
// shape ({"type":"error",...} or an SSE `error` event) surfaces only
// error.type; cache tokens ride the non-streaming usage object or the
// SSE message_start event.
func claudeResponseMeta(body []byte) claudeResponseMetadata {
	// Non-streaming JSON: success carries id+usage; an error response is
	// {"type":"error","error":{"type":"..."}}.
	var jr struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
		Usage struct {
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(body, &jr) == nil && (jr.ID != "" || jr.Type == "error") {
		if jr.Type == "error" {
			return claudeResponseMetadata{ErrorType: jr.Error.Type}
		}
		return claudeResponseMetadata{
			ID:                  jr.ID,
			CacheReadTokens:     jr.Usage.CacheReadInputTokens,
			CacheCreationTokens: jr.Usage.CacheCreationInputTokens,
		}
	}
	// SSE: id + cache tokens ride message_start; an `error` event carries
	// the same {"type":"error","error":{"type":...}} payload.
	var meta claudeResponseMetadata
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 || payload[0] != '{' {
			continue
		}
		var ev struct {
			Type    string `json:"type"`
			Message struct {
				ID    string `json:"id"`
				Usage struct {
					CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
					CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		}
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		switch ev.Type {
		case "message_start":
			meta.ID = ev.Message.ID
			meta.CacheReadTokens = ev.Message.Usage.CacheReadInputTokens
			meta.CacheCreationTokens = ev.Message.Usage.CacheCreationInputTokens
		case "error":
			meta.ErrorType = ev.Error.Type
		}
	}
	return meta
}

// claudeContentMessages extracts the ordered system/user/assistant/tool
// input messages from an Anthropic /v1/messages request body for the
// GenAI content convention. Every content block is mapped to a GenAI
// message part (see claudeBlockPart), so tool calls, tool results, and
// reasoning are captured alongside text rather than dropped.
func claudeContentMessages(reqBody []byte) []genAIMessage {
	var req struct {
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(reqBody, &req) != nil {
		return nil
	}
	var out []genAIMessage
	if sys := claudeMessageParts(req.System); len(sys) > 0 {
		out = append(out, genAIMessage{Role: "system", Parts: sys})
	}
	for _, m := range req.Messages {
		parts := claudeMessageParts(m.Content)
		if len(parts) == 0 {
			continue
		}
		out = append(out, genAIMessage{Role: m.Role, Parts: parts})
	}
	return out
}

// claudeMessageParts converts an Anthropic message Content — either a
// plain string or an array of typed blocks — into GenAI message parts.
func claudeMessageParts(c json.RawMessage) []genAIPart {
	if len(c) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(c, &s) == nil {
		if s == "" {
			return nil
		}
		return []genAIPart{{Type: "text", Content: s}}
	}
	var blocks []json.RawMessage
	if json.Unmarshal(c, &blocks) != nil {
		return nil
	}
	var parts []genAIPart
	for _, raw := range blocks {
		if p, ok := claudeBlockPart(raw); ok {
			parts = append(parts, p)
		}
	}
	return parts
}

// claudeBlockPart maps a single Anthropic content block to a GenAI
// message part following the part-type conventions. Known block types
// become their semantic part (text, reasoning, tool_call,
// tool_call_response); any other block type (image, document,
// redacted_thinking, web_search_tool_result, …) becomes a generic part
// that preserves the type so it is recorded rather than silently
// dropped. Raw binary payloads (e.g. base64 image data) are
// intentionally not captured. ok is false for blocks with no type and
// for empty text/reasoning blocks that carry nothing worth recording.
func claudeBlockPart(raw json.RawMessage) (genAIPart, bool) {
	var hdr struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &hdr) != nil || hdr.Type == "" {
		return genAIPart{}, false
	}
	switch hdr.Type {
	case "text":
		var b struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(raw, &b)
		if b.Text == "" {
			return genAIPart{}, false
		}
		return genAIPart{Type: "text", Content: b.Text}, true
	case "thinking":
		var b struct {
			Thinking string `json:"thinking"`
		}
		_ = json.Unmarshal(raw, &b)
		if b.Thinking == "" {
			return genAIPart{}, false
		}
		return genAIPart{Type: "reasoning", Content: b.Thinking}, true
	case "tool_use", "server_tool_use":
		var b struct {
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		}
		_ = json.Unmarshal(raw, &b)
		return genAIPart{Type: "tool_call", ID: b.ID, Name: b.Name, Arguments: rawOrNil(b.Input)}, true
	case "tool_result":
		var b struct {
			ToolUseID string          `json:"tool_use_id"`
			Content   json.RawMessage `json:"content"`
		}
		_ = json.Unmarshal(raw, &b)
		return genAIPart{Type: "tool_call_response", ID: b.ToolUseID, Response: rawOrNil(b.Content)}, true
	default:
		return genAIPart{Type: hdr.Type}, true
	}
}

// rawOrNil normalizes an absent or literal-null RawMessage to nil so it
// is omitted from the serialized part.
func rawOrNil(r json.RawMessage) json.RawMessage {
	if len(r) == 0 || string(bytes.TrimSpace(r)) == "null" {
		return nil
	}
	return r
}

// claudeResponseContent extracts the assistant response parts and
// stop_reason from an Anthropic /v1/messages response, handling both
// non-streaming JSON and streaming SSE bodies. Every content block
// (text, tool_use, thinking, …) is mapped to a GenAI message part via
// claudeBlockPart, so the response is captured beyond just its text.
func claudeResponseContent(body []byte) (parts []genAIPart, finish string) {
	// Non-streaming JSON: {"stop_reason":"...","content":[ <blocks> ]}.
	var jr struct {
		StopReason string          `json:"stop_reason"`
		Content    json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(body, &jr); err == nil && (len(jr.Content) > 0 || jr.StopReason != "") {
		var blocks []json.RawMessage
		if json.Unmarshal(jr.Content, &blocks) == nil {
			for _, raw := range blocks {
				if p, ok := claudeBlockPart(raw); ok {
					parts = append(parts, p)
				}
			}
		}
		return parts, jr.StopReason
	}
	// SSE: reconstruct each block from its start + delta events.
	return claudeResponseSSEParts(body)
}

// claudeResponseSSEParts reconstructs the assistant response parts and
// stop_reason from an Anthropic streaming (SSE) response. Blocks are
// tracked by index across content_block_start / content_block_delta
// events: text and thinking deltas accumulate their content, and
// tool_use input_json_delta fragments accumulate the arguments JSON.
// stop_reason rides the message_delta event.
func claudeResponseSSEParts(body []byte) (parts []genAIPart, finish string) {
	type sseBlock struct {
		typ  string
		id   string
		name string
		text strings.Builder
		args strings.Builder
	}
	blocks := map[int]*sseBlock{}
	var order []int
	// get returns the block at index i, defaulting unseen indices to a
	// text block (some streams omit content_block_start, e.g. a plain
	// text-only response).
	get := func(i int) *sseBlock {
		b := blocks[i]
		if b == nil {
			b = &sseBlock{typ: "text"}
			blocks[i] = b
			order = append(order, i)
		}
		return b
	}
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 || payload[0] != '{' {
			continue
		}
		var ev struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				Thinking    string `json:"thinking"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
		}
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		switch ev.Type {
		case "content_block_start":
			b := get(ev.Index)
			if ev.ContentBlock.Type != "" {
				b.typ = ev.ContentBlock.Type
			}
			b.id = ev.ContentBlock.ID
			b.name = ev.ContentBlock.Name
		case "content_block_delta":
			b := get(ev.Index)
			switch ev.Delta.Type {
			case "text_delta":
				b.text.WriteString(ev.Delta.Text)
			case "thinking_delta":
				b.text.WriteString(ev.Delta.Thinking)
			case "input_json_delta":
				b.args.WriteString(ev.Delta.PartialJSON)
			}
		case "message_delta":
			if ev.Delta.StopReason != "" {
				finish = ev.Delta.StopReason
			}
		}
	}
	for _, i := range order {
		b := blocks[i]
		switch b.typ {
		case "text":
			if b.text.Len() > 0 {
				parts = append(parts, genAIPart{Type: "text", Content: b.text.String()})
			}
		case "thinking":
			if b.text.Len() > 0 {
				parts = append(parts, genAIPart{Type: "reasoning", Content: b.text.String()})
			}
		case "tool_use", "server_tool_use":
			p := genAIPart{Type: "tool_call", ID: b.id, Name: b.name}
			if b.args.Len() > 0 {
				p.Arguments = json.RawMessage(b.args.String())
			}
			parts = append(parts, p)
		default:
			parts = append(parts, genAIPart{Type: b.typ})
		}
	}
	return parts, finish
}
