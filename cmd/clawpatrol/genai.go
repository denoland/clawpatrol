// OpenTelemetry GenAI semantic-convention export for intercepted LLM
// turns. Targets semconv v1.27.0
// (https://opentelemetry.io/docs/specs/semconv/gen-ai/): one span per
// model invocation carrying gen_ai.* attributes (system, models, token
// usage, finish reason) and — only when the operator opts in — the
// prompt/completion message content as span events.
//
// Opt-in is two independent switches (internal/config GenAITelemetry):
// the `genai_telemetry {}` block presence enables the attribute span;
// `include_message_content` additionally attaches content events.
// Disabled is the zero-overhead default — recordGenAITurn returns
// before parsing anything.

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

// genAIMessage is one input message (system/user/assistant) captured
// for the GenAI content convention.
type genAIMessage struct {
	Role    string
	Content string
}

// genAITurn is one intercepted LLM request/response mapped to OTel
// GenAI semantic-convention terms.
type genAITurn struct {
	System        string // gen_ai.system: "anthropic" | "openai"
	Operation     string // gen_ai.operation.name: "chat"
	RequestModel  string // gen_ai.request.model
	ResponseModel string // gen_ai.response.model
	InputTokens   int64  // gen_ai.usage.input_tokens
	OutputTokens  int64  // gen_ai.usage.output_tokens
	FinishReason  string // gen_ai.response.finish_reasons[0]

	// Start, when non-zero, sets the span start time so its duration
	// reflects the real upstream round-trip latency. Zero → span is
	// stamped at emission time.
	Start time.Time

	// Messages and Completion populate the content events; filled only
	// when message-content capture is enabled.
	Messages   []genAIMessage
	Completion string
}

// emitGenAISpan records one GenAI span on the provided tracer. When
// includeContent is true, message content is attached as span events
// per the GenAI content convention. A free function (not a method) so
// tests can drive it with an in-memory tracer.
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
		attribute.String("gen_ai.system", t.System),
		attribute.String("gen_ai.operation.name", t.Operation),
	}
	if t.RequestModel != "" {
		attrs = append(attrs, attribute.String("gen_ai.request.model", t.RequestModel))
	}
	if t.ResponseModel != "" {
		attrs = append(attrs, attribute.String("gen_ai.response.model", t.ResponseModel))
	}
	if t.InputTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.usage.input_tokens", t.InputTokens))
	}
	if t.OutputTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.usage.output_tokens", t.OutputTokens))
	}
	if t.FinishReason != "" {
		attrs = append(attrs, attribute.StringSlice("gen_ai.response.finish_reasons", []string{t.FinishReason}))
	}
	span.SetAttributes(attrs...)

	if includeContent {
		for _, m := range t.Messages {
			role := m.Role
			if role == "" {
				role = "user"
			}
			span.AddEvent("gen_ai."+role+".message", trace.WithAttributes(
				attribute.String("gen_ai.system", t.System),
				attribute.String("content", m.Content),
			))
		}
		if t.Completion != "" {
			span.AddEvent("gen_ai.choice", trace.WithAttributes(
				attribute.String("gen_ai.system", t.System),
				attribute.Int("index", 0),
				attribute.String("finish_reason", t.FinishReason),
				attribute.String("content", t.Completion),
			))
		}
	}
	span.End()
}

// recordGenAITurn emits a GenAI span for a completed LLM turn when the
// feature is enabled and the trace exporter is live. system is the
// gen_ai.system value ("anthropic"/"openai"). Content is parsed from
// the bodies only when content capture is opted in, so the disabled and
// no-content paths stay cheap.
func (g *Gateway) recordGenAITurn(system, reqModel, respModel string, in, out int64, reqBody, respBody []byte, start time.Time) {
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
		System:        system,
		Operation:     "chat",
		RequestModel:  model,
		ResponseModel: respModel,
		InputTokens:   in,
		OutputTokens:  out,
		Start:         start,
	}
	includeContent := cfg.GenAITelemetryIncludeContent()
	if system == "anthropic" {
		// stop_reason is on the response regardless of content capture.
		completion, finish := claudeResponseContent(respBody)
		turn.FinishReason = finish
		if includeContent {
			turn.Messages = claudeContentMessages(reqBody)
			turn.Completion = completion
		}
	}
	emitGenAISpan(genaiTracer, turn, includeContent)
}

// claudeContentMessages extracts the ordered system/user/assistant
// input messages from an Anthropic /v1/messages request body for the
// GenAI content convention. Reuses messageText so both string and
// content-block message shapes are flattened to text.
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
	if sys := messageText(req.System); sys != "" {
		out = append(out, genAIMessage{Role: "system", Content: sys})
	}
	for _, m := range req.Messages {
		txt := messageText(m.Content)
		if txt == "" {
			continue
		}
		out = append(out, genAIMessage{Role: m.Role, Content: txt})
	}
	return out
}

// claudeResponseContent extracts the assistant completion text and
// stop_reason from an Anthropic /v1/messages response, handling both
// non-streaming JSON and streaming SSE bodies.
func claudeResponseContent(body []byte) (text, finish string) {
	// Non-streaming JSON: {"stop_reason":"...","content":[{"type":"text","text":"..."}]}.
	var jr struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &jr); err == nil && (len(jr.Content) > 0 || jr.StopReason != "") {
		var b strings.Builder
		for _, c := range jr.Content {
			if c.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(c.Text)
		}
		return b.String(), jr.StopReason
	}
	// SSE: accumulate content_block_delta text; stop_reason rides the
	// message_delta event.
	var b strings.Builder
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
			Type  string `json:"type"`
			Delta struct {
				Type       string `json:"type"`
				Text       string `json:"text"`
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		switch ev.Type {
		case "content_block_delta":
			b.WriteString(ev.Delta.Text)
		case "message_delta":
			if ev.Delta.StopReason != "" {
				finish = ev.Delta.StopReason
			}
		}
	}
	return b.String(), finish
}
