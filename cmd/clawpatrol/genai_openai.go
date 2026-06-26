// OpenAI provider mapping for the OTel GenAI export. Fills the shared
// genAITurn (see genai.go) from OpenAI's two wire formats — the Chat
// Completions API (/v1/chat/completions, /v1/completions) and the
// Responses API (/v1/responses and chatgpt.com's /backend-api/codex/
// responses) — so OpenAI turns emit the same gen_ai.* telemetry as
// Anthropic. The representation and span exporter are shared; only this
// per-provider extraction differs.
//
// OpenAI has no top_k and no Anthropic-style prompt-cache token
// breakdown, so those fields stay unset (the exporter omits them) rather
// than carrying wrong/empty values. max-token caps are spread across
// max_tokens / max_completion_tokens / max_output_tokens depending on
// the API surface; all three are coalesced into gen_ai.request.max_tokens.

package main

import (
	"bytes"
	"encoding/json"
	"strings"
)

// mapOpenAITurn fills the GenAI turn from an OpenAI request/response
// pair, transparently handling both the Chat Completions and Responses
// API shapes. Request sampling params, tool name+type, the response id,
// and the finish reason ride the span regardless of content capture;
// message content and tool schemas are gated behind includeContent.
func mapOpenAITurn(turn *genAITurn, reqBody, respBody []byte, includeContent bool) {
	p := parseOpenAIRequestParams(reqBody)
	turn.Stream = p.Stream
	turn.MaxTokens = p.MaxTokens
	turn.Temperature = p.Temperature
	turn.TopP = p.TopP
	turn.StopSequences = p.StopSequences
	turn.Tools = parseOpenAIToolDefs(reqBody, includeContent)

	id, errType := openAIResponseMeta(respBody)
	turn.ResponseID = id
	turn.ErrorType = errType

	parts, finish := openAIResponseContent(respBody)
	turn.FinishReason = finish
	if includeContent {
		turn.Messages = openAIContentMessages(reqBody)
		turn.Output = parts
	}
}

// openAIRequestParams holds the GenAI request sampling parameters parsed
// from an OpenAI request body. Optional scalars are pointers so a real
// zero (e.g. temperature 0) is distinguished from "absent". OpenAI has
// no top_k, so the GenAI top_k attribute is never set for this provider.
type openAIRequestParams struct {
	Stream        *bool
	MaxTokens     int64
	Temperature   *float64
	TopP          *float64
	StopSequences []string
}

// parseOpenAIRequestParams pulls the sampling parameters from an OpenAI
// request body. The max-token cap appears under different keys across
// API surfaces (max_tokens on classic Chat Completions,
// max_completion_tokens on newer Chat Completions, max_output_tokens on
// the Responses API); the first non-zero one wins. `stop` may be a single
// string or an array of strings. A malformed body yields the zero value.
func parseOpenAIRequestParams(reqBody []byte) openAIRequestParams {
	var req struct {
		Stream              *bool           `json:"stream"`
		MaxTokens           int64           `json:"max_tokens"`
		MaxCompletionTokens int64           `json:"max_completion_tokens"`
		MaxOutputTokens     int64           `json:"max_output_tokens"`
		Temperature         *float64        `json:"temperature"`
		TopP                *float64        `json:"top_p"`
		Stop                json.RawMessage `json:"stop"`
	}
	if json.Unmarshal(reqBody, &req) != nil {
		return openAIRequestParams{}
	}
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = req.MaxCompletionTokens
	}
	if maxTokens == 0 {
		maxTokens = req.MaxOutputTokens
	}
	return openAIRequestParams{
		Stream:        req.Stream,
		MaxTokens:     maxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		StopSequences: parseStopSequences(req.Stop),
	}
}

// parseStopSequences normalizes OpenAI's `stop` field — a single string
// or an array of strings — into a slice. Returns nil when absent.
func parseStopSequences(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

// parseOpenAIToolDefs extracts the tool catalogue from an OpenAI request
// body for gen_ai.tool.definitions, handling both shapes: Chat
// Completions nests the spec under a `function` object
// ({type:"function", function:{name, description, parameters}}), while
// the Responses API carries it flat ({type:"function", name,
// description, parameters}). Name and type ride the base span; the
// description and JSON-schema parameters are captured only when
// includeContent is set. Built-in Responses tools (e.g.
// type:"web_search_preview") carry no name, so the type doubles as the
// name to keep them recorded. A malformed body, or one offering no
// tools, yields nil.
func parseOpenAIToolDefs(reqBody []byte, includeContent bool) []genAIToolDef {
	var req struct {
		Tools []struct {
			Type        string          `json:"type"`
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Parameters  json.RawMessage `json:"parameters"`
			Function    *struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		} `json:"tools"`
	}
	if json.Unmarshal(reqBody, &req) != nil || len(req.Tools) == 0 {
		return nil
	}
	defs := make([]genAIToolDef, 0, len(req.Tools))
	for _, tl := range req.Tools {
		name, desc, params := tl.Name, tl.Description, tl.Parameters
		if tl.Function != nil {
			name, desc, params = tl.Function.Name, tl.Function.Description, tl.Function.Parameters
		}
		typ := tl.Type
		if typ == "" {
			typ = "function"
		}
		// Built-in tools (web_search_preview, file_search, …) have no
		// name; fall back to the type so they are still recorded.
		if name == "" {
			if typ == "function" {
				continue
			}
			name = typ
		}
		d := genAIToolDef{Type: typ, Name: name}
		if includeContent {
			d.Description = desc
			d.Parameters = rawOrNil(params)
		}
		defs = append(defs, d)
	}
	if len(defs) == 0 {
		return nil
	}
	return defs
}

// openAIResponseMeta extracts the response id and any error type from an
// OpenAI response, handling non-streaming JSON (both API shapes) and
// streaming SSE. Chat Completions and Responses both carry a top-level
// `id`; an error HTTP body is {"error":{"type":...,"code":...}}. In SSE,
// Chat chunks repeat the id while a Responses stream's terminal event
// carries response.id (and response.error on failure).
func openAIResponseMeta(body []byte) (id, errorType string) {
	var jr struct {
		ID    string `json:"id"`
		Error *struct {
			Type string `json:"type"`
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &jr) == nil && (jr.ID != "" || jr.Error != nil) {
		if jr.Error != nil {
			return jr.ID, firstNonEmpty(jr.Error.Type, jr.Error.Code)
		}
		return jr.ID, ""
	}
	for _, payload := range sseDataPayloads(body) {
		var ev struct {
			ID    string `json:"id"`
			Error *struct {
				Type string `json:"type"`
				Code string `json:"code"`
			} `json:"error"`
			Response struct {
				ID    string `json:"id"`
				Error *struct {
					Type string `json:"type"`
					Code string `json:"code"`
				} `json:"error"`
			} `json:"response"`
		}
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		if ev.Response.ID != "" {
			id = ev.Response.ID
		} else if ev.ID != "" {
			id = ev.ID
		}
		if ev.Error != nil {
			errorType = firstNonEmpty(ev.Error.Type, ev.Error.Code)
		}
		if ev.Response.Error != nil {
			errorType = firstNonEmpty(ev.Response.Error.Type, ev.Response.Error.Code)
		}
	}
	return id, errorType
}

// openAIResponseContent extracts the assistant response parts and finish
// reason from an OpenAI response, handling non-streaming JSON for both
// API shapes (Chat Completions `choices`, Responses `output`) and
// streaming SSE. Every part (text, tool_call, reasoning, generic) maps to
// a GenAI message part.
func openAIResponseContent(body []byte) (parts []genAIPart, finish string) {
	var jr struct {
		Choices           json.RawMessage `json:"choices"`
		Output            json.RawMessage `json:"output"`
		Status            string          `json:"status"`
		IncompleteDetails struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
	}
	if json.Unmarshal(body, &jr) == nil && (len(jr.Choices) > 0 || len(jr.Output) > 0) {
		if len(jr.Choices) > 0 {
			return openAIChatChoiceContent(jr.Choices)
		}
		return openAIResponsesOutput(jr.Output), responsesFinish(jr.Status, jr.IncompleteDetails.Reason)
	}
	return openAIResponseSSE(body)
}

// openAIChatChoiceContent maps the first choice of a non-streaming Chat
// Completions response to GenAI parts (assistant text + tool_call parts)
// and its finish_reason.
func openAIChatChoiceContent(choices json.RawMessage) (parts []genAIPart, finish string) {
	var cs []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content   json.RawMessage  `json:"content"`
			ToolCalls []openAIToolCall `json:"tool_calls"`
		} `json:"message"`
	}
	if json.Unmarshal(choices, &cs) != nil || len(cs) == 0 {
		return nil, ""
	}
	c := cs[0]
	parts = append(parts, openAIContentParts(c.Message.Content)...)
	parts = append(parts, openAIToolCallParts(c.Message.ToolCalls)...)
	return parts, c.FinishReason
}

// openAIResponsesOutput maps a Responses API `output` array to GenAI
// parts: message items become text/generic parts, function_call items
// become tool_call parts, reasoning items become reasoning parts, and any
// other item type becomes a generic part preserving its type.
func openAIResponsesOutput(output json.RawMessage) []genAIPart {
	var items []struct {
		Type      string          `json:"type"`
		Content   json.RawMessage `json:"content"`
		CallID    string          `json:"call_id"`
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Summary   json.RawMessage `json:"summary"`
	}
	if json.Unmarshal(output, &items) != nil {
		return nil
	}
	var parts []genAIPart
	for _, it := range items {
		switch it.Type {
		case "message", "":
			parts = append(parts, openAIContentParts(it.Content)...)
		case "function_call":
			parts = append(parts, genAIPart{
				Type:      "tool_call",
				ID:        it.CallID,
				Name:      it.Name,
				Arguments: rawArgsToRaw(it.Arguments),
			})
		case "reasoning":
			if t := openAIReasoningText(it.Summary); t != "" {
				parts = append(parts, genAIPart{Type: "reasoning", Content: t})
			}
		default:
			parts = append(parts, genAIPart{Type: it.Type})
		}
	}
	return parts
}

// openAIResponseSSE reconstructs the assistant response from a streaming
// body. A Responses-API stream ends with a terminal event carrying the
// full response object (response.completed / .incomplete / .failed) — when
// its output is populated it is parsed exactly like a non-streaming
// Responses body. Codex's /backend-api/codex/responses stream is the
// exception: its terminal frame's output is always empty ([]), and the
// finished output items ride the per-item response.output_item.done events
// instead — so those are accumulated (by output_index, latest-wins) and
// used to reconstruct the output when the terminal output is empty or no
// terminal event arrives. Otherwise the body is a Chat Completions stream
// whose choice deltas are accumulated: text content concatenates, and
// tool-call fragments accumulate by index.
func openAIResponseSSE(body []byte) (parts []genAIPart, finish string) {
	type toolAccum struct {
		id   string
		name string
		args strings.Builder
	}
	var (
		text      strings.Builder
		tools     = map[int]*toolAccum{}
		order     []int
		haveChat  bool
		respItems = map[int]json.RawMessage{}
		respOrder []int
	)
	for _, payload := range sseDataPayloads(body) {
		var ev struct {
			Type        string          `json:"type"`
			Response    json.RawMessage `json:"response"`
			Item        json.RawMessage `json:"item"`
			OutputIndex int             `json:"output_index"`
			Choices     []struct {
				FinishReason string `json:"finish_reason"`
				Delta        struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		// Responses-API per-item completion: a fully-formed output item
		// (message / reasoning / function_call). Codex delivers the real
		// output here, not on the terminal frame. Latest-wins per index.
		if ev.Type == "response.output_item.done" && len(ev.Item) > 0 {
			if _, seen := respItems[ev.OutputIndex]; !seen {
				respOrder = append(respOrder, ev.OutputIndex)
			}
			respItems[ev.OutputIndex] = ev.Item
			continue
		}
		// Responses-API terminal event: the embedded response object
		// carries the final state. Its output is the source of truth when
		// populated; when empty (Codex) fall back to the items accumulated
		// from response.output_item.done events. Only the terminal events
		// carry the final state — response.created / .in_progress snapshots
		// also embed a (still-empty) response.
		if isResponsesTerminalEvent(ev.Type) && len(ev.Response) > 0 {
			var r struct {
				Output            json.RawMessage `json:"output"`
				Status            string          `json:"status"`
				IncompleteDetails struct {
					Reason string `json:"reason"`
				} `json:"incomplete_details"`
			}
			if json.Unmarshal(ev.Response, &r) == nil {
				finish = responsesFinish(r.Status, r.IncompleteDetails.Reason)
				if out := openAIResponsesOutput(r.Output); len(out) > 0 {
					return out, finish
				}
				return assembleResponsesOutput(respItems, respOrder), finish
			}
			continue
		}
		if len(ev.Choices) == 0 {
			continue
		}
		haveChat = true
		ch := ev.Choices[0]
		text.WriteString(ch.Delta.Content)
		if ch.FinishReason != "" {
			finish = ch.FinishReason
		}
		for _, tc := range ch.Delta.ToolCalls {
			acc := tools[tc.Index]
			if acc == nil {
				acc = &toolAccum{}
				tools[tc.Index] = acc
				order = append(order, tc.Index)
			}
			if tc.ID != "" {
				acc.id = tc.ID
			}
			if tc.Function.Name != "" {
				acc.name = tc.Function.Name
			}
			acc.args.WriteString(tc.Function.Arguments)
		}
	}
	if !haveChat {
		// No chat deltas and no terminal frame (e.g. a truncated Codex
		// stream): reconstruct from the per-item events seen so far.
		return assembleResponsesOutput(respItems, respOrder), finish
	}
	if text.Len() > 0 {
		parts = append(parts, genAIPart{Type: "text", Content: text.String()})
	}
	for _, i := range order {
		acc := tools[i]
		parts = append(parts, genAIPart{
			Type:      "tool_call",
			ID:        acc.id,
			Name:      acc.name,
			Arguments: argStringToRaw(acc.args.String()),
		})
	}
	return parts, finish
}

// assembleResponsesOutput maps the output items accumulated from
// response.output_item.done events into GenAI parts, reusing the
// non-streaming Responses output mapper. items is keyed by output_index;
// order preserves first-seen index order. Returns nil when no items were
// collected.
func assembleResponsesOutput(items map[int]json.RawMessage, order []int) []genAIPart {
	if len(items) == 0 {
		return nil
	}
	arr := make([]json.RawMessage, 0, len(order))
	for _, i := range order {
		arr = append(arr, items[i])
	}
	js, err := json.Marshal(arr)
	if err != nil {
		return nil
	}
	return openAIResponsesOutput(js)
}

// openAIContentMessages extracts the ordered input messages from an
// OpenAI request body for the GenAI content convention. Chat Completions
// carries them under `messages`; the Responses API uses `input` (a string
// or item array) plus a top-level `instructions` system prompt. A
// malformed body, or one with neither field, yields nil.
func openAIContentMessages(reqBody []byte) []genAIMessage {
	var probe struct {
		Messages     json.RawMessage `json:"messages"`
		Input        json.RawMessage `json:"input"`
		Instructions string          `json:"instructions"`
	}
	if json.Unmarshal(reqBody, &probe) != nil {
		return nil
	}
	if len(probe.Messages) > 0 {
		return openAIChatMessages(probe.Messages)
	}
	if len(probe.Input) > 0 {
		return openAIResponsesInput(probe.Input, probe.Instructions)
	}
	return nil
}

// openAIChatMessages converts a Chat Completions `messages` array into
// GenAI messages. A `tool` role message becomes a tool_call_response
// part; an assistant message's tool_calls become tool_call parts
// alongside any text content.
func openAIChatMessages(raw json.RawMessage) []genAIMessage {
	var msgs []struct {
		Role       string           `json:"role"`
		Content    json.RawMessage  `json:"content"`
		ToolCalls  []openAIToolCall `json:"tool_calls"`
		ToolCallID string           `json:"tool_call_id"`
	}
	if json.Unmarshal(raw, &msgs) != nil {
		return nil
	}
	var out []genAIMessage
	for _, m := range msgs {
		var parts []genAIPart
		if m.Role == "tool" && m.ToolCallID != "" {
			parts = append(parts, genAIPart{
				Type:     "tool_call_response",
				ID:       m.ToolCallID,
				Response: rawOrNil(m.Content),
			})
		} else {
			parts = append(parts, openAIContentParts(m.Content)...)
			parts = append(parts, openAIToolCallParts(m.ToolCalls)...)
		}
		if len(parts) == 0 {
			continue
		}
		out = append(out, genAIMessage{Role: m.Role, Parts: parts})
	}
	return out
}

// openAIResponsesInput converts a Responses API `input` (a plain string
// or an item array) plus the top-level `instructions` into GenAI
// messages. function_call items become assistant tool_call parts,
// function_call_output items become tool tool_call_response parts, and
// message items carry their text/generic content parts.
func openAIResponsesInput(raw json.RawMessage, instructions string) []genAIMessage {
	var out []genAIMessage
	if instructions != "" {
		out = append(out, genAIMessage{Role: "system", Parts: []genAIPart{{Type: "text", Content: instructions}}})
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s != "" {
			out = append(out, genAIMessage{Role: "user", Parts: []genAIPart{{Type: "text", Content: s}}})
		}
		return out
	}
	var items []struct {
		Type      string          `json:"type"`
		Role      string          `json:"role"`
		Content   json.RawMessage `json:"content"`
		CallID    string          `json:"call_id"`
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Output    json.RawMessage `json:"output"`
	}
	if json.Unmarshal(raw, &items) != nil {
		return out
	}
	for _, it := range items {
		switch it.Type {
		case "function_call":
			out = append(out, genAIMessage{Role: "assistant", Parts: []genAIPart{{
				Type:      "tool_call",
				ID:        it.CallID,
				Name:      it.Name,
				Arguments: rawArgsToRaw(it.Arguments),
			}}})
		case "function_call_output":
			out = append(out, genAIMessage{Role: "tool", Parts: []genAIPart{{
				Type:     "tool_call_response",
				ID:       it.CallID,
				Response: rawOrNil(it.Output),
			}}})
		case "message", "":
			role := it.Role
			if role == "" {
				role = "user"
			}
			if parts := openAIContentParts(it.Content); len(parts) > 0 {
				out = append(out, genAIMessage{Role: role, Parts: parts})
			}
		default:
			out = append(out, genAIMessage{Role: it.Role, Parts: []genAIPart{{Type: it.Type}}})
		}
	}
	return out
}

// openAIToolCall is a Chat Completions tool call ({id, type,
// function:{name, arguments}}); arguments is a JSON-encoded string.
type openAIToolCall struct {
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// openAIToolCallParts maps Chat Completions tool_calls to GenAI tool_call
// parts, decoding each call's JSON-string arguments into structured JSON.
func openAIToolCallParts(calls []openAIToolCall) []genAIPart {
	var parts []genAIPart
	for _, tc := range calls {
		parts = append(parts, genAIPart{
			Type:      "tool_call",
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: argStringToRaw(tc.Function.Arguments),
		})
	}
	return parts
}

// openAIContentParts converts an OpenAI message `content` — a plain
// string or an array of typed parts — into GenAI parts. Text parts
// (text / input_text / output_text) carry their text; any other part
// type (input_image, input_file, …) becomes a generic part preserving
// the type rather than being dropped. Raw binary/url payloads are not
// captured.
func openAIContentParts(c json.RawMessage) []genAIPart {
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
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(c, &blocks) != nil {
		return nil
	}
	var parts []genAIPart
	for _, b := range blocks {
		switch b.Type {
		case "text", "input_text", "output_text":
			if b.Text != "" {
				parts = append(parts, genAIPart{Type: "text", Content: b.Text})
			}
		case "":
			continue
		default:
			parts = append(parts, genAIPart{Type: b.Type})
		}
	}
	return parts
}

// openAIReasoningText flattens a Responses API reasoning item's `summary`
// (an array of {type:"summary_text", text} parts) into a single string.
func openAIReasoningText(summary json.RawMessage) string {
	if len(summary) == 0 {
		return ""
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(summary, &parts) != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		if p.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p.Text)
	}
	return b.String()
}

// isResponsesTerminalEvent reports whether a Responses-API SSE event type
// is the terminal one whose embedded response object holds the final
// output — as opposed to the response.created / response.in_progress
// snapshots that precede it.
func isResponsesTerminalEvent(typ string) bool {
	switch typ {
	case "response.completed", "response.incomplete", "response.failed":
		return true
	}
	return false
}

// responsesFinish maps a Responses API completion to a GenAI finish
// reason: the incomplete reason when the response stopped short, else the
// status ("completed", "failed", …).
func responsesFinish(status, incompleteReason string) string {
	if status == "incomplete" && incompleteReason != "" {
		return incompleteReason
	}
	return status
}

// rawArgsToRaw normalizes a tool-call arguments value that may arrive
// either as structured JSON or as a JSON-encoded string (OpenAI encodes
// arguments as a string) into structured JSON for the part.
func rawArgsToRaw(raw json.RawMessage) json.RawMessage {
	raw = rawOrNil(raw)
	if raw == nil {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return argStringToRaw(s)
	}
	return raw
}

// argStringToRaw turns a tool-call arguments string into a RawMessage: the
// inner JSON when the string is valid JSON, otherwise the string itself
// as a JSON string. Empty input yields nil.
func argStringToRaw(s string) json.RawMessage {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	if b, err := json.Marshal(s); err == nil {
		return json.RawMessage(b)
	}
	return nil
}

// firstNonEmpty returns the first non-empty argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// sseDataPayloads returns the JSON object payloads of each `data:` line in
// an SSE body, skipping non-JSON sentinels (e.g. "data: [DONE]").
func sseDataPayloads(body []byte) [][]byte {
	var out [][]byte
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 || payload[0] != '{' {
			continue
		}
		out = append(out, payload)
	}
	return out
}
