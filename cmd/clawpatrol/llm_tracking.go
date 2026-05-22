package main

// LLM-traffic bookkeeping. The MITM dispatcher hands captured request /
// response bodies (plus a kind tag derived from the destination host)
// to these helpers so the dashboard's "agent sessions" view can show
// model, title, and token totals per turn — independent of how the
// session was framed on the wire (HTTPS POST + SSE, Codex WS, or
// pre-create-then-update for streaming responses).
//
// Per-kind shape parsers live here too: parseClaudeResponse,
// parseClaudeRequest, parseOpenAIResponse, plus the Codex envelope
// helpers that pull a stable session id + human-meaningful title out
// of agent CLI traffic. None of these helpers touch the connection
// state; they only consume captured bytes and emit recordLLMUsage
// calls.

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
)

// trackCodexWSUsage parses a single WebSocket text-frame payload from
// chatgpt.com/codex traffic. Codex sends JSON envelopes containing the
// user prompt (client→server) and usage info (server→client). Sessions
// key on the per-connection wsSessionID supplied by handleWSUpgrade
// — usually codex's own `Session_id` request header so two parallel
// `clawpatrol run codex` instances on the same device land in
// distinct rows. Empty wsSessionID falls back to a per-remoteAddr
// hash so older code paths still produce one row per connection.
func (g *Gateway) trackCodexWSUsage(remoteAddr, wsSessionID string, payload []byte) {
	ip := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ip = h
	}
	sid := wsSessionID
	if sid == "" {
		sid = "ws_" + shortHash(remoteAddr)
	} else {
		sid = "s_" + shortHash(sid)
	}
	// Codex Responses-API frames. Shapes we care about:
	//   client → server: full request envelope w/ `input` (user prompt)
	//     {"input":[{"role":"user","content":[{"type":"input_text","text":"..."}]}],
	//      "model":"...", ...}
	//   server → client:
	//     {"type":"response.created","response":{"id":"...","model":"..."}}
	//     {"type":"response.output_item.added","item":{"type":"function_call",
	//        "name":"shell"|"apply_patch"|...,"arguments":"<json string>"}}
	//     {"type":"response.completed","response":{"usage":{...},
	//        "output":[{"type":"message","content":[{"type":"output_text","text":"..."}]}]}}
	var msg struct {
		Type     string `json:"type"`
		Model    string `json:"model"`
		Response struct {
			ID    string `json:"id"`
			Model string `json:"model"`
			Usage struct {
				InputTokens           int64 `json:"input_tokens"`
				CachedInputTokens     int64 `json:"cached_input_tokens"`
				OutputTokens          int64 `json:"output_tokens"`
				ReasoningOutputTokens int64 `json:"reasoning_output_tokens"`
			} `json:"usage"`
			Output []struct {
				Type    string `json:"type"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
		} `json:"response"`
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
		Input []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"input"`
		Item struct {
			Type      string `json:"type"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"item"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}
	model := msg.Response.Model
	if model == "" {
		model = msg.Model
	}
	in := msg.Response.Usage.InputTokens + msg.Response.Usage.CachedInputTokens + msg.Usage.InputTokens
	out := msg.Response.Usage.OutputTokens + msg.Response.Usage.ReasoningOutputTokens + msg.Usage.OutputTokens
	// Title selection — latest wins. recordLLMUsage overwrites Title
	// on every non-empty pass, so the dashboard shows whatever the
	// session is doing right now:
	//   - user prompt frame → "<first input_text>"
	//   - tool-call frame   → "▸ <name>(<first arg snippet>)"
	//   - completion frame  → "↩ <assistant text head>"
	title := codexInputTitle(msg.Input)
	if title == "" && msg.Type == "response.output_item.added" && msg.Item.Type == "function_call" {
		title = codexToolTitle(msg.Item.Name, msg.Item.Arguments)
	}
	if title == "" && msg.Type == "response.completed" {
		title = codexCompletedTitle(msg.Response.Output)
	}
	if in == 0 && out == 0 && model == "" && title == "" {
		return
	}
	g.agents.recordLLMUsage(ip, "codex", sid, title, model, in, out)
}

// codexToolTitle formats a tool-call frame into "▸ name(arg)". Codex's
// `arguments` field is a JSON string whose shape varies per tool —
// shell.command[], apply_patch.input, file_search.query, etc. We pull
// the first usefully-named argument when present, else show the raw
// args truncated.
func codexToolTitle(name, args string) string {
	if name == "" {
		return ""
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(args), &generic); err != nil {
		return "▸ " + name
	}
	// Preferred argument keys, in order. Most codex tools surface one
	// of these as the human-meaningful value.
	for _, k := range []string{"command", "path", "file_path", "input", "query", "url"} {
		v, ok := generic[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			return "▸ " + name + " " + truncate(t, 40)
		case []any:
			parts := make([]string, 0, len(t))
			for _, p := range t {
				if s, ok := p.(string); ok {
					parts = append(parts, s)
				}
			}
			joined := strings.Join(parts, " ")
			if joined != "" {
				return "▸ " + name + " " + truncate(joined, 40)
			}
		}
	}
	return "▸ " + name
}

// codexCompletedTitle returns the assistant's final text from a
// response.completed frame. Walks output[].content[] looking for the
// first output_text block and uses its head as the title — gives the
// dashboard a glimpse of what the model just said when no tool call
// followed.
func codexCompletedTitle(output []struct {
	Type    string `json:"type"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}) string {
	for _, o := range output {
		for _, c := range o.Content {
			if c.Text != "" {
				return "↩ " + truncate(c.Text, 60)
			}
		}
	}
	return ""
}

// codexInputTitle returns the LATEST user text from a Codex
// Responses-API `input` array. Codex sends the full conversation
// history on every turn; the most-recent user message lives at the
// tail. Walking forward (the old behavior) returned the system-y
// first prompt ("You are deno node-compat fixer …") every time and
// title never changed across turns.
func codexInputTitle(input []struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}) string {
	for i := len(input) - 1; i >= 0; i-- {
		m := input[i]
		if m.Role != "user" {
			continue
		}
		text := stripCodexWrappers(joinUserContent(m.Content))
		if text != "" {
			return truncate(text, 80)
		}
	}
	return ""
}

// codexInputFirstTitle returns the FIRST real user message from a Codex
// input array — used as a stable session ID seed across turns (since the
// full conversation history is resent every turn, the first message never
// changes, giving a consistent shortHash).
func codexInputFirstTitle(input []struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}) string {
	for _, m := range input {
		if m.Role != "user" {
			continue
		}
		text := stripCodexWrappers(joinUserContent(m.Content))
		if text != "" {
			return truncate(text, 80)
		}
	}
	return ""
}

// joinUserContent flattens a Codex/OpenAI message Content (string OR
// array of typed blocks). Blocks are joined with newlines so a single
// user message that mixes <environment_context> + the actual prompt
// (sent as separate input_text blocks) yields the full text after
// stripCodexWrappers peels off the wrapper.
func joinUserContent(c json.RawMessage) string {
	var s string
	if err := json.Unmarshal(c, &s); err == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(c, &blocks); err == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(blk.Text)
		}
		return b.String()
	}
	return ""
}

// stripCodexWrappers removes Codex CLI's auto-injected XML wrapper
// blocks (environment_context, user_instructions) so the session
// title shows the actual user prompt.
func stripCodexWrappers(s string) string {
	return stripXMLBlocks(s, "environment_context", "user_instructions")
}

// trackKindFor returns the usage-parsing flavor for a given host (and,
// for chatgpt.com, also gates HTTP-mode codex tracking). Tracking is
// always-on; operators don't configure it per rule. chatgpt.com matches
// by suffix — codex HTTP POSTs hit backend-api.chatgpt.com, WS upgrades
// hit chatgpt.com bare; both need the codex parser.
func trackKindFor(host string) string {
	h := strings.ToLower(host)
	switch h {
	case "api.anthropic.com":
		return "claude_usage"
	case "api.openai.com":
		return "openai_usage"
	}
	if strings.HasSuffix(h, "chatgpt.com") {
		return "codex_ws_usage"
	}
	return ""
}

// preCreateLLMSession parses just the request body and seeds a session
// row with title + model so the dashboard reflects an in-flight turn
// before the SSE stream completes. Token counts arrive later via
// trackLLMUsage. Mirrors trackLLMUsage's path/kind gating but skips
// any work that depends on the response body.
// sessionHint is the value of the Session_id / Session-Id request header
// when present — used as a stable session key for codex_ws_usage HTTP requests.
func (g *Gateway) preCreateLLMSession(c net.Conn, kind, path string, reqBody []byte, sessionHint string) {
	if g.agents == nil {
		return
	}
	ip := g.agentIPFor(c)
	switch kind {
	case "claude_usage":
		if path != "/v1/messages" {
			return
		}
		reqInfo := parseClaudeRequest(reqBody)
		sid := reqInfo.SessionID
		title := reqInfo.Title
		if sid == "" {
			if title == "" {
				return
			}
			sid = shortHash(title)
		}
		g.agents.recordLLMUsage(ip, "claude", sid, title, reqInfo.Model, 0, 0)
	case "openai_usage":
		if !strings.HasPrefix(path, "/v1/chat/completions") &&
			!strings.HasPrefix(path, "/v1/responses") &&
			!strings.HasPrefix(path, "/v1/completions") {
			return
		}
		title := openaiFirstUserMessage(reqBody)
		if title == "" {
			return
		}
		g.agents.recordLLMUsage(ip, "codex", shortHash(title), title, "", 0, 0)
	case "codex_ws_usage":
		if !strings.Contains(path, "/codex/responses") {
			return
		}
		title := codexResponsesRequestTitle(reqBody)
		if title == "" {
			return
		}
		sid := shortHash(sessionHint)
		if sid == "" {
			sid = shortHash(codexResponsesRequestFirstTitle(reqBody))
		}
		g.agents.recordLLMUsage(ip, "codex", sid, title, codexRequestModel(reqBody), 0, 0)
	}
}

// codexRequestModel pulls the top-level "model" field from a codex
// /backend-api/codex/responses request body. The Codex SSE stream
// doesn't include model in the JSON payload (it ships in the
// OpenAI-Model response header instead), so the request body is the
// only place to source it before the turn completes.
func codexRequestModel(body []byte) string {
	var r struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &r)
	return r.Model
}

// trackLLMUsage parses LLM API request/response bodies for session id,
// title, model, and token usage. Only fires on actual model-invocation
// endpoints; ignores heartbeat / event_logging / mcp / oauth probes.
func (g *Gateway) trackLLMUsage(c net.Conn, kind, path string, reqBody, respBody []byte, sessionHint string) {
	ip := g.agentIPFor(c)
	switch kind {
	case "claude_usage":
		if path != "/v1/messages" {
			return
		}
		reqInfo := parseClaudeRequest(reqBody)
		respModel, in, out := parseClaudeResponse(respBody)
		model := reqInfo.Model
		if model == "" {
			model = respModel
		}
		// Prefer Claude Code's session id from metadata; fall back to
		// hash of first real user message. Skip if neither.
		sid := reqInfo.SessionID
		title := reqInfo.Title
		if sid == "" {
			if title == "" {
				return // heartbeat/probe with no session info
			}
			sid = shortHash(title)
		}
		g.agents.recordLLMUsage(ip, "claude", sid, title, model, in, out)
	case "openai_usage":
		if !strings.HasPrefix(path, "/v1/chat/completions") &&
			!strings.HasPrefix(path, "/v1/responses") &&
			!strings.HasPrefix(path, "/v1/completions") {
			return
		}
		title := openaiFirstUserMessage(reqBody)
		sid := shortHash(title)
		model, in, out := parseOpenAIResponse(respBody)
		if model == "" && in == 0 && out == 0 && title == "" {
			return
		}
		g.agents.recordLLMUsage(ip, "codex", sid, title, model, in, out)
	case "codex_ws_usage":
		// chatgpt.com Codex backend. Two transports:
		//   1. POST /backend-api/codex/responses (SSE stream) — usual path
		//   2. WSS upgrade (handled separately in handleWSUpgrade via
		//      trackCodexWSUsage frame parser). This case only fires for
		//      HTTP-mode requests since WS upgrades return early before
		//      trackLLMUsage.
		if !strings.Contains(path, "/codex/responses") {
			return
		}
		title := codexResponsesRequestTitle(reqBody)
		model, in, out := parseOpenAIResponse(respBody)
		if model == "" && in == 0 && out == 0 && title == "" {
			return
		}
		sid := shortHash(sessionHint)
		if sid == "" {
			sid = shortHash(codexResponsesRequestFirstTitle(reqBody))
		}
		g.agents.recordLLMUsage(ip, "codex", sid, title, model, in, out)
	}
}

// codexResponsesRequestTitle parses a chatgpt.com /backend-api/codex/responses
// POST body and returns the latest user message text. Body shape mirrors
// OpenAI Responses API: {"input":[{"role":"user","content":[{"type":"input_text","text":"..."}]},...]}.
// Reuses codexInputTitle so HTTP and WS paths agree — backward walk skips
// the stale environment_context wrapper that fronts every turn.
func codexResponsesRequestTitle(body []byte) string {
	var req struct {
		Input []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return codexInputTitle(req.Input)
}

// codexResponsesRequestFirstTitle returns the first real user message from
// the request body — stable across turns, used as a session ID seed.
func codexResponsesRequestFirstTitle(body []byte) string {
	var req struct {
		Input []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return codexInputFirstTitle(req.Input)
}

func parseOpenAIResponse(body []byte) (model string, in, out int64) {
	var jr struct {
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			InputTokens      int64 `json:"input_tokens"`
			OutputTokens     int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &jr); err == nil && jr.Model != "" {
		in = jr.Usage.PromptTokens + jr.Usage.InputTokens
		out = jr.Usage.CompletionTokens + jr.Usage.OutputTokens
		return jr.Model, in, out
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
			Model    string `json:"model"`
			Response struct {
				Model string `json:"model"`
				Usage struct {
					InputTokens  int64 `json:"input_tokens"`
					OutputTokens int64 `json:"output_tokens"`
				} `json:"usage"`
			} `json:"response"`
			Usage struct {
				PromptTokens     int64 `json:"prompt_tokens"`
				CompletionTokens int64 `json:"completion_tokens"`
				InputTokens      int64 `json:"input_tokens"`
				OutputTokens     int64 `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		if ev.Model != "" {
			model = ev.Model
		} else if ev.Response.Model != "" {
			model = ev.Response.Model
		}
		in += ev.Usage.PromptTokens + ev.Usage.InputTokens + ev.Response.Usage.InputTokens
		out += ev.Usage.CompletionTokens + ev.Usage.OutputTokens + ev.Response.Usage.OutputTokens
	}
	return
}

// parseClaudeResponse handles both JSON (non-streaming) and SSE
// (streaming) Anthropic /v1/messages responses. Returns model + total
// input/output tokens.
func parseClaudeResponse(body []byte) (model string, in, out int64) {
	// non-streaming JSON
	var jr struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &jr); err == nil && jr.Model != "" {
		in = jr.Usage.InputTokens + jr.Usage.CacheCreationInputTokens + jr.Usage.CacheReadInputTokens
		out = jr.Usage.OutputTokens
		return jr.Model, in, out
	}
	// SSE: walk lines, parse data: payloads
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
				Model string `json:"model"`
				Usage struct {
					InputTokens              int64 `json:"input_tokens"`
					CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
					CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage struct {
				OutputTokens             int64 `json:"output_tokens"`
				InputTokens              int64 `json:"input_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
				CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		if ev.Type == "message_start" && ev.Message.Model != "" {
			model = ev.Message.Model
			in = ev.Message.Usage.InputTokens + ev.Message.Usage.CacheCreationInputTokens + ev.Message.Usage.CacheReadInputTokens
		}
		if ev.Type == "message_delta" {
			out += ev.Usage.OutputTokens
		}
	}
	return
}

type claudeReqInfo struct {
	Model     string
	SessionID string
	Title     string
}

// parseClaudeRequest extracts Claude session metadata + first real user
// message (stripped of system-reminder hook noise) from an Anthropic
// /v1/messages POST body.
func parseClaudeRequest(body []byte) claudeReqInfo {
	var req struct {
		Model    string `json:"model"`
		Metadata struct {
			UserID         string `json:"user_id"`
			SessionID      string `json:"session_id"`
			ConversationID string `json:"conversation_id"`
		} `json:"metadata"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return claudeReqInfo{}
	}
	out := claudeReqInfo{Model: req.Model}
	// Claude Code packs the real session_id inside metadata.user_id as
	// an escaped JSON string: "{\"device_id\":\"...\",\"session_id\":\"<uuid>\"}".
	// Prefer the inner session_id since it's stable across restarts of
	// a single CLI session; fall back to the wrapper hash otherwise.
	innerSession := ""
	if req.Metadata.UserID != "" && strings.HasPrefix(req.Metadata.UserID, "{") {
		var inner struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal([]byte(req.Metadata.UserID), &inner) == nil {
			innerSession = inner.SessionID
		}
	}
	switch {
	case req.Metadata.SessionID != "":
		out.SessionID = "s_" + shortHash(req.Metadata.SessionID)
	case req.Metadata.ConversationID != "":
		out.SessionID = "c_" + shortHash(req.Metadata.ConversationID)
	case innerSession != "":
		out.SessionID = "s_" + shortHash(innerSession)
	case req.Metadata.UserID != "":
		out.SessionID = "u_" + shortHash(req.Metadata.UserID)
	}
	// Title heuristic: take FIRST user message. Skip known probe payloads
	// Claude Code sends to check quota/health (those would otherwise
	// overwrite a real title since recordLLMUsage locks title once set).
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		clean := stripSystemReminders(messageText(m.Content))
		if clean == "" {
			continue
		}
		if isClaudeProbeMessage(clean) {
			break
		}
		out.Title = truncate(clean, 80)
		break
	}
	return out
}

// isClaudeProbeMessage matches single-token health / quota / capability
// probes Claude Code sends (e.g., "quota"). Real prompts like "Hello"
// or "Hi" are NOT probes — we want them as titles.
func isClaudeProbeMessage(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "quota", "ping", "health":
		return true
	}
	return false
}

// messageText concatenates all text from a Claude message Content
// (which is either a string or an array of typed blocks). Joining is
// required because Claude Code packs <system-reminder> blocks and the
// actual user prompt as SEPARATE text blocks; returning only the
// first one yields the reminder, which then gets stripped to empty.
func messageText(c json.RawMessage) string {
	var s string
	if err := json.Unmarshal(c, &s); err == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(c, &blocks); err == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(blk.Text)
		}
		return b.String()
	}
	return ""
}

// stripSystemReminders removes <system-reminder>...</system-reminder>
// blocks (Claude Code injects these via hooks) and returns trimmed text.
func stripSystemReminders(s string) string {
	return stripXMLBlocks(s, "system-reminder")
}

// stripXMLBlocks removes all <tag>...</tag> blocks from s. Used to peel
// off agent-injected wrappers (system-reminder for Claude Code,
// environment_context / user_instructions for Codex CLI) so we can
// surface the human-typed prompt as the session title.
func stripXMLBlocks(s string, tags ...string) string {
	for _, tag := range tags {
		open := "<" + tag + ">"
		closing := "</" + tag + ">"
		for {
			i := strings.Index(s, open)
			if i < 0 {
				break
			}
			j := strings.Index(s[i:], closing)
			if j < 0 {
				s = s[:i]
				break
			}
			s = s[:i] + s[i+j+len(closing):]
		}
	}
	return strings.TrimSpace(s)
}

func openaiFirstUserMessage(body []byte) string {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		var s string
		if err := json.Unmarshal(m.Content, &s); err == nil {
			return truncate(s, 80)
		}
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(m.Content, &blocks); err == nil {
			for _, b := range blocks {
				if b.Text != "" {
					return truncate(b.Text, 80)
				}
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
