package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/denoland/clawpatrol-go/config"
	"github.com/denoland/clawpatrol-go/config/match"
	_ "github.com/denoland/clawpatrol-go/config/plugins/all"
	"github.com/denoland/clawpatrol-go/config/plugins/approvers"
	"github.com/denoland/clawpatrol-go/config/runtime"
)

// Tailscale aliases the operational tailscale-block type loaded from
// HCL. Existing call sites (newWebMux / StartWGServer / newOnboarder /
// mintTailscaleAuthKey) take a value of this type; aliasing keeps
// those signatures unchanged while the canonical definition lives in
// config/.
type Tailscale = config.Tailscale

// emit a terminal request event to both the SSE sink and OTel.
// ev.Action and ev.Ms must be populated. Non-request events (e.g.
// hitl_pending) call g.sink.Emit directly to stay out of the
// request-duration histogram.
func (g *Gateway) emit(ev Event) {
	g.sink.Emit(ev)
	otelRecordVerdict(ev.Action)
	otelRecordRequest(time.Duration(ev.Ms)*time.Millisecond, ev.Action, ev.Status)
}

// loadConfig parses the gateway HCL via the typed-block grammar and
// compiles it into a runtime CompiledPolicy.
func loadConfig(path string) (*config.Gateway, *config.CompiledPolicy, error) {
	gw, diags := config.Load(path)
	if diags.HasErrors() {
		return nil, nil, fmt.Errorf("%s", diags.Error())
	}
	if gw.Listen == "" {
		gw.Listen = ":443"
	}
	if gw.Tailscale == nil {
		gw.Tailscale = &config.Tailscale{}
	}
	cp, err := config.Compile(gw)
	if err != nil {
		return nil, nil, fmt.Errorf("compile: %w", err)
	}
	return gw, cp, nil
}

// orderedProfileNames returns the declared profile names in source
// order. Map iteration over Policy.Profiles isn't deterministic, so
// we re-sort by the Order slice (which buildSymbols populates in
// declaration order) and filter to KindProfile entries.
func orderedProfileNames(p *config.Policy) []string {
	if p == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, name := range p.Order {
		if seen[name] {
			continue
		}
		if _, ok := p.Profiles[name]; ok {
			out = append(out, name)
			seen[name] = true
		}
	}
	for name := range p.Profiles {
		if !seen[name] {
			out = append(out, name)
		}
	}
	return out
}

func peekSNI(c net.Conn) (string, []byte, error) {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", nil, err
	}
	if hdr[0] != 0x16 {
		return "", hdr, errors.New("not TLS")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 42 || recLen > 16384 {
		return "", hdr, errors.New("bad TLS record length")
	}
	rec := make([]byte, recLen)
	if _, err := io.ReadFull(c, rec); err != nil {
		return "", nil, err
	}
	buf := append(hdr, rec...)

	p := rec
	if len(p) < 38 || p[0] != 0x01 {
		return "", buf, errors.New("not ClientHello")
	}
	p = p[38:]
	if len(p) < 1 {
		return "", buf, errors.New("truncated")
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return "", buf, errors.New("truncated sid")
	}
	p = p[sidLen:]
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen+1 {
		return "", buf, errors.New("truncated cs")
	}
	p = p[csLen:]
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen+2 {
		return "", buf, errors.New("truncated cm")
	}
	p = p[cmLen:]
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return "", buf, errors.New("truncated ext")
	}
	exts := p[:extLen]
	for len(exts) >= 4 {
		t := int(exts[0])<<8 | int(exts[1])
		l := int(exts[2])<<8 | int(exts[3])
		exts = exts[4:]
		if l > len(exts) {
			return "", buf, errors.New("truncated ext body")
		}
		if t == 0x00 {
			body := exts[:l]
			if len(body) < 5 {
				return "", buf, errors.New("bad sni")
			}
			n := int(body[3])<<8 | int(body[4])
			if 5+n > len(body) {
				return "", buf, errors.New("truncated sni name")
			}
			return string(body[5 : 5+n]), buf, nil
		}
		exts = exts[l:]
	}
	return "", buf, errors.New("no SNI")
}

type peekConn struct {
	net.Conn
	r io.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *peekConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func wrapPeek(c net.Conn, prefix []byte) net.Conn {
	return &peekConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}

func newUpstreamDialer(resolver string) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if resolver == "" {
		return d
	}
	d.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dd net.Dialer
			return dd.DialContext(ctx, network, resolver)
		},
	}
	return d
}

type Gateway struct {
	cfg     *config.Gateway
	cfgPath string // path the HCL config was loaded from
	db      *sql.DB
	policy  atomic.Pointer[config.CompiledPolicy]
	certs   *CertCache
	dialer  *net.Dialer
	sink    *Sink
	oauth   *OAuthRegistry
	agents  *AgentRegistry
	hitl    *HITLRegistry
	onboard *onboardRegistry
	// secrets hands credential plugins the secret bytes they inject
	// at request time. Default env-var-backed; OAuth-flow credentials
	// land via a follow-up bridge that delegates to OAuthRegistry.
	secrets runtime.SecretStore
	// pgIdx maps WG-forwarder dstIPs to the postgres endpoint that
	// owns them. Rebuilt on every policy load. Lookups are O(1)
	// after the initial DNS resolution.
	pgIdx atomic.Pointer[pgIndex]
}

// Policy returns the current snapshot of the lowered runtime policy.
// nil before the first successful Load. Cheap (atomic load).
func (g *Gateway) Policy() *config.CompiledPolicy {
	return g.policy.Load()
}

// profileFor returns the profile name to use when applying rules /
// looking up OAuth credentials for a given peer IP. Falls back to the
// first declared profile in the config when the peer hasn't been
// assigned (single-tenant default).
func (g *Gateway) profileFor(peerIP string) string {
	if g.onboard != nil {
		if p := g.onboard.ProfileForIP(peerIP); p != "" {
			return p
		}
	}
	if names := orderedProfileNames(g.cfg.Policy); len(names) > 0 {
		return names[0]
	}
	return ""
}

// watchConfig polls the config file's mtime every 3s. On change it
// re-decodes the HCL and atomically swaps in the new rules + admin_email
// + integrations list. Listen ports / CA dir / OAuth dir / Tailscale
// block changes still require a restart (logged but not applied).
func (g *Gateway) watchConfig(path string) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	last := st.ModTime()
	for {
		time.Sleep(3 * time.Second)
		st, err := os.Stat(path)
		if err != nil || !st.ModTime().After(last) {
			continue
		}
		last = st.ModTime()
		next, policy, err := loadConfig(path)
		if err != nil {
			log.Printf("config reload: %v", err)
			continue
		}
		g.policy.Store(policy)
		registerOAuthCredentials(g.oauth, policy)
		g.pgIdx.Store(buildPgIndex(policy))
		// Hot-swap the operational *config.Gateway too — AdminEmail /
		// PublicURL / DashboardSecret reads pick up immediately.
		// Listen / CADir / Tailscale changes are not applied (restart).
		g.cfg = next
		log.Printf("config reloaded: %d endpoints across %d profile(s)",
			len(policy.Endpoints), len(policy.Profiles))
		logDashboardSecretState(next)
	}
}

// logDashboardSecretState emits a one-line summary of dashboard-auth
// state every time the config (re)loads, so an accidentally-open
// dashboard shows up in `journalctl -u clawpatrol-gateway` even when
// nobody opens the dashboard in a browser.
func logDashboardSecretState(cfg *config.Gateway) {
	switch {
	case cfg.DashboardSecret != "":
		log.Printf("dashboard auth: enabled (dashboard_secret set)")
	case cfg.InsecureNoDashboardSecret:
		log.Printf("dashboard auth: DISABLED via insecure_no_dashboard_secret — anyone who reaches the dashboard URL gets in")
	default:
		log.Printf("dashboard auth: MISCONFIGURED — gateway.hcl is missing both dashboard_secret and insecure_no_dashboard_secret; dashboard will refuse to serve until one is set")
	}
}

// trackCodexWSUsage parses a single WebSocket text-frame payload from
// chatgpt.com/codex traffic. Codex sends JSON envelopes containing the
// user prompt (client→server) and usage info (server→client). Sessions
// key by remoteAddr — one logical Codex CLI session per WS connection.
func (g *Gateway) trackCodexWSUsage(remoteAddr string, payload []byte) {
	ip := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ip = h
	}
	sid := "ws_" + shortHash(remoteAddr)
	// Codex Responses-API frames. Three shapes we care about:
	//   client → server: full request envelope w/ `input` (user prompt)
	//     {"input":[{"role":"user","content":[{"type":"input_text","text":"..."}]}],
	//      "model":"...", ...}
	//   server → client: response.created / response.completed
	//     {"type":"response.created","response":{"id":"...","model":"..."}}
	//     {"type":"response.completed","response":{"usage":{...}}}
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
		} `json:"response"`
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
		Input []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"input"`
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
	title := codexInputTitle(msg.Input)
	if in == 0 && out == 0 && model == "" && title == "" {
		return
	}
	g.agents.recordLLMUsage(ip, "codex", sid, title, model, in, out)
}

// codexInputTitle returns the first user text from a Codex Responses-API
// `input` array. Each input item has role + content (which can be either
// a string or an array of typed blocks like input_text/input_image).
func codexInputTitle(input []struct {
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
// always-on; operators don't configure it per rule.
func trackKindFor(host string) string {
	switch host {
	case "api.anthropic.com":
		return "claude_usage"
	case "api.openai.com":
		return "openai_usage"
	case "chatgpt.com":
		return "codex_ws_usage"
	}
	return ""
}

// trackLLMUsage parses LLM API request/response bodies for session id,
// title, model, and token usage. Only fires on actual model-invocation
// endpoints; ignores heartbeat / event_logging / mcp / oauth probes.
func (g *Gateway) trackLLMUsage(c net.Conn, kind, path string, reqBody, respBody []byte) {
	ip := peerIP(c)
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
		// Empty sid → reuse the latest codex session for this device
		// (see findOrAddSession). Each codex CLI run shares a session on
		// the same device; first call w/ a real prompt fills the title.
		g.agents.recordLLMUsage(ip, "codex", "", title, model, in, out)
	}
}

// codexResponsesRequestTitle parses a chatgpt.com /backend-api/codex/responses
// POST body and returns the first user message text. Body shape mirrors
// OpenAI Responses API: {"input":[{"role":"user","content":[{"type":"input_text","text":"..."}]},...]}.
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
	for _, m := range req.Input {
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
		close := "</" + tag + ">"
		for {
			i := strings.Index(s, open)
			if i < 0 {
				break
			}
			j := strings.Index(s[i:], close)
			if j < 0 {
				s = s[:i]
				break
			}
			s = s[:i] + s[i+j+len(close):]
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

// ownerForRequest returns the credential-bucket key for a peer. With
// the profile-as-tenant model, that's the device's assigned profile
// name (devices.profile). Falls back to the peer's onboard-mapped
// owner email and finally peer IP for un-onboarded clients — both
// preserve compatibility with credentials saved before the profile
// migration. Whois lookup remains in place for tailscale-control mode
// where the dashboard still binds creds to the human's login.
func (g *Gateway) ownerForRequest(c net.Conn, _ *OAuthIntegration) string {
	ip := peerIP(c)
	if g.onboard != nil {
		if profile := g.onboard.ProfileForIP(ip); profile != "" {
			return profile
		}
	}
	login := ""
	if g.agents != nil && g.agents.lc != nil {
		if who := g.agents.lookupWhois(ip); who != nil && !who.UserProfile.IsZero() {
			login = who.UserProfile.LoginName
		}
	}
	if (login == "" || login == "tagged-devices") && g.onboard != nil {
		if owner := g.onboard.OwnerForIP(ip); owner != "" {
			return owner
		}
	}
	if login != "" {
		return login
	}
	return ip
}

func (g *Gateway) handle(raw net.Conn) {
	defer raw.Close()
	defer otelTrackConn("https_mitm")()
	host, prefix, err := peekSNI(raw)
	if err != nil {
		log.Printf("sni: %v", err)
		return
	}
	c := wrapPeek(raw, prefix)
	log.Printf("sni-peek: %s", host)
	pip := peerIP(c)
	profile := g.profileFor(pip)
	ep := runtime.HostEndpoint(g.Policy(), profile, host)
	if ep == nil {
		// Host isn't bound to this profile's endpoint set. Apply the
		// `defaults.unknown_host` policy: passthrough today (matches
		// the v14 default). A "deny" mode would close the conn.
		g.splice(c, host)
		return
	}
	switch ep.Family {
	case "https", "k8s":
		// k8s endpoints are HTTPS-underneath; the matcher walk
		// populates K8sMeta from the URL path.
		g.mitmHTTPS(c, host, ep)
	default:
		// postgres / clickhouse_* — wire-protocol handlers land in
		// a follow-up commit. Until then: passthrough.
		log.Printf("endpoint %s family %q: runtime not yet wired; passthrough", ep.Name, ep.Family)
		g.splice(c, host)
	}
}

// handlePostgresConn dispatches an inbound 5432 connection to the
// postgres endpoint runtime. The dstIP comes from the WG forwarder —
// agents resolve real RDS hostnames via public DNS and the gateway
// intercepts at L3, so dstIP is the upstream RDS / postgres server
// address. The endpoint is selected from the device's profile
// (first postgres-family endpoint wins; multi-postgres profiles need
// DNS-aware resolution, tracked as a follow-up).
//
// passthrough fallback when no endpoint applies, mirroring the
// HTTPS handler's `unknown_host = passthrough` default.
func (g *Gateway) handlePostgresConn(c net.Conn, dstIP string) {
	defer c.Close()
	defer otelTrackConn("pg_relay")()
	pip := peerIP(c)
	profile := g.profileFor(pip)

	policy := g.Policy()
	// Try the DNS-resolved IP index first — multi-postgres profiles
	// dispatch correctly when each endpoint's hostname resolves to
	// distinct IPs. When multiple endpoints share an IP (writer +
	// readonly pointing at the same RDS), filter by the device's
	// profile so the right one wins. Fall back to first-postgres-in-
	// profile so single-database profiles work without DNS at all.
	var ep *config.CompiledEndpoint
	if idx := g.pgIdx.Load(); idx != nil {
		candidates := idx.lookup(dstIP)
		ep = pickEndpointForProfile(candidates, policy, profile)
	}
	if ep == nil {
		ep = firstPostgresEndpoint(policy, profile)
	}
	if ep == nil {
		// No postgres policy → relay verbatim. Closes when either
		// side hangs up.
		log.Printf("pg %s: no postgres endpoint in profile %q; relaying", dstIP, profile)
		wgRelay(c, dstIP, 5432)
		return
	}

	connRT, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime)
	if !ok {
		log.Printf("pg endpoint %q plugin lacks ConnEndpointRuntime", ep.Name)
		return
	}

	upstreamAddr := dstIP + ":5432"
	ch := &runtime.ConnHandle{
		Conn:     c,
		Endpoint: ep,
		Policy:   policy,
		Profile:  profile,
		PeerIP:   pip,
		Secrets:  g.secrets,
		DialUpstream: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Plugin asks for ep.Hosts[0]:port; we bypass DNS by
			// dialing the original upstream IP the WG forwarder
			// gave us. Plugin-supplied addr is ignored when it's
			// the endpoint's declared host (the common case).
			if addr == "" {
				addr = upstreamAddr
			}
			return g.dialer.DialContext(ctx, network, upstreamAddr)
		},
		Emit: func(ev runtime.ConnEvent) {
			if g.sink == nil {
				return
			}
			g.sink.Emit(Event{
				Mode: "pg", Host: dstIP, AgentIP: pip,
				Method: ev.Verb, Path: ev.Summary,
				Action: ev.Action, Reason: ev.Reason,
			})
		},
		Approve: func(req runtime.ApproveCallRequest) runtime.ApproveVerdict {
			return g.runApproveChain(context.Background(), req.Stages, runApproveCtx{
				AgentIP: pip, Host: dstIP, Method: req.Verb, Path: req.Summary,
				Reason:   ifNotEmpty(req.Rule, func(r *config.CompiledRule) string { return r.Outcome.Reason }),
				Endpoint: ep, Rule: req.Rule, Profile: profile,
			})
		},
	}
	if err := connRT.HandleConn(context.Background(), ch); err != nil {
		log.Printf("pg %s: %v", dstIP, err)
	}
}

// firstPostgresEndpoint returns the first postgres-family endpoint in
// the device's profile. Multi-postgres profiles need DNS-aware
// matching against the WG forwarder's dstIP — tracked as follow-up;
// the first-match heuristic covers the single-database common case.
// pickEndpointForProfile takes pgIndex.lookup candidates and returns
// the one whose name belongs to the device's profile. Returns nil when
// none of them do — caller should refuse the connection rather than
// silently route through an endpoint the device isn't supposed to
// touch. Single-tenant configs (no profile bound) fall through to
// the first candidate.
func pickEndpointForProfile(candidates []*config.CompiledEndpoint, policy *config.CompiledPolicy, profile string) *config.CompiledEndpoint {
	if len(candidates) == 0 {
		return nil
	}
	if policy == nil || profile == "" {
		return candidates[0]
	}
	prof, ok := policy.Profiles[profile]
	if !ok {
		return candidates[0]
	}
	for _, c := range candidates {
		if _, in := prof.Endpoints[c.Name]; in {
			return c
		}
	}
	return nil
}

func firstPostgresEndpoint(policy *config.CompiledPolicy, profile string) *config.CompiledEndpoint {
	if policy == nil {
		return nil
	}
	prof, ok := policy.Profiles[profile]
	if !ok {
		// Single-tenant fallback: scan every profile.
		for _, p := range policy.Profiles {
			for _, ep := range p.Endpoints {
				if ep.Plugin.Type == "postgres" {
					return ep
				}
			}
		}
		return nil
	}
	for _, ep := range prof.Endpoints {
		if ep.Plugin.Type == "postgres" {
			return ep
		}
	}
	return nil
}

func (g *Gateway) splice(c net.Conn, host string) {
	start := time.Now()
	up, err := g.dialer.Dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		log.Printf("dial %s: %v", host, err)
		g.emit(Event{Mode: "splice", Host: host, AgentIP: peerIP(c), Action: "error", Reason: err.Error(), Ms: time.Since(start).Milliseconds()})
		return
	}
	defer up.Close()
	agentAddr := peerIP(c) // capture BEFORE pipe — RemoteAddr() goes nil once netstack closes the conn
	in, out := pipe(c, up)
	g.emit(Event{Mode: "splice", Host: host, AgentIP: agentAddr, Action: "allow", In: in, Out: out, Ms: time.Since(start).Milliseconds()})
	if g.agents != nil && agentAddr != "" {
		g.agents.track(agentAddr, host, in, out)
	}
}

// pipe shuttles bytes both ways between two conns. Returns (a-rx, a-tx)
// = (bytes received from up into a, bytes sent from a to up). Sends
// CloseWrite half-shutdown on each side after its copy finishes.
func pipe(a, b net.Conn) (rx, tx int64) {
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(b, a)
		atomic.AddInt64(&tx, n)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(a, b)
		atomic.AddInt64(&rx, n)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
	return
}

// mitmHTTPS handles an SNI-matched TLS connection for an HTTPS-family
// endpoint (https, kubernetes). It mints a leaf cert, terminates TLS,
// then loops reading HTTP requests and dispatching each through the
// compiled policy: runtime.MatchRequest picks the rule, the rule's
// Outcome decides verdict / approve. Forwarding is plain TLS upstream
// for now — credential injection (via the credential plugin's
// HTTPCredentialRuntime) lands in a follow-up commit; until then
// matched requests forward verbatim.
func (g *Gateway) mitmHTTPS(c net.Conn, host string, ep *config.CompiledEndpoint) {
	agentAddr := peerIP(c)
	profile := g.profileFor(agentAddr)
	cert, err := g.certs.mint(host)
	if err != nil {
		log.Printf("mint %s: %v", host, err)
		return
	}
	tc := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		log.Printf("mitm tls handshake %s: %v", host, err)
		return
	}
	defer tc.Close()

	transport := &http.Transport{
		DialContext: g.dialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, _, err := net.SplitHostPort(addr)
			if err != nil {
				h = host
			}
			// mTLS-equipped endpoints (k8s API servers, internal
			// CAs) carry a credential whose TLSCredentialRuntime
			// configures the upstream tls.Config — adds a client
			// cert + a custom root pool. Endpoints with no TLS
			// credential dial via plain stdlib TLS.
			return g.dialUpstream(ctx, network, addr, h, ep)
		},
		ForceAttemptHTTP2: false,
		IdleConnTimeout:   30 * time.Second,
	}
	defer transport.CloseIdleConnections()

	br := bufio.NewReader(tc)
	for {
		tc.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF {
				log.Printf("mitm read req %s: %v", host, err)
			}
			return
		}
		tc.SetReadDeadline(time.Time{})

		start := time.Now()
		pip := peerIP(c)

		// Body buffering. Any rule with a `body_json` or
		// `body_contains` match facet needs the body up-front; we
		// don't know which yet, so for any POST/PUT/PATCH with a
		// body we read up to 1 MiB and re-attach. Reads beyond 1 MiB
		// stream through unbuffered (rare for agent traffic).
		var matchBody []byte
		if req.Body != nil && (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {
			b, rdErr := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			req.Body.Close()
			if rdErr == nil {
				matchBody = b
				req.Body = io.NopCloser(bytes.NewReader(b))
				if req.ContentLength > 0 {
					req.ContentLength = int64(len(b))
				}
			}
		}

		mreq := &match.Request{
			Family:  ep.Family,
			Method:  req.Method,
			URL:     req.URL,
			Headers: req.Header,
			Body:    matchBody,
			PeerIP:  pip,
		}
		if ep.Family == "k8s" {
			mreq.K8s = runtime.ParseK8sPath(req.Method, req.URL.RequestURI())
		}

		ev := Event{
			Mode: "mitm", Host: host,
			Method: req.Method, Path: req.URL.Path,
			AgentIP: pip,
		}

		cr := runtime.MatchRequest(ep, mreq)

		// Approve chain — dispatch each stage to its approver
		// runtime (config/plugins/approvers). All stages must
		// allow; first deny short-circuits.
		if cr != nil && len(cr.Outcome.Approve) > 0 {
			v := g.runApproveChain(req.Context(), cr.Outcome.Approve, runApproveCtx{
				AgentIP: pip, Host: host, Method: req.Method, Path: req.URL.Path,
				UA: req.Header.Get("User-Agent"), Reason: cr.Outcome.Reason,
				Endpoint: ep, Rule: cr, Profile: profile,
			})
			if v.Decision != "allow" {
				reason := v.Reason
				if reason == "" {
					reason = "denied by approver"
				}
				log.Printf("hitl-deny %s %s %s: %s (by %s)", host, req.Method, req.URL.Path, reason, v.By)
				fmt.Fprintf(tc, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reason), reason)
				ev.Status = 403
				ev.Action = "hitl_deny"
				ev.Reason = reason
				ev.Ms = time.Since(start).Milliseconds()
				g.emit(ev)
				return
			}
			log.Printf("hitl-allow %s %s %s by %s", host, req.Method, req.URL.Path, v.By)
			ev.Action = "hitl_allow"
		}

		// Verdict.
		if cr != nil && cr.Outcome.Verdict == "deny" {
			reason := cr.Outcome.Reason
			if reason == "" {
				reason = "denied by policy"
			}
			log.Printf("deny %s %s %s: %s (rule %q)", host, req.Method, req.URL.Path, reason, cr.Name)
			fmt.Fprintf(tc, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reason), reason)
			ev.Status = 403
			ev.Action = "deny"
			ev.Reason = reason
			ev.Ms = time.Since(start).Milliseconds()
			g.emit(ev)
			return
		}

		// Forward upstream. Hop-by-hop / proxy-leak headers stripped
		// per RFC 7230 §6.1 plus chatgpt.com / Cloudflare flagged set.
		req.URL.Scheme = "https"
		req.URL.Host = host
		req.Host = host
		req.RequestURI = ""
		for _, h := range []string{
			"Connection", "Keep-Alive", "Proxy-Authenticate",
			"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
			"Cf-Worker", "Cf-Ray", "Cf-Ew-Via", "Cf-Connecting-Ip", "Cdn-Loop",
			"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Via",
		} {
			req.Header.Del(h)
		}

		// Credential injection. Pick the credential entry that
		// applies to this request (singular binding short-circuits;
		// multi-credential dispatch asks the endpoint plugin's
		// PlaceholderDetector which placeholder the agent sent),
		// fetch the secret bytes from the configured store, and
		// hand both to the credential plugin's HTTPCredentialRuntime
		// to stamp onto the request. Schema-only credential types
		// (slack / telegram / gemini / etc.) leave Runtime nil; we
		// pass through verbatim and rely on policy alone.
		if cc := runtime.ResolveCredential(ep, mreq); cc != nil {
			// Plugin.Runtime is a typed-nil sentinel used only for
			// interface-compliance assertions; the actual decoded HCL
			// values (BearerToken.IdempotencyKey, PostgresCredential.User,
			// etc.) live on Body. Invoke methods through Body so the
			// receiver is the real instance.
			if injector, ok := cc.Credential.Body.(runtime.HTTPCredentialRuntime); ok {
				sec, err := g.secrets.Get(cc.Credential.Symbol.Name, pip)
				if err != nil {
					log.Printf("secret %s/%s: %v — forwarding without injection", cc.Credential.Symbol.Name, pip, err)
				} else if len(sec.Bytes) == 0 {
					log.Printf("secret %s/%s: not configured (set CLAWPATROL_SECRET_%s)", cc.Credential.Symbol.Name, pip, secretEnvName(cc.Credential.Symbol.Name))
				} else if err := injector.InjectHTTP(req.Context(), req, sec); err != nil {
					log.Printf("inject %s: %v", cc.Credential.Symbol.Name, err)
				}
			}
		}

		// WebSocket upgrade. http.Transport.RoundTrip mangles the
		// 101 response and Cloudflare's WAF rejects modified frames,
		// so we hand off to a raw byte bridge that forwards the
		// upgrade verbatim and pumps frames untouched. The handler
		// runs until either side closes — when it returns, the
		// caller's request loop ends naturally.
		if isWSUpgrade(req) {
			log.Printf("ws-upgrade %s %s", host, req.URL.Path)
			ev.Action = "ws"
			ev.Ms = time.Since(start).Milliseconds()
			g.emit(ev)
			g.handleWSUpgrade(tc, br, req, host)
			return
		}

		trackKind := trackKindFor(host)
		var trackedReqBody []byte
		if trackKind != "" && req.Body != nil {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			req.Body.Close()
			trackedReqBody = b
			req.Body = io.NopCloser(bytes.NewReader(b))
			if req.ContentLength > 0 {
				req.ContentLength = int64(len(b))
			}
		}
		reqS := newSampler(4096)
		if req.Body != nil {
			req.Body = wrapBodySampler(req.Body, reqS)
		}

		rtStart := time.Now()
		resp, err := transport.RoundTrip(req)
		rtDur := time.Since(rtStart)
		if err != nil {
			log.Printf("mitm upstream %s %s: %v", host, req.URL.Path, err)
			fmt.Fprintf(tc, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			ev.Status = 502
			ev.Action = "error"
			ev.Reason = err.Error()
			ev.Ms = time.Since(start).Milliseconds()
			ev.ReqSha = reqS.sha()
			ev.ReqSample = reqS.sample()
			ev.In = reqS.n
			g.emit(ev)
			return
		}
		var trackBuf *bytes.Buffer
		if trackKind != "" && resp.StatusCode == 200 {
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "json") || strings.Contains(ct, "event-stream") {
				trackBuf = &bytes.Buffer{}
				resp.Body = io.NopCloser(io.TeeReader(resp.Body, trackBuf))
			}
		}
		respS := newSampler(4096)
		resp.Body = wrapBodySampler(resp.Body, respS)
		// Close-delimited responses (no Content-Length, no Transfer-
		// Encoding) come from h2 upstreams that we forced to http/1.1
		// via ALPN — Go's transport leaves cl=-1 and te=[] in that
		// case. Without an explicit terminator, peers (curl, browsers)
		// idle until the conn closes, which the 60s ReadRequest
		// deadline then triggers — a ~60s perceived delay per request.
		// Re-frame as chunked so the peer sees a proper end-of-body.
		if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 && !resp.Close {
			resp.TransferEncoding = []string{"chunked"}
		}
		writeErr := resp.Write(tc)
		_ = rtDur
		resp.Body.Close()
		if trackBuf != nil && g.agents != nil {
			body := trackBuf.Bytes()
			if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
				if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
					if d, err := io.ReadAll(zr); err == nil {
						body = d
					}
					zr.Close()
				}
			}
			g.trackLLMUsage(c, trackKind, req.URL.Path, trackedReqBody, body)
		}

		if ev.Action == "" {
			ev.Action = "allow"
		}
		ev.Status = resp.StatusCode
		ev.In = reqS.n
		ev.Out = respS.n
		ev.ReqSha = reqS.sha()
		ev.ReqSample = reqS.sample()
		ev.RespSha = respS.sha()
		ev.RespSample = respS.sample()
		ev.Ms = time.Since(start).Milliseconds()
		g.emit(ev)
		if g.agents != nil && agentAddr != "" {
			g.agents.trackUA(agentAddr, host, req.UserAgent(), reqS.n, respS.n)
		}

		if writeErr != nil {
			log.Printf("mitm resp write %s: %v", host, writeErr)
			return
		}
		if req.Close || resp.Close {
			return
		}
	}
}

// secretEnvName mirrors EnvSecretStore's lookup key derivation so log
// messages can hint at the exact var name an operator should set.
// Uppercase, hyphens → underscores.
func secretEnvName(credName string) string {
	return strings.ToUpper(strings.ReplaceAll(credName, "-", "_"))
}

// defaultHITLTimeout returns the configured human approver timeout
// (defaults.human_timeout) or the legacy 60s default when nothing
// is configured. Per-approver timeouts overlay this in a follow-up.
// runApproveCtx is the context blob the dispatcher passes per stage —
// HITL prompt fields + the matching rule + the device's profile.
type runApproveCtx struct {
	AgentIP    string
	Host       string
	Method     string
	Path       string
	UA         string
	BodySample string
	Reason     string
	Endpoint   *config.CompiledEndpoint
	Rule       *config.CompiledRule
	Profile    string
}

// runApproveChain dispatches each stage of an approve = [...] list to
// the matching approver entity's runtime. All-must-allow semantics —
// the first non-allow verdict short-circuits and is returned. Built-in
// `dashboard` is handled inline (no policy entity needed).
func (g *Gateway) runApproveChain(ctx context.Context, stages []config.ApproveStage, c runApproveCtx) runtime.ApproveVerdict {
	policy := g.Policy()
	for _, st := range stages {
		var ar runtime.ApproverRuntime
		if st.Name == "dashboard" {
			ar = approvers.DashboardApprover{}
		} else if policy != nil {
			if ent, ok := policy.Approvers[st.Name]; ok {
				if rt, ok := ent.Body.(runtime.ApproverRuntime); ok {
					ar = rt
				}
			}
		}
		if ar == nil {
			return runtime.ApproveVerdict{Decision: "deny", Reason: "approver " + st.Name + " not found", By: "gateway"}
		}
		req := runtime.ApproveRequest{
			Stage:        st,
			Endpoint:     c.Endpoint,
			Rule:         c.Rule,
			ApproverName: st.Name,
			Profile:      c.Profile,
			Method:       c.Method,
			Host:         c.Host,
			Path:         c.Path,
			UA:           c.UA,
			BodySample:   c.BodySample,
			Reason:       c.Reason,
			Pool:         g.hitl,
			Secrets:      g.secrets,
			DashboardURL: g.cfg.PublicURL,
			Policy:       policy,
		}
		if policy != nil {
			req.Defaults = policy.Defaults
		}
		v, err := ar.Approve(ctx, req)
		if err != nil {
			return runtime.ApproveVerdict{Decision: "deny", Reason: err.Error(), By: "gateway"}
		}
		if v.Decision != "allow" {
			if v.Decision == "" {
				v.Decision = "deny"
				if v.Reason == "" {
					v.Reason = "approver " + st.Name + " timed out"
				}
			}
			return v
		}
	}
	return runtime.ApproveVerdict{Decision: "allow"}
}

// ifNotEmpty returns f(v) when v != nil, else "".
func ifNotEmpty(r *config.CompiledRule, f func(*config.CompiledRule) string) string {
	if r == nil {
		return ""
	}
	return f(r)
}

func defaultHITLTimeout(p *config.CompiledPolicy) time.Duration {
	if p != nil && p.Defaults.HumanTimeout > 0 {
		return time.Duration(p.Defaults.HumanTimeout) * time.Second
	}
	return 60 * time.Second
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "gateway":
		runGateway(os.Args[2:])
	case "login":
		runLogin(os.Args[2:])
	case "join":
		runJoin(os.Args[2:])
	case "run":
		runRun(os.Args[2:])
	case "env":
		runEnv(os.Args[2:])
	case "init-ca":
		runInitCA(os.Args[2:])
	case "version":
		fmt.Println("clawpatrol 0.1")
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
	}
}

func peerIP(c net.Conn) string {
	if c == nil {
		return ""
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func usage() {
	fmt.Fprintln(os.Stderr, `clawpatrol — secret-injection MITM proxy for AI agents

usage:
  clawpatrol gateway [-config FILE]    run the gateway server
  clawpatrol login                     onboard this machine (set exit-node + install CA)
  clawpatrol env                       print shell exports for sourcing
  clawpatrol init-ca DIR               generate a new CA in DIR
  clawpatrol version`)
	os.Exit(2)
}

func runInitCA(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: clawpatrol init-ca DIR")
		os.Exit(2)
	}
	if err := writeCA(args[0]); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote ca.crt + ca.key to %s\n", args[0])
}

func runGateway(args []string) {
	// `clawpatrol gateway init` is a one-shot setup wizard, distinct from
	// `clawpatrol gateway -config …` which starts the long-running daemon.
	if len(args) > 0 && args[0] == "init" {
		runGatewayInit(args[1:])
		return
	}
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "config file")
	_ = fs.Parse(args)

	startModelRefresh()
	cfg, policy, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	logDashboardSecretState(cfg)
	certs, err := loadCA(cfg.CADir)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	stateDir := cfg.OAuthDir
	if stateDir == "" {
		stateDir = filepath.Join(cfg.CADir, "..", "oauth")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Fatalf("state dir: %v", err)
	}
	db, err := OpenDB(filepath.Join(stateDir, "clawpatrol.db"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	setDB(db)
	sink, err := NewSink(db, 4096)
	if err != nil {
		log.Fatalf("log: %v", err)
	}
	oauthDir := cfg.OAuthDir
	if oauthDir == "" {
		oauthDir = filepath.Join(cfg.CADir, "..", "oauth")
	}
	// OAuthRegistry seed list is empty for now — credential plugins
	// own credential discovery in the new policy. The registry stays
	// in place because per-owner token persistence + refresh logic
	// is reused by the credential-plugin runtime bridge (lands when
	// the credential injection path is wired into mitmHTTPS).
	_ = oauthDir
	oauthReg, err := NewOAuthRegistry(nil, db)
	if err != nil {
		log.Fatalf("oauth: %v", err)
	}
	g := &Gateway{
		cfg:     cfg,
		cfgPath: *cfgPath,
		db:      db,
		certs:   certs,
		dialer:  newUpstreamDialer(cfg.Resolver),
		sink:    sink,
		oauth:   oauthReg,
		agents:  NewAgentRegistry(),
		hitl:    newHITLRegistry(sink),
		onboard: newOnboardRegistry(),
	}
	g.secrets = newGatewaySecretStore(db, oauthReg)
	registerOAuthCredentials(oauthReg, policy)
	g.policy.Store(policy)
	g.pgIdx.Store(buildPgIndex(policy))
	log.Printf("policy: %d endpoints across %d profiles", len(policy.Endpoints), len(policy.Profiles))
	go g.watchConfig(*cfgPath)
	if err := g.onboard.Load(db); err != nil {
		log.Fatalf("onboard load: %v", err)
	}
	g.agents.onboard = g.onboard
	// Seed agent entries for every persisted device so the dashboard
	// renders them on boot, before any traffic arrives. Without this,
	// devices disappear after every gateway restart and only reappear
	// on the next request from each peer.
	if rows, err := db.Query("SELECT id FROM devices"); err == nil {
		for rows.Next() {
			var ip string
			if rows.Scan(&ip) == nil {
				g.agents.Seed(ip)
			}
		}
		rows.Close()
	}

	// HITL notifications fan-out via the approver runtimes
	// (config/plugins/approvers); the registry's Add hook emits
	// the SSE event for the dashboard.

	if _, err := StartOtel(g); err != nil {
		log.Printf("otel: %v", err)
	}

	if cfg.InfoListen != "" {
		mux := newWebMux(g, cfg.CADir, *cfg.Tailscale, cfg.PublicURL)
		go func() {
			http.ListenAndServe(cfg.InfoListen, mux)
		}()
		printDashboardURL(cfg.InfoListen)
	}
	go g.servePorts()

	// Embedded userspace WireGuard server. When operator sets
	// tailscale.control=wireguard, the clawpatrol process becomes the
	// WG endpoint — peers established at onboard time route ALL
	// traffic into our netstack (AllowedIPs=0.0.0.0/0). The
	// promiscuous forwarder accepts SYNs to any dst IP/port:
	//   - 443    → MITM (g.handle does SNI peek + rule dispatch)
	//   - dash   → dashboard mux
	//   - else   → transparent relay to the real upstream
	// No /etc/hosts hack needed on clients — agents resolve real
	// hostnames via public DNS and the gateway intercepts at L3.
	if strings.EqualFold(cfg.Tailscale.Control, "wireguard") {
		wg, err := StartWGServer(*cfg.Tailscale, stateDir)
		if err != nil {
			log.Fatalf("wireguard: %v", err)
		}
		setWGServer(wg)
		dashMux := newWebMux(g, cfg.CADir, *cfg.Tailscale, cfg.PublicURL)
		dashPort := portOf(cfg.InfoListen)
		if err := wg.EnablePromiscuousForwarder(func(c net.Conn, dstIP string, dstPort uint16) {
			log.Printf("wg-fwd: %s:%d", dstIP, dstPort)
			switch {
			case dstPort == 443:
				g.handle(c)
			case dstPort == 5432:
				g.handlePostgresConn(c, dstIP)
			case dashPort != 0 && int(dstPort) == dashPort:
				_ = http.Serve(&oneShotListener{c: c}, dashMux)
			default:
				// Anything else relays transparently until its
				// endpoint plugin's wire-protocol runtime ships
				// (clickhouse_native, etc.).
				wgRelay(c, dstIP, int(dstPort))
			}
		}); err != nil {
			log.Fatalf("wireguard forwarder: %v", err)
		}
		log.Printf("wireguard promiscuous forwarder ready (any dst → :443=mitm, :5432=pg, :%d=dash, else=relay)", dashPort)
	}

	ln, err := openListener(cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("gateway listening on %s, %d endpoints across %d profiles",
		ln.Addr(), len(policy.Endpoints), len(policy.Profiles))

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go g.handle(c)
	}
}

// portOf extracts the numeric port from a "host:port" or ":port" listen
// string. Returns 0 when the input is empty or unparseable.
func portOf(addr string) int {
	if addr == "" {
		return 0
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// oneShotListener wraps a single net.Conn so http.Serve can hand it to
// the dashboard mux. After the first Accept, subsequent calls block
// until Close — the netstack forwarder spawns one goroutine per conn
// so http.Serve cleanly exits when the connection ends.
type oneShotListener struct {
	c    net.Conn
	done chan struct{}
	once bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.once {
		<-l.done
		return nil, net.ErrClosed
	}
	l.once = true
	if l.done == nil {
		l.done = make(chan struct{})
	}
	return l.c, nil
}

func (l *oneShotListener) Close() error {
	if l.done != nil {
		select {
		case <-l.done:
		default:
			close(l.done)
		}
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	if l.c == nil {
		return &net.TCPAddr{}
	}
	return l.c.LocalAddr()
}

// wgRelay is the catch-all path: WG peer wants to talk to a host we
// don't MITM (plain HTTP, ssh, anything not on :443 or the dash port).
// Dials the real dst from the host network and pipes bytes both ways.
func wgRelay(c net.Conn, dstIP string, dstPort int) {
	defer c.Close()
	up, err := net.DialTimeout("tcp", net.JoinHostPort(dstIP, strconv.Itoa(dstPort)), 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	pipe(c, up)
}
