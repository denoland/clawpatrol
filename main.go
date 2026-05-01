package main

import (
	"bufio"
	"bytes"
	"context"
	"compress/gzip"
	"crypto/tls"
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

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen           string             `yaml:"listen"`
	InfoListen       string             `yaml:"info_listen"`
	PublicURL        string             `yaml:"public_url"` // shown in dashboard "add device" modal so new clients reach gateway from public internet
	// AdminEmail is the operator's identity in single-tenant
	// (wireguard / proxy) mode where there's no tailnet whois. All
	// onboard approvals get attributed to this email so per-user
	// OAuth credential lookup works.
	AdminEmail string `yaml:"admin_email,omitempty"`
	CADir            string             `yaml:"ca_dir"`
	Resolver         string             `yaml:"resolver"`
	LogPath          string             `yaml:"log_path"`
	OAuthDir         string             `yaml:"oauth_dir"`
	Tailscale        Tailscale          `yaml:"tailscale"`
	IntegrationNames []string           `yaml:"integrations"`
	OAuth            []OAuthIntegration `yaml:"oauth"`
	Rules            []Rule             `yaml:"rules"`
}

type Tailscale struct {
	AuthKey    string `yaml:"authkey"`
	ControlURL string `yaml:"control_url"`
	Hostname   string `yaml:"hostname"`
	StateDir   string `yaml:"state_dir"`

	// Control is "tailscale" (default) or "headscale". Picks which
	// onboarder mints auth-keys when new clients run `clawpatrol join`.
	Control string `yaml:"control"`

	// OAuth client used to mint single-use auth-keys for new clients
	// during `clawpatrol login --url ...` device-flow onboarding. Create
	// an OAuth client at https://login.tailscale.com/admin/settings/oauth
	// with the `auth_keys` scope.  (control=tailscale)
	OAuthClientID     string   `yaml:"oauth_client_id"`
	OAuthClientSecret string   `yaml:"oauth_client_secret"`
	Tags              []string `yaml:"tags"` // tags applied to onboarded devices, e.g. ["tag:client"]

	// Plain WireGuard self-host. (control=wireguard)
	// Gateway runs `wg-quick` on its own, mints a peer config per
	// onboard. No control server, no SaaS.
	WGInterface  string `yaml:"wg_interface"`   // e.g. "wg0"
	WGEndpoint   string `yaml:"wg_endpoint"`    // public host:port for AllowedIPs routing
	WGServerPub  string `yaml:"wg_server_pub"`  // gateway's wg public key
	WGSubnetCIDR string `yaml:"wg_subnet_cidr"` // pool we allocate from, e.g. "10.42.0.0/24"
}

type Rule struct {
	// Device scopes the rule. Empty = global (applies to all peers).
	// Otherwise matched against the peer's tailnet IP.
	// Device-scoped rules take precedence over globals.
	Device   string            `yaml:"device,omitempty" json:"device,omitempty"`
	Host     string            `yaml:"host" json:"host"`
	Port     int               `yaml:"port,omitempty" json:"port,omitempty"`
	Match    *Match            `yaml:"match,omitempty" json:"match,omitempty"`
	Action   string            `yaml:"action,omitempty" json:"action,omitempty"`
	Reason   string            `yaml:"reason,omitempty" json:"reason,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Swap     []Swap            `yaml:"swap,omitempty" json:"swap,omitempty"`
	WSScan   bool              `yaml:"ws_scan,omitempty" json:"ws_scan,omitempty"`
	Body     bool              `yaml:"body,omitempty" json:"body,omitempty"`
	Upstream string            `yaml:"upstream,omitempty" json:"upstream,omitempty"`
	Auth     string            `yaml:"auth,omitempty" json:"auth,omitempty"`
	Track    string            `yaml:"track,omitempty" json:"track,omitempty"` // "claude_usage" | "openai_usage"
	// Action="hitl" pauses the request, asks for human approval via
	// the dashboard (and any registered notifier plugin like web-push
	// or slack). HITLTimeout caps the wait; default 60s. On timeout
	// the request is denied.
	HITLTimeout int `yaml:"hitl_timeout,omitempty" json:"hitl_timeout,omitempty"` // seconds
	// MTLS configures the gateway-to-upstream client certificate
	// presented when dialing this rule's host. Used for endpoints
	// like the Kubernetes API server that authenticate via client
	// cert rather than a bearer token. Paths point at PEM files
	// readable by the gateway process.
	MTLS *MTLSConfig `yaml:"mtls,omitempty" json:"mtls,omitempty"`
}

type MTLSConfig struct {
	CA   string `yaml:"ca" json:"ca"`     // path to PEM (optional — pinning upstream cert)
	Cert string `yaml:"cert" json:"cert"` // path to client cert PEM
	Key  string `yaml:"key" json:"key"`   // path to client key PEM
}

type Swap struct {
	Placeholder string `yaml:"placeholder" json:"placeholder"`
	Secret      string `yaml:"secret" json:"secret"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":443"
	}
	return &c, nil
}

func (r *Rule) matches(host string) bool {
	if r.Host == host {
		return true
	}
	if strings.HasPrefix(r.Host, "*.") {
		return strings.HasSuffix(host, r.Host[1:])
	}
	return false
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

// ensureAnthropicBeta appends `beta` to the comma-separated
// `anthropic-beta` request header if missing. Anthropic gates
// experimental features (including OAuth bearer-token auth) behind
// these tokens — without `oauth-2025-04-20`, OAuth requests get
// rejected with "OAuth authentication is currently not supported".
func ensureAnthropicBeta(h http.Header, beta string) {
	cur := h.Get("anthropic-beta")
	if cur == "" {
		h.Set("anthropic-beta", beta)
		return
	}
	for _, p := range strings.Split(cur, ",") {
		if strings.TrimSpace(p) == beta {
			return
		}
	}
	h.Set("anthropic-beta", cur+","+beta)
}

func resolveTemplate(s string) string {
	out := s
	for {
		i := strings.Index(out, "{{secret:")
		if i < 0 {
			break
		}
		j := strings.Index(out[i:], "}}")
		if j < 0 {
			break
		}
		name := out[i+9 : i+j]
		val := os.Getenv(name)
		out = out[:i] + val + out[i+j+2:]
	}
	return out
}

func injectHeaders(h http.Header, rule *Rule) {
	for name, tmpl := range rule.Headers {
		h.Set(name, resolveTemplate(tmpl))
	}
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
	cfg     *Config
	rules   []Rule
	certs   *CertCache
	dialer  *net.Dialer
	sink    *Sink
	oauth   *OAuthRegistry
	agents  *AgentRegistry
	hitl    *HITLRegistry
	onboard *onboardRegistry
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

// ownerForRequest returns the user-scoped credential-owner key for a
// peer. Falls back to peer IP when whois unavailable. For tagged
// (onboarded) devices, the override populated by /api/onboard/claim
// resolves the IP to the human approver — without it, Tailscale OAuth
// only reports "tagged-devices" and per-user credential lookups miss.
func (g *Gateway) ownerForRequest(c net.Conn, _ *OAuthIntegration) string {
	ip := peerIP(c)
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
	host, prefix, err := peekSNI(raw)
	if err != nil {
		log.Printf("sni: %v", err)
		return
	}
	c := wrapPeek(raw, prefix)
	log.Printf("sni-peek: %s", host)
	hostRule := selectHostRule(g.rules, host, peerIP(c))
	if hostRule == nil {
		g.splice(c, host)
		return
	}
	if hostRule.Match == nil && hostRule.Action == "deny" {
		log.Printf("deny %s: %s", host, hostRule.Reason)
		return
	}
	g.mitm(c, host, hostRule)
}

func (g *Gateway) splice(c net.Conn, host string) {
	start := time.Now()
	up, err := g.dialer.Dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		log.Printf("dial %s: %v", host, err)
		g.sink.Emit(Event{Mode: "splice", Host: host, AgentIP: peerIP(c), Action: "error", Reason: err.Error(), Ms: time.Since(start).Milliseconds()})
		return
	}
	defer up.Close()
	var bytesIn, bytesOut int64
	defer func() {
		g.sink.Emit(Event{Mode: "splice", Host: host, AgentIP: peerIP(c), Action: "allow", In: bytesIn, Out: bytesOut, Ms: time.Since(start).Milliseconds()})
		if g.agents != nil {
			g.agents.track(c.RemoteAddr().String(), host, bytesIn, bytesOut)
		}
	}()
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(up, c)
		atomic.AddInt64(&bytesOut, n)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(c, up)
		atomic.AddInt64(&bytesIn, n)
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (g *Gateway) mitm(c net.Conn, host string, defaultRule *Rule) {
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
			// Per-host mTLS for endpoints like the Kubernetes API
			// server. Falls back to plain TLS when rule.MTLS is nil.
			if defaultRule.MTLS != nil {
				return dialMTLSUpstream(ctx, network, addr, h, defaultRule.MTLS)
			}
			return dialUpstreamTLS(ctx, network, addr, h)
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
		rule := selectRequestRule(g.rules, host, peerIP(c), req)
		// If the host-level default rule has a Match that didn't fire for
		// this request (e.g. method:[POST] and request is GET), don't
		// fall back to it — a GET shouldn't inherit a POST-only deny.
		// Use a stripped passthrough rule (preserves host metadata for
		// logging but no auth/swap/track/action).
		if rule == nil {
			if defaultRule.Match == nil {
				rule = defaultRule
			} else {
				rule = &Rule{Host: defaultRule.Host}
			}
		}
		ev := Event{
			Mode: "mitm", Host: host,
			Method: req.Method, Path: req.URL.Path,
			AgentIP: peerIP(c),
		}
		if rule.Action == "hitl" {
			pending := &HITLPending{
				AgentIP: peerIP(c),
				Host:    host,
				Method:  req.Method,
				Path:    req.URL.Path,
				UA:      req.Header.Get("User-Agent"),
				Reason:  rule.Reason,
			}
			timeout := time.Duration(rule.HITLTimeout) * time.Second
			d := g.hitl.Wait(req.Context(), pending, timeout)
			if !d.Allow {
				reason := d.Reason
				if reason == "" {
					reason = "denied by approver"
				}
				log.Printf("hitl-deny %s %s %s: %s (by %s)", host, req.Method, req.URL.Path, reason, d.By)
				fmt.Fprintf(tc, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reason), reason)
				ev.Status = 403
				ev.Action = "hitl_deny"
				ev.Reason = reason
				ev.Ms = time.Since(start).Milliseconds()
				g.sink.Emit(ev)
				return
			}
			log.Printf("hitl-allow %s %s %s by %s", host, req.Method, req.URL.Path, d.By)
			ev.Action = "hitl_allow"
		}
		if rule.Action == "deny" {
			reason := rule.Reason
			if reason == "" {
				reason = "denied by policy"
			}
			log.Printf("deny %s %s %s: %s", host, req.Method, req.URL.Path, reason)
			fmt.Fprintf(tc, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reason), reason)
			ev.Status = 403
			ev.Action = "deny"
			ev.Reason = reason
			ev.Ms = time.Since(start).Milliseconds()
			g.sink.Emit(ev)
			return
		}

		upstream := host
		if rule.Upstream != "" {
			upstream = rule.Upstream
		}
		req.URL.Scheme = "https"
		req.URL.Host = upstream
		req.Host = upstream
		req.RequestURI = ""
		scanReplaceHeaders(req.Header, rule.Swap)
		if rule.Auth != "" {
			it := g.oauth.Integration(rule.Auth)
			if it == nil {
				log.Printf("rule references unknown oauth integration: %s", rule.Auth)
			} else {
				owner := g.ownerForRequest(c, it)
				if overrode, err := g.oauth.Inject(rule.Auth, owner, req); err != nil {
					log.Printf("oauth %s/%s inject: %v", rule.Auth, owner, err)
				} else if !overrode {
					log.Printf("oauth %s/%s: no token yet — passing agent header through", rule.Auth, owner)
				} else if rule.Auth == "claude" {
					// Anthropic rejects OAuth tokens (sk-ant-oat01-…)
					// without `anthropic-beta: oauth-2025-04-20` in
					// the request — "OAuth authentication is
					// currently not supported". Append (preserving
					// any existing comma-separated betas the agent
					// already set, like prompt-caching).
					ensureAnthropicBeta(req.Header, "oauth-2025-04-20")
					req.Header.Del("x-api-key") // OAuth flow uses Authorization, not x-api-key
				}
			}
		}
		injectHeaders(req.Header, rule)
		if isWSUpgrade(req) && rule.WSScan {
			g.handleWSUpgrade(tc, br, req, rule, upstream)
			return
		}
		var trackedReqBody []byte
		if rule.Track != "" && req.Body != nil {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			req.Body.Close()
			trackedReqBody = b
			req.Body = io.NopCloser(bytes.NewReader(b))
			if req.ContentLength > 0 {
				req.ContentLength = int64(len(b))
			}
		}
		if rule.Body && req.Body != nil && req.ContentLength > 0 && req.ContentLength < 1<<20 {
			b, err := io.ReadAll(req.Body)
			req.Body.Close()
			if err == nil {
				b = scanReplaceBytes(b, rule.Swap)
				req.Body = io.NopCloser(bytes.NewReader(b))
				req.ContentLength = int64(len(b))
				req.Header.Set("Content-Length", fmt.Sprintf("%d", len(b)))
			}
		}
		reqS := newSampler(4096)
		if req.Body != nil {
			req.Body = wrapBodySampler(req.Body, reqS)
		}
		for _, h := range []string{
			// hop-by-hop (RFC 7230 §6.1)
			"Connection", "Keep-Alive", "Proxy-Authenticate",
			"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
			// proxy-leak headers — chatgpt.com / Cloudflare WAF flag these
			// and respond with "Attack attempt detected". Strip so the
			// upstream sees a clean client request.
			"Cf-Worker", "Cf-Ray", "Cf-Ew-Via", "Cf-Connecting-Ip", "Cdn-Loop",
			"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Via",
		} {
			req.Header.Del(h)
		}

		resp, err := transport.RoundTrip(req)
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
			g.sink.Emit(ev)
			return
		}
		var trackBuf *bytes.Buffer
		if rule.Track != "" && resp.StatusCode == 200 {
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "json") || strings.Contains(ct, "event-stream") {
				trackBuf = &bytes.Buffer{}
				resp.Body = io.NopCloser(io.TeeReader(resp.Body, trackBuf))
			}
		}
		respS := newSampler(4096)
		resp.Body = wrapBodySampler(resp.Body, respS)
		writeErr := resp.Write(tc)
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
			g.trackLLMUsage(c, rule.Track, req.URL.Path, trackedReqBody, body)
		}

		ev.Status = resp.StatusCode
		ev.Action = "allow"
		ev.In = reqS.n
		ev.Out = respS.n
		ev.ReqSha = reqS.sha()
		ev.ReqSample = reqS.sample()
		ev.RespSha = respS.sha()
		ev.RespSample = respS.sample()
		ev.Ms = time.Since(start).Milliseconds()
		g.sink.Emit(ev)
		if g.agents != nil {
			g.agents.trackUA(c.RemoteAddr().String(), host, req.UserAgent(), reqS.n, respS.n)
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
	case "env":
		runEnv(os.Args[2:])
	case "auth":
		runAuth(os.Args[2:])
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
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

func usage() {
	fmt.Fprintln(os.Stderr, `clawpatrol — secret-injection MITM proxy for AI agents

usage:
  clawpatrol gateway [-config FILE]    run the gateway server
  clawpatrol login                     onboard this machine (set exit-node + install CA)
  clawpatrol env                       print shell exports for sourcing
  clawpatrol auth ID                   run browser OAuth flow, capture refresh token
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
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := expandDefaults(cfg); err != nil {
		log.Fatalf("expand defaults: %v", err)
	}
	// runtime override (from dashboard rule edits) wins over config file
	overrideFile := rulesOverrideFile(cfg)
	if b, err := os.ReadFile(overrideFile); err == nil {
		var override []Rule
		if err := yaml.Unmarshal(b, &override); err == nil {
			cfg.Rules = override
			log.Printf("loaded rule override (%d rules) from %s", len(override), overrideFile)
		}
	}
	rules := cfg.Rules
	certs, err := loadCA(cfg.CADir)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	sink, err := NewSink(cfg.LogPath, 4096)
	if err != nil {
		log.Fatalf("log: %v", err)
	}
	oauthDir := cfg.OAuthDir
	if oauthDir == "" {
		oauthDir = filepath.Join(cfg.CADir, "..", "oauth")
	}
	oauthReg, err := NewOAuthRegistry(cfg.OAuth, oauthDir)
	if err != nil {
		log.Fatalf("oauth: %v", err)
	}
	g := &Gateway{
		cfg:     cfg,
		rules:   rules,
		certs:   certs,
		dialer:  newUpstreamDialer(cfg.Resolver),
		sink:    sink,
		oauth:   oauthReg,
		agents:  NewAgentRegistry(),
		hitl:    newHITLRegistry(),
		onboard: newOnboardRegistry(),
	}
	g.onboard.Load(cfg.OAuthDir)
	// always-on built-in HITL notifier: fan-out to dashboard SSE.
	g.hitl.Register(&hitlSinkNotifier{sink: g.sink})

	if cfg.InfoListen != "" {
		mux := newWebMux(g, cfg.CADir, cfg.Tailscale, cfg.PublicURL)
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
		wg, err := StartWGServer(cfg.Tailscale, oauthDir)
		if err != nil {
			log.Fatalf("wireguard: %v", err)
		}
		setWGServer(wg)
		dashMux := newWebMux(g, cfg.CADir, cfg.Tailscale, cfg.PublicURL)
		dashPort := portOf(cfg.InfoListen)
		if err := wg.EnablePromiscuousForwarder(func(c net.Conn, dstIP string, dstPort uint16) {
			switch {
			case dstPort == 443:
				g.handle(c)
			case dashPort != 0 && int(dstPort) == dashPort:
				_ = http.Serve(&oneShotListener{c: c}, dashMux)
			default:
				wgRelay(c, dstIP, int(dstPort))
			}
		}); err != nil {
			log.Fatalf("wireguard forwarder: %v", err)
		}
		log.Printf("wireguard promiscuous forwarder ready (any dst → :443=mitm, :%d=dash, else=relay)", dashPort)
	}

	ln, err := openListener(cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("gateway listening on %s, %d rules", ln.Addr(), len(cfg.Rules))

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
// don't MITM (e.g. plain HTTP, ssh, anything not on :443 or the dash
// port). We just dial the real destination from the gateway's host
// network and proxy bytes both ways. Lets agents reach github.com,
// package mirrors, etc., without exempting them in routing config.
func wgRelay(c net.Conn, dstIP string, dstPort int) {
	defer c.Close()
	up, err := net.DialTimeout("tcp", net.JoinHostPort(dstIP, strconv.Itoa(dstPort)), 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

