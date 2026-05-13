package endpoints

// anthropic endpoint: HTTPS-shaped provider plugin for
// api.anthropic.com. Carries both the http facet (so existing
// http_rule predicates on method / path / headers keep matching) and
// the llm facet, which the runtime populates from the Anthropic
// Messages API request + response. Streaming responses are
// concatenated SSE byte streams; non-streaming responses are JSON.
//
// Sample HCL:
//
//	credential "bearer_token" "anthropic" {}
//
//	endpoint "anthropic" "claude" {
//	  hosts      = ["api.anthropic.com"]
//	  credential = anthropic
//	}

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	llmfacet "github.com/denoland/clawpatrol/config/plugins/facets/llm"
	"github.com/denoland/clawpatrol/config/runtime"
)

// AnthropicEndpoint is part of the clawpatrol plugin API.
type AnthropicEndpoint struct {
	Hosts          []string  `hcl:"hosts,optional"`
	Credential     string    `hcl:"credential,optional"`
	CredentialsRaw cty.Value `hcl:"credentials,optional" json:"-"`

	Credentials []CredentialEntry `json:"Credentials,omitempty"`
}

// EndpointHosts is part of the clawpatrol plugin API. Defaults to
// api.anthropic.com so the common single-host case is one-line HCL.
func (e *AnthropicEndpoint) EndpointHosts() []string {
	if len(e.Hosts) == 0 {
		return []string{"api.anthropic.com"}
	}
	return e.Hosts
}

// EndpointCredentials is part of the clawpatrol plugin API.
func (e *AnthropicEndpoint) EndpointCredentials() []config.CredBinding {
	return bindings(e.Credential, e.Credentials)
}

func (e *AnthropicEndpoint) credentialAndRaw() (string, cty.Value) {
	return e.Credential, e.CredentialsRaw
}

func (e *AnthropicEndpoint) setCredentialEntries(es []CredentialEntry) {
	e.Credentials = es
}

// AnthropicEndpointRuntime detects placeholders in the same
// Authorization / x-api-key headers Anthropic accepts and parses the
// Messages API for LLM facets.
type AnthropicEndpointRuntime struct{}

// DetectPlaceholder mirrors the default HTTPS detector but also scans
// x-api-key (Anthropic's preferred header) — agents that bind their
// credential placeholder there must still resolve.
func (AnthropicEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil || req.Headers == nil {
		return ""
	}
	hay := req.Headers.Get("Authorization") + "\x00" + req.Headers.Get("x-api-key")
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

// ParseLLMRequest extracts provider / model / stream from a Messages
// API request body. Returns nil for non-JSON / unparseable bodies so
// the dispatcher omits LLM facets cleanly on non-API paths.
func (AnthropicEndpointRuntime) ParseLLMRequest(reqBody []byte) any {
	if len(reqBody) == 0 {
		return nil
	}
	var req struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return nil
	}
	if req.Model == "" {
		return nil
	}
	return &llmfacet.Meta{
		Provider: "anthropic",
		Model:    req.Model,
		Stream:   req.Stream,
	}
}

// ParseLLMResponse amends the pre-flight Meta with token counts and
// stop_reason extracted from the response. Streaming responses
// arrive as concatenated SSE bytes — the parser walks them
// line-by-line and lifts usage from the message_delta event and the
// final message_stop. Non-streaming responses are full JSON.
func (AnthropicEndpointRuntime) ParseLLMResponse(reqBody, respBody []byte, pre any) any {
	m, _ := pre.(*llmfacet.Meta)
	if m == nil {
		m = &llmfacet.Meta{Provider: "anthropic"}
	}
	if len(respBody) == 0 {
		return m
	}
	if isAnthropicSSE(respBody) {
		fillFromAnthropicSSE(m, respBody)
		return m
	}
	fillFromAnthropicJSON(m, respBody)
	return m
}

func isAnthropicSSE(body []byte) bool {
	// SSE responses begin with `event: ` framing.
	return bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("event:"))
}

// fillFromAnthropicJSON reads usage + stop_reason from a non-streamed
// /v1/messages response. Schema (subset):
//
//	{
//	  "model": "...",
//	  "stop_reason": "end_turn|max_tokens|stop_sequence|tool_use",
//	  "usage": { "input_tokens": N, "output_tokens": N,
//	             "cache_creation_input_tokens": N,
//	             "cache_read_input_tokens": N }
//	}
func fillFromAnthropicJSON(m *llmfacet.Meta, body []byte) {
	var r struct {
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return
	}
	if m.Model == "" {
		m.Model = r.Model
	}
	if r.StopReason != "" {
		m.StopReason = r.StopReason
	}
	m.InputTokens += r.Usage.InputTokens
	m.OutputTokens += r.Usage.OutputTokens
	m.CacheReadTokens += r.Usage.CacheReadInputTokens
	m.CacheWriteTokens += r.Usage.CacheCreationInputTokens
}

// fillFromAnthropicSSE walks the concatenated SSE stream the gateway
// captured. Anthropic emits one usage block on the initial
// message_start (with input_tokens + cache fields), partial output
// counts via message_delta events, and a final stop_reason on the
// terminating message_delta.
//
// The parser sums output_tokens across message_delta events and
// keeps the most recent stop_reason — Anthropic's protocol emits
// each only once per turn, so summation is a no-op past the final
// frame; matching the upstream behaviour even if a hostile stream
// repeats frames stays the right shape.
func fillFromAnthropicSSE(m *llmfacet.Meta, body []byte) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var event string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		switch event {
		case "message_start":
			fillAnthropicMessageStart(m, payload)
		case "message_delta":
			fillAnthropicMessageDelta(m, payload)
		}
	}
}

// fillAnthropicMessageStart pulls the initial usage block and model
// out of a message_start frame.
//
//	data: {"type":"message_start","message":{"model":"...","usage":{
//	    "input_tokens":N,"cache_creation_input_tokens":N,
//	    "cache_read_input_tokens":N}}}
func fillAnthropicMessageStart(m *llmfacet.Meta, payload string) {
	var f struct {
		Message struct {
			Model string `json:"model"`
			Usage struct {
				InputTokens              int64 `json:"input_tokens"`
				OutputTokens             int64 `json:"output_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
				CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			} `json:"usage"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(payload), &f); err != nil {
		return
	}
	if m.Model == "" {
		m.Model = f.Message.Model
	}
	m.InputTokens += f.Message.Usage.InputTokens
	m.OutputTokens += f.Message.Usage.OutputTokens
	m.CacheReadTokens += f.Message.Usage.CacheReadInputTokens
	m.CacheWriteTokens += f.Message.Usage.CacheCreationInputTokens
}

// fillAnthropicMessageDelta pulls output token counts and the
// terminating stop_reason out of a message_delta frame.
//
//	data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},
//	       "usage":{"output_tokens":N}}
func fillAnthropicMessageDelta(m *llmfacet.Meta, payload string) {
	var f struct {
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
		Usage struct {
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(payload), &f); err != nil {
		return
	}
	if f.Delta.StopReason != "" {
		m.StopReason = f.Delta.StopReason
	}
	m.OutputTokens += f.Usage.OutputTokens
}

func init() {
	var _ runtime.PlaceholderDetector = AnthropicEndpointRuntime{}
	var _ runtime.LLMResponseParser = AnthropicEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind: config.KindEndpoint,
		Type: "anthropic",
		// "http" is primary: the wire is HTTPS, the dashboard
		// renders the Family column off it, and http_rule keeps
		// matching method / path / headers. "llm" rides as the
		// auxiliary facet that the LLMResponseParser populates with
		// model + token counts.
		Families: []string{"http", "llm"},
		New:      func() any { return &AnthropicEndpoint{} },
		Refs:     singularRef,
		Validate: multiCredValidate,
		Runtime:  AnthropicEndpointRuntime{},
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*AnthropicEndpoint)
			if len(e.Hosts) > 0 {
				b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			}
			emitCredentialBinding(b, e.Credential, e.Credentials, "placeholder")
		},
	})
}
