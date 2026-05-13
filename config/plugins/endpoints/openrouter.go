package endpoints

// openrouter endpoint: HTTPS-shaped provider plugin for
// openrouter.ai. OpenRouter exposes an OpenAI-compatible
// /v1/chat/completions surface that proxies the underlying provider;
// the response carries an OpenAI-shaped `usage` block with
// prompt_tokens / completion_tokens and a model string formatted as
// `<provider>/<model>` (e.g. `anthropic/claude-3-5-sonnet`).
//
// Sample HCL:
//
//	credential "bearer_token" "openrouter" {}
//
//	endpoint "openrouter" "router" {
//	  hosts      = ["openrouter.ai"]
//	  credential = openrouter
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

// OpenRouterEndpoint is part of the clawpatrol plugin API.
type OpenRouterEndpoint struct {
	Hosts          []string  `hcl:"hosts,optional"`
	Credential     string    `hcl:"credential,optional"`
	CredentialsRaw cty.Value `hcl:"credentials,optional" json:"-"`

	Credentials []CredentialEntry `json:"Credentials,omitempty"`
}

// EndpointHosts is part of the clawpatrol plugin API. Defaults to
// openrouter.ai when the operator doesn't list explicit hosts.
func (e *OpenRouterEndpoint) EndpointHosts() []string {
	if len(e.Hosts) == 0 {
		return []string{"openrouter.ai"}
	}
	return e.Hosts
}

// EndpointCredentials is part of the clawpatrol plugin API.
func (e *OpenRouterEndpoint) EndpointCredentials() []config.CredBinding {
	return bindings(e.Credential, e.Credentials)
}

func (e *OpenRouterEndpoint) credentialAndRaw() (string, cty.Value) {
	return e.Credential, e.CredentialsRaw
}

func (e *OpenRouterEndpoint) setCredentialEntries(es []CredentialEntry) {
	e.Credentials = es
}

// OpenRouterEndpointRuntime owns OpenRouter's placeholder detection
// (Authorization: Bearer) and OpenAI-compatible response parsing.
type OpenRouterEndpointRuntime struct{}

// DetectPlaceholder reuses the canonical HTTPS Authorization scan.
func (OpenRouterEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil || req.Headers == nil {
		return ""
	}
	hay := req.Headers.Get("Authorization")
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

// ParseLLMRequest extracts provider / model / stream from a
// /v1/chat/completions request body. The model string is left
// untouched (operators write `llm.model.matches("^anthropic/")` if
// they want to gate by underlying provider).
func (OpenRouterEndpointRuntime) ParseLLMRequest(reqBody []byte) any {
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
		Provider: "openrouter",
		Model:    req.Model,
		Stream:   req.Stream,
	}
}

// ParseLLMResponse amends the pre-flight Meta with token counts and
// finish_reason. OpenRouter mirrors OpenAI's `usage` shape on the
// final chunk of a streamed response and on the body of a
// non-streamed one; cached_tokens (when present) maps onto
// cache_read_tokens.
func (OpenRouterEndpointRuntime) ParseLLMResponse(reqBody, respBody []byte, pre any) any {
	m, _ := pre.(*llmfacet.Meta)
	if m == nil {
		m = &llmfacet.Meta{Provider: "openrouter"}
	}
	if len(respBody) == 0 {
		return m
	}
	if isOpenAISSE(respBody) {
		fillFromOpenAISSE(m, respBody)
		return m
	}
	fillFromOpenAIJSON(m, respBody)
	return m
}

// isOpenAISSE recognises an OpenAI-compatible streamed response by
// the first non-blank `data:` frame. Anthropic's SSE starts with
// `event:`; OpenAI ships only `data:` lines, with `[DONE]` as the
// terminator.
func isOpenAISSE(body []byte) bool {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	return bytes.HasPrefix(trimmed, []byte("data:"))
}

// fillFromOpenAIJSON reads usage / finish_reason from the final
// /v1/chat/completions JSON body.
//
//	{
//	  "model": "anthropic/claude-...",
//	  "choices": [{"finish_reason": "stop", ...}],
//	  "usage": { "prompt_tokens": N, "completion_tokens": N,
//	             "total_tokens": N,
//	             "prompt_tokens_details": { "cached_tokens": N } }
//	}
func fillFromOpenAIJSON(m *llmfacet.Meta, body []byte) {
	var r openAIChatResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return
	}
	mergeOpenAIResponse(m, &r)
}

// fillFromOpenAISSE walks the SSE stream and merges every
// chunk that carries a `usage` block. Chunks carrying choices with a
// finish_reason update StopReason. OpenAI emits usage only on the
// final chunk (when the request opted in via stream_options.include_usage)
// or repeatedly per chunk — the merge sums in either case and the
// final chunk's stop_reason wins because it overwrites.
func fillFromOpenAISSE(m *llmfacet.Meta, body []byte) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var chunk openAIChatResponse
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		mergeOpenAIResponse(m, &chunk)
	}
}

// openAIChatResponse is the subset of the OpenAI / OpenRouter chat
// completions payload the LLM facet cares about. Same shape for
// final body, terminal SSE chunk, and (when streaming usage is
// enabled) per-chunk frames.
type openAIChatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens        int64 `json:"prompt_tokens"`
		CompletionTokens    int64 `json:"completion_tokens"`
		TotalTokens         int64 `json:"total_tokens"`
		PromptTokensDetails *struct {
			CachedTokens int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
}

func mergeOpenAIResponse(m *llmfacet.Meta, r *openAIChatResponse) {
	if m.Model == "" {
		m.Model = r.Model
	}
	for _, c := range r.Choices {
		if c.FinishReason != "" {
			m.StopReason = c.FinishReason
		}
	}
	if r.Usage == nil {
		return
	}
	m.InputTokens += r.Usage.PromptTokens
	m.OutputTokens += r.Usage.CompletionTokens
	if r.Usage.PromptTokensDetails != nil {
		m.CacheReadTokens += r.Usage.PromptTokensDetails.CachedTokens
	}
}

func init() {
	var _ runtime.PlaceholderDetector = OpenRouterEndpointRuntime{}
	var _ runtime.LLMResponseParser = OpenRouterEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "openrouter",
		Families: []string{"http", "llm"},
		New:      func() any { return &OpenRouterEndpoint{} },
		Refs:     singularRef,
		Validate: multiCredValidate,
		Runtime:  OpenRouterEndpointRuntime{},
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*OpenRouterEndpoint)
			if len(e.Hosts) > 0 {
				b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			}
			emitCredentialBinding(b, e.Credential, e.Credentials, "placeholder")
		},
	})
}
