package endpoints

import (
	"testing"

	llmfacet "github.com/denoland/clawpatrol/config/plugins/facets/llm"
)

// TestOpenRouterParseLLMRequest pins pre-flight extraction. OpenRouter
// passes model strings through verbatim (operators write
// `llm.model.matches("^anthropic/")` to gate underlying provider),
// so the parser preserves the provider/model shape.
func TestOpenRouterParseLLMRequest(t *testing.T) {
	body := `{"model":"anthropic/claude-3-5-sonnet-20240620","stream":true,"messages":[]}`
	got := OpenRouterEndpointRuntime{}.ParseLLMRequest([]byte(body))
	m, ok := got.(*llmfacet.Meta)
	if !ok {
		t.Fatalf("expected *llmfacet.Meta, got %T", got)
	}
	if m.Provider != "openrouter" {
		t.Errorf("provider=%q want openrouter", m.Provider)
	}
	if m.Model != "anthropic/claude-3-5-sonnet-20240620" {
		t.Errorf("model=%q want passthrough", m.Model)
	}
	if !m.Stream {
		t.Errorf("stream=false want true")
	}
}

// TestOpenRouterParseLLMResponseJSON pins the non-streamed OpenAI-
// compatible response shape, including cached_tokens.
func TestOpenRouterParseLLMResponseJSON(t *testing.T) {
	pre := &llmfacet.Meta{Provider: "openrouter", Model: "anthropic/claude-3-5-sonnet-20240620"}
	resp := `{
		"model":"anthropic/claude-3-5-sonnet-20240620",
		"choices":[{"finish_reason":"stop"}],
		"usage":{
			"prompt_tokens":150,
			"completion_tokens":60,
			"total_tokens":210,
			"prompt_tokens_details":{"cached_tokens":100}
		}
	}`
	got := OpenRouterEndpointRuntime{}.ParseLLMResponse(nil, []byte(resp), pre).(*llmfacet.Meta)
	if got.InputTokens != 150 {
		t.Errorf("input=%d want 150", got.InputTokens)
	}
	if got.OutputTokens != 60 {
		t.Errorf("output=%d want 60", got.OutputTokens)
	}
	if got.CacheReadTokens != 100 {
		t.Errorf("cache_read=%d want 100", got.CacheReadTokens)
	}
	if got.CacheWriteTokens != 0 {
		t.Errorf("cache_write=%d want 0 (no write/read split on OpenAI)", got.CacheWriteTokens)
	}
	if got.StopReason != "stop" {
		t.Errorf("stop_reason=%q want stop", got.StopReason)
	}
}

// TestOpenRouterParseLLMResponseSSE walks a streamed OpenAI-shaped
// response. Usage lifts off the final chunk; finish_reason off the
// last chunk that carries one. [DONE] terminator is ignored.
func TestOpenRouterParseLLMResponseSSE(t *testing.T) {
	stream := "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: {\"choices\":[{\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":80,\"completion_tokens\":20,\"prompt_tokens_details\":{\"cached_tokens\":40}}}\n\n" +
		"data: [DONE]\n\n"
	pre := &llmfacet.Meta{Provider: "openrouter", Model: "openai/gpt-4o"}
	got := OpenRouterEndpointRuntime{}.ParseLLMResponse(nil, []byte(stream), pre).(*llmfacet.Meta)
	if got.InputTokens != 80 {
		t.Errorf("input=%d want 80", got.InputTokens)
	}
	if got.OutputTokens != 20 {
		t.Errorf("output=%d want 20", got.OutputTokens)
	}
	if got.CacheReadTokens != 40 {
		t.Errorf("cache_read=%d want 40", got.CacheReadTokens)
	}
	if got.StopReason != "stop" {
		t.Errorf("stop_reason=%q want stop", got.StopReason)
	}
}
