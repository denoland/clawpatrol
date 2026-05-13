package endpoints

import (
	"testing"

	llmfacet "github.com/denoland/clawpatrol/config/plugins/facets/llm"
)

// TestOpenAICodexParseLLMRequest pins pre-flight extraction from a
// chatgpt.com codex /backend-api/codex/responses POST. The body's
// model + stream lift; non-JSON / model-less / empty bodies return
// nil so non-API paths (the JWKS GET the synthetic responder serves)
// don't fabricate llm facets.
func TestOpenAICodexParseLLMRequest(t *testing.T) {
	body := `{"model":"gpt-5-codex","stream":true,"input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}`
	got := OpenAICodexHTTPSEndpointRuntime{}.ParseLLMRequest([]byte(body))
	m, ok := got.(*llmfacet.Meta)
	if !ok {
		t.Fatalf("expected *llmfacet.Meta, got %T", got)
	}
	if m.Provider != "openai" {
		t.Errorf("provider=%q want openai", m.Provider)
	}
	if m.Model != "gpt-5-codex" {
		t.Errorf("model=%q want gpt-5-codex", m.Model)
	}
	if !m.Stream {
		t.Errorf("stream=false want true")
	}
	rt := OpenAICodexHTTPSEndpointRuntime{}
	if v := rt.ParseLLMRequest([]byte(``)); v != nil {
		t.Errorf("empty body returned %+v, want nil", v)
	}
	if v := rt.ParseLLMRequest([]byte(`not json`)); v != nil {
		t.Errorf("non-JSON returned %+v, want nil", v)
	}
}

// TestOpenAICodexParseLLMResponseJSON pins the non-streamed
// Responses-API shape (codex sometimes returns the final body
// directly).
func TestOpenAICodexParseLLMResponseJSON(t *testing.T) {
	pre := &llmfacet.Meta{Provider: "openai", Model: "gpt-5-codex"}
	resp := `{
		"model":"gpt-5-codex",
		"status":"completed",
		"usage":{
			"input_tokens":300,
			"output_tokens":80,
			"input_tokens_details":{"cached_tokens":120}
		}
	}`
	got := OpenAICodexHTTPSEndpointRuntime{}.ParseLLMResponse(nil, []byte(resp), pre).(*llmfacet.Meta)
	if got.InputTokens != 300 {
		t.Errorf("input=%d want 300", got.InputTokens)
	}
	if got.OutputTokens != 80 {
		t.Errorf("output=%d want 80", got.OutputTokens)
	}
	if got.CacheReadTokens != 120 {
		t.Errorf("cache_read=%d want 120", got.CacheReadTokens)
	}
	if got.StopReason != "completed" {
		t.Errorf("stop_reason=%q want completed", got.StopReason)
	}
}

// TestOpenAICodexParseLLMResponseSSE walks a streamed Responses-API
// flow. The wrapping `response.completed` event carries the final
// `response` object with usage; the parser merges it.
func TestOpenAICodexParseLLMResponseSSE(t *testing.T) {
	stream := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5-codex\",\"status\":\"completed\",\"usage\":{\"input_tokens\":250,\"output_tokens\":40,\"input_tokens_details\":{\"cached_tokens\":75}}}}\n\n"
	pre := &llmfacet.Meta{Provider: "openai", Model: "gpt-5-codex"}
	got := OpenAICodexHTTPSEndpointRuntime{}.ParseLLMResponse(nil, []byte(stream), pre).(*llmfacet.Meta)
	if got.InputTokens != 250 {
		t.Errorf("input=%d want 250", got.InputTokens)
	}
	if got.OutputTokens != 40 {
		t.Errorf("output=%d want 40", got.OutputTokens)
	}
	if got.CacheReadTokens != 75 {
		t.Errorf("cache_read=%d want 75", got.CacheReadTokens)
	}
	if got.StopReason != "completed" {
		t.Errorf("stop_reason=%q want completed", got.StopReason)
	}
}
