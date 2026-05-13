package endpoints

import (
	"testing"

	llmfacet "github.com/denoland/clawpatrol/config/plugins/facets/llm"
)

// TestAnthropicParseLLMRequest pins the pre-flight extraction:
// model + stream lift cleanly off a Messages API POST body. Empty
// / non-JSON / model-less bodies return nil so the dispatcher
// omits llm facets on non-API paths.
func TestAnthropicParseLLMRequest(t *testing.T) {
	cases := []struct {
		name string
		body string
		want *llmfacet.Meta
	}{
		{"streamed claude opus", `{"model":"claude-opus-4-7-20251001","stream":true,"messages":[]}`,
			&llmfacet.Meta{Provider: "anthropic", Model: "claude-opus-4-7-20251001", Stream: true}},
		{"non-streamed sonnet", `{"model":"claude-3-5-sonnet-20240620","messages":[]}`,
			&llmfacet.Meta{Provider: "anthropic", Model: "claude-3-5-sonnet-20240620"}},
		{"empty body", ``, nil},
		{"non-JSON", `not json at all`, nil},
		{"missing model", `{"messages":[]}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AnthropicEndpointRuntime{}.ParseLLMRequest([]byte(tc.body))
			if tc.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			m, ok := got.(*llmfacet.Meta)
			if !ok {
				t.Fatalf("expected *llmfacet.Meta, got %T", got)
			}
			if *m != *tc.want {
				t.Errorf("got %+v want %+v", *m, *tc.want)
			}
		})
	}
}

// TestAnthropicParseLLMResponseJSON exercises the non-streaming
// response path against the actual Messages API schema, including
// cache token fields.
func TestAnthropicParseLLMResponseJSON(t *testing.T) {
	pre := &llmfacet.Meta{Provider: "anthropic", Model: "claude-opus-4-7-20251001"}
	resp := `{
		"model":"claude-opus-4-7-20251001",
		"stop_reason":"end_turn",
		"usage":{
			"input_tokens":120,
			"output_tokens":45,
			"cache_creation_input_tokens":300,
			"cache_read_input_tokens":900
		}
	}`
	got := AnthropicEndpointRuntime{}.ParseLLMResponse(nil, []byte(resp), pre).(*llmfacet.Meta)
	if got.StopReason != "end_turn" {
		t.Errorf("stop_reason=%q want end_turn", got.StopReason)
	}
	if got.InputTokens != 120 {
		t.Errorf("input=%d want 120", got.InputTokens)
	}
	if got.OutputTokens != 45 {
		t.Errorf("output=%d want 45", got.OutputTokens)
	}
	if got.CacheReadTokens != 900 {
		t.Errorf("cache_read=%d want 900", got.CacheReadTokens)
	}
	if got.CacheWriteTokens != 300 {
		t.Errorf("cache_write=%d want 300", got.CacheWriteTokens)
	}
}

// TestAnthropicParseLLMResponseSSE walks a realistic streaming
// response: message_start carries input + cache tokens; one or more
// message_delta frames carry partial output tokens; the terminating
// message_delta carries the final stop_reason and last output
// chunk. The parser must sum output_tokens across deltas and keep
// the final stop_reason.
func TestAnthropicParseLLMResponseSSE(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"model":"claude-opus-4-7-20251001","usage":{"input_tokens":200,"output_tokens":1,"cache_creation_input_tokens":50,"cache_read_input_tokens":800}}}

event: content_block_start
data: {"type":"content_block_start"}

event: message_delta
data: {"type":"message_delta","delta":{},"usage":{"output_tokens":12}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}

event: message_stop
data: {"type":"message_stop"}
`
	pre := &llmfacet.Meta{Provider: "anthropic", Model: "claude-opus-4-7-20251001"}
	got := AnthropicEndpointRuntime{}.ParseLLMResponse(nil, []byte(stream), pre).(*llmfacet.Meta)
	if got.InputTokens != 200 {
		t.Errorf("input=%d want 200", got.InputTokens)
	}
	if got.OutputTokens != 20 {
		t.Errorf("output=%d want 20 (1+12+7)", got.OutputTokens)
	}
	if got.CacheReadTokens != 800 {
		t.Errorf("cache_read=%d want 800", got.CacheReadTokens)
	}
	if got.CacheWriteTokens != 50 {
		t.Errorf("cache_write=%d want 50", got.CacheWriteTokens)
	}
	if got.StopReason != "end_turn" {
		t.Errorf("stop_reason=%q want end_turn", got.StopReason)
	}
}
