// Package middlewares holds the built-in HTTP request middleware
// plugins. A middleware is an endpoint-attached, request-side hook
// (runtime.HTTPMiddleware) that runs after credential injection and
// before the upstream forward; it may rewrite the request body. Each
// type lives in its own file and registers itself via init(), mirroring
// the credential plugin layout under config/plugins/credentials.
package middlewares

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// anthropicHost is the only upstream the anthropic_system_prompt
// middleware knows how to rewrite. The compile-time host-compatibility
// check (CheckEndpointHosts) rejects endpoints that don't reach it.
const anthropicHost = "api.anthropic.com"

// anthropicMessagesPath is the Anthropic Messages API path whose
// request bodies carry the `system` field this middleware appends to.
// Other paths on the same host (token counting, model listing) have no
// `system` field and pass through untouched.
const anthropicMessagesPath = "/v1/messages"

// AnthropicSystemPrompt appends a configured text block to the `system`
// field of Anthropic POST /v1/messages request bodies. It handles all
// three legal `system` shapes:
//
//   - string  → system = original + "\n\n" + injected
//   - array   → append a {"type":"text","text": injected} content block
//   - absent  → system = injected
//
// The first consumer is clawpatrol tool-discovery (telling the model
// which gateway-mediated tools it can reach), but the configured text
// is opaque to the middleware — it's literal HCL (or a `<<file:NAME>>`
// include) for v1.
type AnthropicSystemPrompt struct {
	// Text is the block appended to the request's system prompt.
	// Supports the loader's `<<file:NAME>>` include marker so large
	// prompts can live next to the policy file rather than inline.
	Text string `hcl:"text"`
}

// RewriteHTTPRequest is part of the clawpatrol plugin API
// (runtime.HTTPMiddleware). It mutates only POST /v1/messages bodies;
// everything else passes through. A `system` field whose shape is
// neither a string nor a content-block array fails the request closed
// (the dispatcher turns the error into a 502) rather than silently
// dropping the injected text.
func (m *AnthropicSystemPrompt) RewriteHTTPRequest(_ context.Context, req *http.Request, body []byte) ([]byte, error) {
	if req.Method != http.MethodPost || req.URL.Path != anthropicMessagesPath {
		return body, nil
	}
	if m.Text == "" || len(body) == 0 {
		return body, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		// Not a JSON object we can reason about (malformed, or a shape
		// the API would reject anyway) — leave it untouched.
		return body, nil
	}
	merged, err := mergeSystem(obj["system"], m.Text)
	if err != nil {
		return nil, err
	}
	obj["system"] = merged
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("re-encode request body: %w", err)
	}
	return out, nil
}

// mergeSystem folds injected into the existing `system` value, handling
// the absent / string / content-block-array shapes. raw is the value of
// the request's "system" key (nil when absent).
func mergeSystem(raw json.RawMessage, injected string) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return json.Marshal(injected)
	}
	// String shape: concatenate with a blank line between the original
	// prompt and the injected block.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return json.Marshal(s + "\n\n" + injected)
	}
	// Content-block array shape: append a text block.
	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err == nil {
		block, err := json.Marshal(map[string]string{"type": "text", "text": injected})
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, json.RawMessage(block))
		return json.Marshal(blocks)
	}
	return nil, fmt.Errorf("unsupported `system` shape: expected a string or a content-block array")
}

// CheckEndpointHosts is part of the clawpatrol plugin API
// (config.MiddlewareEndpointCompat). It rejects endpoints whose hosts
// don't include api.anthropic.com — attaching an Anthropic-specific
// system-prompt rewrite to, say, a GitHub endpoint is always a config
// mistake, so it surfaces as a load-time diagnostic.
func (*AnthropicSystemPrompt) CheckEndpointHosts(hosts []string) error {
	for _, h := range hosts {
		host := h
		if hp, _, err := net.SplitHostPort(h); err == nil {
			host = hp
		}
		if host == anthropicHost {
			return nil
		}
	}
	return fmt.Errorf("type is Anthropic-specific and requires an endpoint whose `hosts` include %q (got %v)", anthropicHost, hosts)
}

// FileIncludeFields is part of the clawpatrol plugin API
// (config.FileIncludable). It lets operators write the prompt as
// `text = "<<file:./discovery.md>>"` and keep the body out of the
// policy file.
func (m *AnthropicSystemPrompt) FileIncludeFields() []config.FileIncludeField {
	return []config.FileIncludeField{
		{Get: func() string { return m.Text }, Set: func(v string) { m.Text = v }},
	}
}

func init() {
	var _ runtime.HTTPMiddleware = (*AnthropicSystemPrompt)(nil)
	var _ config.MiddlewareEndpointCompat = (*AnthropicSystemPrompt)(nil)
	var _ config.FileIncludable = (*AnthropicSystemPrompt)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindMiddleware,
		Type:    "anthropic_system_prompt",
		New:     func() any { return new(AnthropicSystemPrompt) },
		Runtime: (*AnthropicSystemPrompt)(nil),
		Build: func(decoded any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
			return decoded, nil
		},
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*AnthropicSystemPrompt)
			b.SetAttributeValue("text", cty.StringVal(v.Text))
		},
	})
}
