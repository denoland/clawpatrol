// Package middlewares holds the built-in HTTP middleware plugins —
// request-side hooks attached to endpoints via `middleware = [...]`
// that see the request after credential injection and may mutate the
// body before the upstream forward. The seam mirrors the credential
// plugin layout: each type lives in its own file, registers via
// init(), and co-locates its HCL schema with its runtime methods.
package middlewares

// anthropic_system_prompt: appends a configured text block to the
// `system` field of Anthropic `/v1/messages` requests. The first
// consumer is clawpatrol tool-discovery (telling the model which
// gateway-mediated tools it can reach), but the value is literal text
// in v1 — dynamic templating is deferred.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// anthropicMessagesPath is the only request shape this middleware
// transforms. Other methods / paths pass through unchanged.
const anthropicMessagesPath = "/v1/messages"

// anthropicHost is the upstream host this middleware understands. The
// load-time host-compat check rejects attachment to endpoints that
// don't intercept it.
const anthropicHost = "api.anthropic.com"

// AnthropicSystemPrompt is a request middleware that appends Text to
// the `system` field of Anthropic `/v1/messages` requests.
type AnthropicSystemPrompt struct {
	// Text is the literal block appended to the request's system
	// prompt. Supports `<<file:NAME>>` inlining so operators can keep
	// large discovery prompts in a sidecar file.
	Text string `hcl:"text"`
}

// RewriteHTTPRequest is part of the clawpatrol plugin API. It appends
// the configured Text to the `system` field of an Anthropic Messages
// request body, handling all three legal `system` shapes (absent,
// bare string, content-block array). Non-Messages requests pass
// through untouched. A `system` field in an unrecognized shape fails
// the request closed (returns an error), so a malformed body can't
// silently bypass the injection.
func (m *AnthropicSystemPrompt) RewriteHTTPRequest(_ context.Context, req *http.Request, body []byte) ([]byte, error) {
	// Gate on the Messages endpoint. The host is already constrained
	// to api.anthropic.com by the load-time compatibility check, so we
	// only need to discriminate method + path here.
	if req == nil || req.Method != http.MethodPost || req.URL == nil || req.URL.Path != anthropicMessagesPath {
		return body, nil
	}
	if m.Text == "" {
		return body, nil
	}

	// Decode into an order-preserving map of raw values so every field
	// other than `system` round-trips byte-for-byte (no number-
	// precision loss). Only the system field is rewritten.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("anthropic_system_prompt: request body is not a JSON object: %w", err)
	}

	newSystem, err := appendSystem(obj["system"], m.Text)
	if err != nil {
		return nil, err
	}
	obj["system"] = newSystem

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("anthropic_system_prompt: re-encoding request body: %w", err)
	}
	return out, nil
}

// appendSystem returns the new `system` value with text appended,
// dispatching on the existing value's shape:
//
//   - absent / null → system = text (a bare string)
//   - string        → system = original + "\n\n" + text
//   - array         → append {"type":"text","text": text} content block
//
// An unrecognized shape (number, bool, object) returns an error so the
// caller fails closed.
func appendSystem(cur json.RawMessage, text string) (json.RawMessage, error) {
	if len(cur) == 0 || string(cur) == "null" {
		return mustJSON(text), nil
	}

	// String shape.
	var s string
	if err := json.Unmarshal(cur, &s); err == nil {
		return mustJSON(s + "\n\n" + text), nil
	}

	// Content-block array shape.
	var arr []json.RawMessage
	if err := json.Unmarshal(cur, &arr); err == nil {
		block := mustJSON(map[string]string{"type": "text", "text": text})
		arr = append(arr, block)
		out, err := json.Marshal(arr)
		if err != nil {
			return nil, fmt.Errorf("anthropic_system_prompt: re-encoding system array: %w", err)
		}
		return out, nil
	}

	return nil, fmt.Errorf("anthropic_system_prompt: unrecognized `system` shape %s (want string or content-block array)", truncateForError(cur))
}

// mustJSON marshals v, which is only ever a string or a small map here
// — both infallible — so the error is dropped to keep call sites
// readable. A marshal failure would be a programmer error, not config.
func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// truncateForError clips a raw JSON snippet for inclusion in a
// diagnostic so a huge body doesn't flood the log.
func truncateForError(b []byte) string {
	const max = 64
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// CheckEndpointHosts is part of the clawpatrol plugin API. It rejects
// attaching this middleware to an endpoint that doesn't intercept
// api.anthropic.com — the transform only makes sense for the Anthropic
// Messages API. Mirrors the loader's other compatibility diagnostics.
func (m *AnthropicSystemPrompt) CheckEndpointHosts(hosts []string) error {
	for _, h := range hosts {
		host := h
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if strings.EqualFold(host, anthropicHost) {
			return nil
		}
	}
	return fmt.Errorf("anthropic_system_prompt middleware requires an endpoint whose hosts include %q; got %v", anthropicHost, hosts)
}

// FileIncludeFields is part of the clawpatrol plugin API. It lets the
// loader inline `<<file:NAME>>` markers in Text so a large discovery
// prompt can live in a sidecar file next to the policy.
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
		New:     func() any { return &AnthropicSystemPrompt{} },
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
