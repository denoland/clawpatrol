package middlewares

// anthropic_system_prompt: appends a configured text block to the
// `system` field of Anthropic `/v1/messages` requests. The first
// real consumer is clawpatrol tool-discovery — telling the model what
// gateway-mediated tools it can reach — but this type only ships the
// literal-text mechanism; the discovery payload is a separate concern.
//
//   middleware "anthropic_system_prompt" "tool_discovery" {
//     text = "<<file:discovery.md>>"
//   }
//
//   endpoint "https" "anthropic_api" {
//     hosts      = ["api.anthropic.com"]
//     credential = anthropic_manual_key.prod
//     middleware = [anthropic_system_prompt.tool_discovery]
//   }
//
// `text` is a literal string; a `<<file:NAME>>` marker inlines a file's
// contents at load time (file() is not an HCL function here). Note
// `position` is the obvious next knob but is out of scope for v1.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/hostmatch"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const (
	anthropicHost         = "api.anthropic.com"
	anthropicMessagesPath = "/v1/messages"
)

// AnthropicSystemPrompt is part of the clawpatrol plugin API.
type AnthropicSystemPrompt struct {
	// Text is the block appended to the request's Anthropic system
	// prompt. May use a `<<file:NAME>>` marker to inline a file's
	// contents.
	Text string `hcl:"text"`
}

// RewriteHTTPRequest implements runtime.HTTPMiddleware. It appends Text
// to the request's Anthropic `system` prompt, handling all three legal
// shapes (absent, bare string, content-block array). Requests that
// aren't a POST to /v1/messages — and the empty-text no-op — pass
// through unchanged. An unrecognized `system` shape is an error, which
// fails the request closed.
func (m *AnthropicSystemPrompt) RewriteHTTPRequest(_ context.Context, req *http.Request, body []byte) ([]byte, error) {
	if req.Method != http.MethodPost || !strings.HasPrefix(req.URL.Path, anthropicMessagesPath) {
		return body, nil
	}
	if m.Text == "" || len(body) == 0 {
		return body, nil
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse %s body: %w", anthropicMessagesPath, err)
	}

	raw, ok := payload["system"]
	switch {
	case !ok || len(raw) == 0 || string(raw) == "null":
		// Absent / null → set the system prompt to the injected text.
		nv, err := json.Marshal(m.Text)
		if err != nil {
			return nil, err
		}
		payload["system"] = nv
	default:
		switch firstJSONToken(raw) {
		case '"':
			// Bare string → original + "\n\n" + injected.
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, fmt.Errorf("parse `system` string: %w", err)
			}
			nv, err := json.Marshal(s + "\n\n" + m.Text)
			if err != nil {
				return nil, err
			}
			payload["system"] = nv
		case '[':
			// Content-block array → append a {type:text,text:...} block.
			var blocks []json.RawMessage
			if err := json.Unmarshal(raw, &blocks); err != nil {
				return nil, fmt.Errorf("parse `system` blocks: %w", err)
			}
			block, err := json.Marshal(map[string]string{"type": "text", "text": m.Text})
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, block)
			nv, err := json.Marshal(blocks)
			if err != nil {
				return nil, err
			}
			payload["system"] = nv
		default:
			return nil, fmt.Errorf("unexpected `system` shape in %s body (want absent, string, or content-block array)", anthropicMessagesPath)
		}
	}

	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("re-encode %s body: %w", anthropicMessagesPath, err)
	}
	return out, nil
}

// CheckEndpointHosts implements config.MiddlewareEndpointCompat. An
// anthropic_system_prompt middleware only makes sense on an endpoint
// that serves api.anthropic.com; attaching it elsewhere is a config
// error surfaced as a load-time diagnostic.
func (m *AnthropicSystemPrompt) CheckEndpointHosts(hosts []string) error {
	for _, h := range hosts {
		host, _, err := hostmatch.SplitHostPort(h)
		if err != nil || host == "" {
			host = h
		}
		if strings.EqualFold(host, anthropicHost) {
			return nil
		}
	}
	return fmt.Errorf("anthropic_system_prompt only applies to endpoints serving %q; the bound endpoint declares hosts %v", anthropicHost, hosts)
}

// FileIncludeFields implements config.FileIncludable: the `text` field
// may carry a `<<file:NAME>>` marker that the loader inlines.
func (m *AnthropicSystemPrompt) FileIncludeFields() []config.FileIncludeField {
	return []config.FileIncludeField{{
		Get: func() string { return m.Text },
		Set: func(s string) { m.Text = s },
	}}
}

// firstJSONToken returns the first non-whitespace byte of a JSON value,
// used to tell a string (`"`) from an array (`[`). Returns 0 for an
// all-whitespace input.
func firstJSONToken(raw []byte) byte {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return b
		}
	}
	return 0
}

func init() {
	var _ runtime.HTTPMiddleware = (*AnthropicSystemPrompt)(nil)
	var _ config.MiddlewareEndpointCompat = (*AnthropicSystemPrompt)(nil)
	var _ config.FileIncludable = (*AnthropicSystemPrompt)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindMiddleware,
		Type:    "anthropic_system_prompt",
		New:     newer[AnthropicSystemPrompt](),
		Build:   passthrough,
		Runtime: (*AnthropicSystemPrompt)(nil),
		Emit: func(body any, _ string, b *hclwrite.Body) {
			m := body.(*AnthropicSystemPrompt)
			if m.Text != "" {
				b.SetAttributeValue("text", cty.StringVal(m.Text))
			}
		},
	})
}
