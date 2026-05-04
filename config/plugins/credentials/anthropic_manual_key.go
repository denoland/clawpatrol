package credentials

// anthropic_manual_key: Anthropic API key stamped into the
// `x-api-key` header (Anthropic's bearer-style header for direct API
// keys; OAuth subscriptions use Authorization, see anthropic_oauth.go).

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type AnthropicManualKey struct{}

func (a *AnthropicManualKey) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("x-api-key", string(sec.Bytes))
	return nil
}

func (*AnthropicManualKey) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Anthropic API key", Description: "sk-ant-…"}}
}

func (*AnthropicManualKey) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "ANTHROPIC_API_KEY", Value: phClaude, Description: "Anthropic API key (manual)"},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*AnthropicManualKey)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "anthropic_manual_key",
		New:     newer[AnthropicManualKey](),
		Runtime: (*AnthropicManualKey)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
