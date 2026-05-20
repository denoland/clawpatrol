// Package credentials implements clawpatrol credentials support.
package credentials

// anthropic_manual_key: Anthropic API key stamped into the
// `x-api-key` header (Anthropic's bearer-style header for direct API
// keys; OAuth subscriptions use Authorization, see anthropic_oauth.go).

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// AnthropicManualKey is part of the clawpatrol plugin API.
type AnthropicManualKey struct{}

// InjectHTTP is part of the clawpatrol plugin API.
func (a *AnthropicManualKey) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("x-api-key", string(sec.Bytes))
	return nil
}

// SecretSlots is part of the clawpatrol plugin API.
func (*AnthropicManualKey) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Anthropic API key", Description: "sk-ant-…"}}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*AnthropicManualKey)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "anthropic_manual_key",
		Disambiguators: []string{"placeholder"},
		New:            newer[AnthropicManualKey](),
		Runtime:        (*AnthropicManualKey)(nil),
		Build:          passthrough,
		Emit:           emptyEmit,
	})
}
