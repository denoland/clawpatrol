package credentials

// gemini_api_key: Google Gemini accepts the API key in either the
// `x-goog-api-key` header or the `?key=` query parameter. Only the
// header is used: a `?key=` the agent sent (a placeholder) is removed
// rather than swapped, so the real key never travels in the URL.

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// GeminiAPIKey is part of the clawpatrol plugin API.
type GeminiAPIKey struct{}

// InjectHTTP is part of the clawpatrol plugin API.
func (g *GeminiAPIKey) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 || req.URL == nil {
		return nil
	}
	key := string(sec.Bytes)
	req.Header.Set("x-goog-api-key", key)
	// The header is sufficient for every Gemini endpoint. An agent
	// that put a placeholder in ?key= gets it removed rather than
	// replaced: the real key must not travel in the URL, where
	// upstream and proxy logs record it.
	if q := req.URL.Query(); q.Has("key") {
		q.Del("key")
		req.URL.RawQuery = q.Encode()
	}
	return nil
}

// SecretSlots is part of the clawpatrol plugin API.
func (*GeminiAPIKey) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Gemini API key"}}
}

// EnvVars is part of the clawpatrol plugin API.
func (*GeminiAPIKey) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "GOOGLE_API_KEY", Value: phGemini, Description: "Gemini SDKs"},
		{Name: "GEMINI_API_KEY", Value: phGemini, Description: "Gemini CLI"},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*GeminiAPIKey)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "gemini_api_key",
		Disambiguators: []string{"placeholder"},
		New:            newer[GeminiAPIKey](),
		Runtime:        (*GeminiAPIKey)(nil),
		Build:          passthrough,
		Emit:           emptyEmit,
	})
}
