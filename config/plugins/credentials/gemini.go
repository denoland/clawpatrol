package credentials

// gemini_api_key: Google Gemini accepts the API key in either the
// `x-goog-api-key` header or the `?key=` query parameter. Always
// overwrite both — agents that send placeholder values get them
// swapped; agents that don't send anything get the real key stamped
// in.

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type GeminiAPIKey struct{}

func (g *GeminiAPIKey) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 || req.URL == nil {
		return nil
	}
	key := string(sec.Bytes)
	req.Header.Set("x-goog-api-key", key)
	q := req.URL.Query()
	if q.Get("key") != "" {
		// Only rewrite the param when the agent set one — otherwise
		// header injection above is sufficient and we don't want to
		// surprise the agent with an extra param.
		q.Set("key", key)
		req.URL.RawQuery = q.Encode()
	}
	return nil
}

func (*GeminiAPIKey) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Gemini API key"}}
}

func (*GeminiAPIKey) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "GOOGLE_API_KEY", Value: phGemini, Description: "Gemini SDKs"},
		{Name: "GEMINI_API_KEY", Value: phGemini, Description: "Gemini CLI"},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*GeminiAPIKey)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "gemini_api_key",
		New:     newer[GeminiAPIKey](),
		Runtime: (*GeminiAPIKey)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
