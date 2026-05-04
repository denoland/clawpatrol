package credentials

// openai_codex_oauth: bearer token for the codex CLI's OAuth flow.
// api.openai.com + chatgpt.com both accept Authorization: Bearer.

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type OpenAICodexOAuth struct{}

func (a *OpenAICodexOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	return nil
}

func (*OpenAICodexOAuth) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "OPENAI_API_KEY", Value: phOpenAI, Description: "OpenAI / Codex CLI"},
	}
}

func (a *OpenAICodexOAuth) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		OAuth: config.OAuthConfig{
			ClientID:     "app_EMoamEEZ73f0CkXaXp7hrann",
			AuthURL:      "https://auth.openai.com/oauth/authorize",
			TokenURL:     "https://auth.openai.com/oauth/token",
			RedirectURI:  "http://localhost:1455/auth/callback",
			Scopes:       []string{"openid", "profile", "email", "offline_access"},
			RefreshToken: "{{secret:CODEX_REFRESH}}",
		},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*OpenAICodexOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "openai_codex_oauth",
		New:     newer[OpenAICodexOAuth](),
		Runtime: (*OpenAICodexOAuth)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
