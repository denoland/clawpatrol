package credentials

// anthropic_oauth_subscription: claude.ai → console.anthropic.com
// OAuth flow. Stamps the bearer + the beta header that gates
// Anthropic's OAuth-backed access.

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type AnthropicOAuthSubscription struct{}

func (a *AnthropicOAuthSubscription) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	ensureBeta(req.Header, "oauth-2025-04-20")
	return nil
}

func (*AnthropicOAuthSubscription) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "ANTHROPIC_AUTH_TOKEN", Value: phClaude, Description: "Claude Code / Anthropic SDKs"},
	}
}

// OAuthFlow on AnthropicOAuthSubscription returns Anthropic's OAuth
// subscription flow (claude.ai → console.anthropic.com). Bootstrap
// refresh token is templated as `{{secret:CLAUDE_REFRESH}}` so the
// gateway can mint per-owner sessions from operator-provided env
// before the dashboard connect flow has run.
func (a *AnthropicOAuthSubscription) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		OAuth: config.OAuthConfig{
			ClientID:     "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
			AuthURL:      "https://claude.ai/oauth/authorize",
			TokenURL:     "https://console.anthropic.com/v1/oauth/token",
			RedirectURI:  "https://console.anthropic.com/oauth/code/callback",
			Scopes:       []string{"org:create_api_key", "user:profile", "user:inference"},
			RefreshToken: "{{secret:CLAUDE_REFRESH}}",
		},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*AnthropicOAuthSubscription)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "anthropic_oauth_subscription",
		New:     newer[AnthropicOAuthSubscription](),
		Runtime: (*AnthropicOAuthSubscription)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
