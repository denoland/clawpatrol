package credentials

// anthropic_oauth_subscription: claude.ai → console.anthropic.com
// OAuth flow. Stamps the bearer + the beta header that gates
// Anthropic's OAuth-backed access.

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// AnthropicOAuthSubscription is part of the clawpatrol plugin API.
type AnthropicOAuthSubscription struct{}

// InjectHTTP is part of the clawpatrol plugin API.
func (a *AnthropicOAuthSubscription) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	ensureBeta(req.Header, "oauth-2025-04-20")
	return nil
}

// EnvVars is part of the clawpatrol plugin API.
//
// ANTHROPIC_AUTH_TOKEN is the standard env-var shape for the raw
// Anthropic SDKs (Python, Node.js, …) and Claude Code. The value is a
// placeholder; the gateway rewrites the Authorization header at MITM
// time via InjectHTTP, so the bytes here never reach Anthropic — the
// operator's gateway-stored OAuth bearer (with the scopes requested by
// OAuthFlow below, including user:sessions:claude_code) authenticates
// upstream calls, including the session-register step `/remote-control`
// depends on.
//
// Caveat for the `claude` CLI: it refuses OAuth-only features like
// `/remote-control` whenever ANTHROPIC_AUTH_TOKEN is present (it reads
// the env var as bearer/API-key auth via a LOCAL gate, before any
// network call). `clawpatrol run` works around that for the `claude`
// binary specifically via installClaudeCodeOAuthShim — it strips this
// env var and supplies a synthesized OAuth credential instead. See
// cmd/clawpatrol/integrations.go and doc/claude-code-oauth.md.
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
			ClientID:    "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
			AuthURL:     "https://claude.ai/oauth/authorize",
			TokenURL:    "https://console.anthropic.com/v1/oauth/token",
			RedirectURI: "https://console.anthropic.com/oauth/code/callback",
			// user:sessions:claude_code is what gates `/remote-control` and
			// the rest of the OAuth-only Claude Code features on the
			// Anthropic side; without it the upstream session-register call
			// fails with `OAuth token does not meet scope requirement
			// user:sessions:claude_code` (see anthropics/claude-code#33105).
			// Operators who connected the credential before this scope was
			// added will need to re-run the dashboard OAuth flow once so
			// the stored refresh token picks up the new grant.
			Scopes:       []string{"org:create_api_key", "user:profile", "user:inference", "user:sessions:claude_code"},
			RefreshToken: "{{secret:CLAUDE_REFRESH}}",
		},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*AnthropicOAuthSubscription)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "anthropic_oauth_subscription",
		Disambiguators: []string{"placeholder"},
		New:            newer[AnthropicOAuthSubscription](),
		Runtime:        (*AnthropicOAuthSubscription)(nil),
		Build:          passthrough,
		Emit:           emptyEmit,
	})
}
