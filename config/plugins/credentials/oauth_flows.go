package credentials

import "github.com/denoland/clawpatrol/config"

// OAuth flow definitions for the built-in OAuth credential types.
// Each lives next to the credential plugin that returns it via
// OAuthFlow(); the host's OAuthRegistry registers them under each
// credential's bare name at policy load. Keeping the static flow
// data in this package — instead of a parallel defaults map in the
// gateway — means adding a new OAuth provider is a one-file change.

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

// OAuthFlow on OpenAICodexOAuth returns the codex CLI's OAuth flow
// (auth.openai.com → ChatGPT subscription token).
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

// OAuthFlow on GitHubOAuth returns the gh CLI's published OAuth
// device flow. No client secret — device flow is designed for public
// clients.
func (g *GitHubOAuth) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		Flow:   "device",
		OAuth: config.OAuthConfig{
			ClientID:  "178c6fc778ccc68e1d6a",
			DeviceURL: "https://github.com/login/device/code",
			TokenURL:  "https://github.com/login/oauth/access_token",
			Scopes:    []string{"repo", "read:org", "gist", "workflow"},
		},
	}
}
