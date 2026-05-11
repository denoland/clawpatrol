package credentials

// github_oauth: bearer token from gh's device-flow OAuth. Used by
// gh CLI + the GitHub REST API (api.github.com / raw.githubusercontent.com).

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// GitHubOAuth is part of the clawpatrol plugin API.
type GitHubOAuth struct{}

// InjectHTTP is part of the clawpatrol plugin API.
func (g *GitHubOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	return nil
}

// EnvVars is part of the clawpatrol plugin API.
func (*GitHubOAuth) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "GH_TOKEN", Value: phGitHub, Description: "gh CLI"},
		{Name: "GITHUB_TOKEN", Value: phGitHub, Description: "GitHub Actions / SDKs"},
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
		OptionalScopes: githubOptionalScopes,
	}
}

// githubOptionalScopes is the connect-time picker catalog. The base
// Scopes above are always sent; everything below is opt-in so users
// can add SSH key, GPG key, packages, etc. permissions when needed
// without the plugin shipping a maximally-broad default token.
var githubOptionalScopes = []config.OptionalScopeGroup{
	{Title: "repo", Scopes: []config.OptionalScope{
		{ID: "public_repo", Label: "public repos only"},
		{ID: "repo:status", Label: "commit statuses"},
		{ID: "repo_deployment", Label: "deployment statuses"},
		{ID: "repo:invite", Label: "repo invitations"},
		{ID: "security_events", Label: "code scanning / secret scanning"},
		{ID: "delete_repo", Label: "delete repos"},
	}},
	{Title: "ssh keys", Scopes: []config.OptionalScope{
		{ID: "admin:public_key", Label: "manage SSH auth keys"},
		{ID: "write:public_key", Label: "create SSH auth keys"},
		{ID: "read:public_key", Label: "read SSH auth keys"},
		{ID: "admin:ssh_signing_key", Label: "manage SSH signing keys"},
		{ID: "write:ssh_signing_key", Label: "create SSH signing keys"},
		{ID: "read:ssh_signing_key", Label: "read SSH signing keys"},
	}},
	{Title: "gpg keys", Scopes: []config.OptionalScope{
		{ID: "admin:gpg_key", Label: "manage GPG keys"},
		{ID: "write:gpg_key", Label: "create GPG keys"},
		{ID: "read:gpg_key", Label: "read GPG keys"},
	}},
	{Title: "user / org", Scopes: []config.OptionalScope{
		{ID: "user", Label: "all user scopes"},
		{ID: "read:user", Label: "profile"},
		{ID: "user:email", Label: "email addresses"},
		{ID: "user:follow", Label: "follow users"},
		{ID: "admin:org", Label: "manage org & teams"},
		{ID: "write:org", Label: "write org & teams"},
	}},
	{Title: "webhooks", Scopes: []config.OptionalScope{
		{ID: "admin:repo_hook", Label: "manage repo webhooks"},
		{ID: "write:repo_hook", Label: "write repo webhooks"},
		{ID: "read:repo_hook", Label: "read repo webhooks"},
		{ID: "admin:org_hook", Label: "manage org webhooks"},
	}},
	{Title: "packages", Scopes: []config.OptionalScope{
		{ID: "write:packages", Label: "publish packages"},
		{ID: "read:packages", Label: "download packages"},
		{ID: "delete:packages", Label: "delete packages"},
	}},
	{Title: "discussions / projects / notifications", Scopes: []config.OptionalScope{
		{ID: "write:discussion", Label: "write discussions"},
		{ID: "read:discussion", Label: "read discussions"},
		{ID: "project", Label: "manage projects"},
		{ID: "read:project", Label: "read projects"},
		{ID: "notifications", Label: "notifications"},
	}},
	{Title: "codespaces / copilot", Scopes: []config.OptionalScope{
		{ID: "codespace", Label: "manage codespaces"},
		{ID: "codespace:secrets", Label: "codespaces user secrets"},
		{ID: "copilot", Label: "manage copilot subscription"},
		{ID: "manage_billing:copilot", Label: "copilot billing"},
	}},
	{Title: "enterprise / audit", Scopes: []config.OptionalScope{
		{ID: "admin:enterprise", Label: "manage enterprise"},
		{ID: "manage_billing:enterprise", Label: "enterprise billing"},
		{ID: "manage_runners:enterprise", Label: "enterprise runners"},
		{ID: "read:enterprise", Label: "read enterprise"},
		{ID: "audit_log", Label: "manage audit log"},
		{ID: "read:audit_log", Label: "read audit log"},
	}},
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*GitHubOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "github_oauth",
		New:     newer[GitHubOAuth](),
		Runtime: (*GitHubOAuth)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
