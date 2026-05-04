package credentials

// github_oauth: bearer token from gh's device-flow OAuth. Used by
// gh CLI + the GitHub REST API (api.github.com / raw.githubusercontent.com).

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type GitHubOAuth struct{}

func (g *GitHubOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	return nil
}

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
	}
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
