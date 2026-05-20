package environments

// github_environment: env vars the gh CLI / Octokit SDKs / GitHub
// Actions read. Bound github_oauth credential supplies the real
// bearer at MITM time.

import "github.com/denoland/clawpatrol/internal/config"

// GitHubEnvironment is part of the clawpatrol plugin API.
type GitHubEnvironment struct{}

// EnvVars is part of the clawpatrol plugin API.
func (*GitHubEnvironment) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "GH_TOKEN", Value: phGitHub, Description: "gh CLI"},
		{Name: "GITHUB_TOKEN", Value: phGitHub, Description: "GitHub Actions / SDKs"},
	}
}

func init() {
	var _ config.EnvironmentRuntime = (*GitHubEnvironment)(nil)
	config.Register(&config.Plugin{
		Kind:  config.KindEnvironment,
		Type:  "github_environment",
		New:   newer[GitHubEnvironment](),
		Build: passthrough,
		Emit:  emptyEmit,
	})
}
