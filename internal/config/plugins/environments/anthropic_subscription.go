package environments

// anthropic_subscription_environment: env vars the Anthropic SDKs
// (Claude Code in particular) read when they connect via the
// claude.ai → console.anthropic.com OAuth subscription flow. The
// real bearer is supplied at MITM time by the bound
// anthropic_oauth_subscription credential; the env var carries a
// placeholder that LOOKS like a real token so the SDK's startup
// validation passes.
//
// Sample HCL:
//
//	credential "anthropic_oauth_subscription" "claude" {
//	  endpoint = https.anthropic
//	}
//
//	environment "anthropic_subscription_environment" "claude-env" {
//	  credential = anthropic_oauth_subscription.claude
//	}
//
//	profile "default" {
//	  credentials  = [anthropic_oauth_subscription.claude]
//	  environments = [anthropic_subscription_environment.claude-env]
//	}

import (
	"github.com/denoland/clawpatrol/internal/config"
)

// AnthropicSubscriptionEnvironment is part of the clawpatrol plugin API.
type AnthropicSubscriptionEnvironment struct{}

// EnvVars is part of the clawpatrol plugin API.
func (*AnthropicSubscriptionEnvironment) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "ANTHROPIC_AUTH_TOKEN", Value: phClaude, Description: "Claude Code / Anthropic SDKs"},
	}
}

func init() {
	var _ config.EnvironmentRuntime = (*AnthropicSubscriptionEnvironment)(nil)
	config.Register(&config.Plugin{
		Kind:  config.KindEnvironment,
		Type:  "anthropic_subscription_environment",
		New:   newer[AnthropicSubscriptionEnvironment](),
		Build: passthrough,
		Emit:  emptyEmit,
	})
}
