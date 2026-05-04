package credentials

import "github.com/denoland/clawpatrol/config"

// Per-credential EnvVars() implementations. Placeholder values are
// chosen to look like real tokens so the agent CLI's startup
// validation accepts them. The gateway overwrites the auth slot at
// MITM time via the credential plugin's InjectHTTP, so the
// placeholder bytes never reach the upstream.

// Per-credential env-var placeholders. Only credentials whose CLI /
// SDK reads from a process env var on startup contribute pushdown
// lines. Slack / Telegram / Notion SDKs take the token as an explicit
// argument or config field rather than env, so they don't need
// `clawpatrol env` lines — the gateway just overwrites the auth slot
// at MITM time regardless.
const (
	phClaude = "sk-ant-oat01-clawpatrol-placeholder-do-not-use"
	phOpenAI = "sk-clawpatrol-placeholder-do-not-use"
	phGitHub = "ghp_clawpatrol_placeholder_do_not_use"
	phGemini = "AIzaClawpatrolPlaceholderDoNotUse00000000"
)

func (*AnthropicOAuthSubscription) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "ANTHROPIC_AUTH_TOKEN", Value: phClaude, Description: "Claude Code / Anthropic SDKs"},
	}
}

func (*AnthropicManualKey) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "ANTHROPIC_API_KEY", Value: phClaude, Description: "Anthropic API key (manual)"},
	}
}

func (*OpenAICodexOAuth) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "OPENAI_API_KEY", Value: phOpenAI, Description: "OpenAI / Codex CLI"},
	}
}

func (*GitHubOAuth) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "GH_TOKEN", Value: phGitHub, Description: "gh CLI"},
		{Name: "GITHUB_TOKEN", Value: phGitHub, Description: "GitHub Actions / SDKs"},
	}
}

func (*GeminiAPIKey) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "GOOGLE_API_KEY", Value: phGemini, Description: "Gemini SDKs"},
		{Name: "GEMINI_API_KEY", Value: phGemini, Description: "Gemini CLI"},
	}
}
