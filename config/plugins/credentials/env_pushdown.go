package credentials

import "github.com/denoland/clawpatrol-go/config"

// Per-credential EnvVars() implementations. Placeholder values are
// chosen to look like real tokens so the agent CLI's startup
// validation accepts them. The gateway overwrites the auth slot at
// MITM time via the credential plugin's InjectHTTP, so the
// placeholder bytes never reach the upstream.

const (
	phClaude   = "sk-ant-oat01-clawpatrol-placeholder-do-not-use"
	phOpenAI   = "sk-clawpatrol-placeholder-do-not-use"
	phGitHub   = "ghp_clawpatrol_placeholder_do_not_use"
	phSlack    = "xoxb-0000000000-0000000000000-clawpatrolplaceholder"
	phTelegram = "0000000000:clawpatrol-placeholder-do-not-use"
	phGemini   = "AIzaClawpatrolPlaceholderDoNotUse00000000"
	phNotion   = "secret_clawpatrolPlaceholderDoNotUseAsRealKey"
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

func (*SlackTokens) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "SLACK_BOT_TOKEN", Value: phSlack, Description: "Slack SDKs / bolt apps"},
	}
}

func (*TelegramBotToken) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "TELEGRAM_BOT_TOKEN", Value: phTelegram, Description: "Telegram bot SDKs"},
	}
}

func (*GeminiAPIKey) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "GOOGLE_API_KEY", Value: phGemini, Description: "Gemini SDKs"},
		{Name: "GEMINI_API_KEY", Value: phGemini, Description: "Gemini CLI"},
	}
}

func (*NotionOAuth) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "NOTION_TOKEN", Value: phNotion, Description: "Notion SDKs"},
	}
}
