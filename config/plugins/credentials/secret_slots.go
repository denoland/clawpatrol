package credentials

import "github.com/denoland/clawpatrol/config"

// Per-credential SecretSlots() implementations. The dashboard uses
// these to render the connect-credential modal — one input per slot.
// OAuth-flow credentials (anthropic_oauth_subscription, openai_codex_oauth,
// github_oauth, notion_oauth) deliberately don't implement this; their
// auth comes from the OAuth flow instead, and the dashboard renders
// the OAuth connect button.

// Single-slot credentials — one unnamed slot that fills runtime.Secret.Bytes.

func (*BearerToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Bearer token", Description: "Stamped as `Authorization: Bearer …`."}}
}

func (*HeaderToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Header value"}}
}

func (*CookieToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Cookie value"}}
}

func (*AnthropicManualKey) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Anthropic API key", Description: "sk-ant-…"}}
}

func (*PostgresCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Postgres password"}}
}

func (*ClickhouseCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "ClickHouse password"}}
}

func (*GeminiAPIKey) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Gemini API key"}}
}

func (*TelegramBotToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Telegram bot token"}}
}

// Multi-slot credentials — each slot fills runtime.Secret.Extras[Name].

func (*MTLSCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Name: "cert", Label: "Client cert (PEM)", Multiline: true},
		{Name: "key", Label: "Client key (PEM)", Multiline: true},
		{Name: "ca", Label: "CA bundle (PEM, optional)", Multiline: true,
			Description: "Leave empty to use system roots."},
	}
}

func (*SlackTokens) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Name: "bot", Label: "Bot token", Description: "xoxb-…"},
		{Name: "app", Label: "App-level token (optional)", Description: "xapp-…"},
		{Name: "signing_secret", Label: "Signing secret", Description: "Slack app's signing secret — required for interactive approve/deny buttons"},
	}
}

// AWSEKSCredential is configured via mTLS / IAM at the cluster level —
// the gateway shells out to `aws eks get-token`. No paste-secret slots.
