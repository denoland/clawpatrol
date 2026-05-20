package environments

// discord_environment: env vars Discord bot SDKs read (common
// DISCORD_TOKEN / DISCORD_BOT_TOKEN names). Bound discord_bot_token
// credential supplies the real token at MITM time.

import "github.com/denoland/clawpatrol/internal/config"

// DiscordEnvironment is part of the clawpatrol plugin API.
type DiscordEnvironment struct{}

// EnvVars is part of the clawpatrol plugin API.
func (*DiscordEnvironment) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "DISCORD_TOKEN", Value: phDiscord, Description: "Discord bot token placeholder (common SDK/example env var)"},
		{Name: "DISCORD_BOT_TOKEN", Value: phDiscord, Description: "Discord bot token placeholder"},
	}
}

func init() {
	var _ config.EnvironmentRuntime = (*DiscordEnvironment)(nil)
	config.Register(&config.Plugin{
		Kind:  config.KindEnvironment,
		Type:  "discord_environment",
		New:   newer[DiscordEnvironment](),
		Build: passthrough,
		Emit:  emptyEmit,
	})
}
