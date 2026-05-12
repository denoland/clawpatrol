package credentials

// discord_bot_token lets agents run ordinary Discord bot SDKs without
// exposing the real bot token to the child process. `clawpatrol env`
// pushes token-shaped placeholders into the common Discord SDK env var
// names; REST requests get Authorization: Bot <real token>, and Gateway
// WebSocket IDENTIFY frames have the placeholder swapped inside their JSON
// text payload before the bytes reach Discord.

import (
	"bytes"
	"context"
	"net/http"
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// phDiscord is intentionally token-shaped enough for Discord SDKs and
// example apps that sanity-check env vars before opening REST/Gateway
// connections. The gateway replaces it before it reaches discord.com.
const phDiscord = "MTAwMDAwMDAwMDAwMDAwMDAwMA.clawpatrol-placeholder-do-not-use.xxxxxxxxxxxxxxxxxxxxxxxxxxx"

// DiscordBotToken injects Discord bot tokens for REST and Gateway SDK traffic.
type DiscordBotToken struct{}

// InjectHTTP is part of the clawpatrol plugin API.
func (*DiscordBotToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	tok := discordBotTokenSecret(sec)
	if tok == "" {
		return nil
	}
	auth := req.Header.Get("Authorization")
	if strings.Contains(auth, phDiscord) {
		req.Header.Set("Authorization", strings.ReplaceAll(auth, phDiscord, tok))
		return nil
	}
	// Normal SDKs send `Authorization: Bot <token>` after reading
	// DISCORD_TOKEN / DISCORD_BOT_TOKEN. If the caller omitted the
	// header, stamp the configured bot credential directly.
	if auth == "" {
		req.Header.Set("Authorization", "Bot "+tok)
	}
	return nil
}

// RewriteWebSocketPayload is part of the clawpatrol plugin API.
func (*DiscordBotToken) RewriteWebSocketPayload(_ context.Context, payload []byte, sec runtime.Secret) ([]byte, bool, error) {
	tok := discordBotTokenSecret(sec)
	if tok == "" || !bytes.Contains(payload, []byte(phDiscord)) {
		return payload, false, nil
	}
	return bytes.ReplaceAll(payload, []byte(phDiscord), []byte(tok)), true, nil
}

func discordBotTokenSecret(sec runtime.Secret) string {
	if v := sec.Extras["bot"]; v != "" {
		return v
	}
	return string(sec.Bytes)
}

// SecretSlots is part of the clawpatrol plugin API.
func (*DiscordBotToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Discord bot token", Description: "Bot token from the Discord developer portal"}}
}

// EnvVars is part of the clawpatrol plugin API.
func (*DiscordBotToken) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "DISCORD_TOKEN", Value: phDiscord, Description: "Discord bot token placeholder (common SDK/example env var)"},
		{Name: "DISCORD_BOT_TOKEN", Value: phDiscord, Description: "Discord bot token placeholder"},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*DiscordBotToken)(nil)
	var _ runtime.WebSocketCredentialRuntime = (*DiscordBotToken)(nil)
	var _ config.EnvPushdownProvider = (*DiscordBotToken)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "discord_bot_token",
		New:     newer[DiscordBotToken](),
		Runtime: (*DiscordBotToken)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
