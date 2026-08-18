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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

var (
	discordUsersMeURL = "https://discord.com/api/v10/users/@me"
	discordHTTPClient = &http.Client{Timeout: 5 * time.Second}
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

// VerifyCredential confirms the bot token is live by calling
// Discord's GET /users/@me. Returns nil on success or an error
// carrying the Discord error message on failure.
func (*DiscordBotToken) VerifyCredential(ctx context.Context, sec runtime.Secret) error {
	tok := discordBotTokenSecret(sec)
	if tok == "" {
		return fmt.Errorf("no bot token to verify")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", discordUsersMeURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bot "+tok)
	resp, err := discordHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var parsed struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &parsed)
	if parsed.Message != "" {
		return fmt.Errorf("discord users/@me: %s", parsed.Message)
	}
	return fmt.Errorf("discord users/@me: HTTP %d", resp.StatusCode)
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*DiscordBotToken)(nil)
	var _ runtime.WebSocketCredentialRuntime = (*DiscordBotToken)(nil)
	var _ config.EnvPushdownProvider = (*DiscordBotToken)(nil)
	var _ runtime.CredentialVerifier = (*DiscordBotToken)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "discord_bot_token",
		Disambiguators: []string{"placeholder"},
		New:            newer[DiscordBotToken](),
		Runtime:        (*DiscordBotToken)(nil),
		Build:          passthrough,
		Emit:           emptyEmit,
	})
}
