package credentials

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/config/runtime"
)

func TestDiscordInjectHTTPStampsBotAuthorization(t *testing.T) {
	plugin := &DiscordBotToken{}
	req, err := http.NewRequest("GET", "https://discord.com/api/v10/users/@me", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bot "+phDiscord)

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{Bytes: []byte("real.discord.token")}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bot real.discord.token" {
		t.Fatalf("Authorization = %q, want Bot real.discord.token", got)
	}
}

func TestDiscordEnvVarsPushBotTokenPlaceholders(t *testing.T) {
	got := (&DiscordBotToken{}).EnvVars()
	want := map[string]bool{
		"DISCORD_BOT_TOKEN": false,
		"DISCORD_TOKEN":     false,
	}
	for _, ev := range got {
		if _, ok := want[ev.Name]; ok {
			want[ev.Name] = true
			if ev.Value != phDiscord {
				t.Fatalf("%s value = %q, want %q", ev.Name, ev.Value, phDiscord)
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("EnvVars missing %s: %#v", name, got)
		}
	}
}

func TestDiscordRewriteWebSocketPayloadReplacesPlaceholder(t *testing.T) {
	plugin := &DiscordBotToken{}
	payload := []byte(`{"op":2,"d":{"token":"` + phDiscord + `","intents":513}}`)
	rewritten, changed, err := plugin.RewriteWebSocketPayload(t.Context(), bytes.Clone(payload), runtime.Secret{Bytes: []byte("real.discord.token")})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !changed {
		t.Fatal("RewriteWebSocketPayload changed=false, want true")
	}
	if bytes.Contains(rewritten, []byte(phDiscord)) {
		t.Fatalf("rewritten payload still contains placeholder: %s", rewritten)
	}
	if !bytes.Contains(rewritten, []byte(`"token":"real.discord.token"`)) {
		t.Fatalf("rewritten payload does not contain real token: %s", rewritten)
	}
}
