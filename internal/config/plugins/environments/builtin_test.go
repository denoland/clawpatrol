package environments

// Built-in environment-plugin EnvVars() smoke tests. The point is
// to lock down the env-var names and placeholder values the
// migrated plugins emit, so a future tweak to the placeholder
// constants or the var names trips a clear test failure instead of
// silently breaking operator workflows that source from
// `clawpatrol env`.

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

func TestCustomEnvironmentEnvVarsRoundtrip(t *testing.T) {
	c := &CustomEnvironment{Key: "FOO", Value: "bar", Description: "x"}
	got := c.EnvVars()
	if len(got) != 1 {
		t.Fatalf("len(EnvVars) = %d, want 1", len(got))
	}
	if got[0].Name != "FOO" || got[0].Value != "bar" || got[0].Description != "x" {
		t.Fatalf("EnvVars[0] = %+v, want {FOO bar x}", got[0])
	}
}

func TestCustomEnvironmentEnvVarsEmptyKey(t *testing.T) {
	if got := (&CustomEnvironment{}).EnvVars(); got != nil {
		t.Fatalf("EnvVars = %+v, want nil for empty key", got)
	}
}

func TestAnthropicSubscriptionEnvVars(t *testing.T) {
	got := (&AnthropicSubscriptionEnvironment{}).EnvVars()
	expectExactly(t, got, map[string]string{"ANTHROPIC_AUTH_TOKEN": phClaude})
}

func TestGeminiEnvironmentEnvVars(t *testing.T) {
	got := (&GeminiEnvironment{}).EnvVars()
	expectExactly(t, got, map[string]string{
		"GOOGLE_API_KEY": phGemini,
		"GEMINI_API_KEY": phGemini,
	})
}

func TestGitHubEnvironmentEnvVars(t *testing.T) {
	got := (&GitHubEnvironment{}).EnvVars()
	expectExactly(t, got, map[string]string{
		"GH_TOKEN":     phGitHub,
		"GITHUB_TOKEN": phGitHub,
	})
}

func TestDiscordEnvironmentEnvVars(t *testing.T) {
	got := (&DiscordEnvironment{}).EnvVars()
	expectExactly(t, got, map[string]string{
		"DISCORD_TOKEN":     phDiscord,
		"DISCORD_BOT_TOKEN": phDiscord,
	})
}

func expectExactly(t *testing.T, got []config.EnvVar, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len(EnvVars) = %d, want %d: %+v", len(got), len(want), got)
	}
	gotByName := map[string]string{}
	for _, ev := range got {
		gotByName[ev.Name] = ev.Value
	}
	for name, wantVal := range want {
		if gotByName[name] != wantVal {
			t.Errorf("EnvVars[%q] = %q, want %q", name, gotByName[name], wantVal)
		}
	}
}
