package tunnels

import (
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/tsnet"

	cruntime "github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestTunnelStateDir_HostStateDir(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	root := t.TempDir()
	dir, err := tunnelStateDir(&TailscaleTunnel{}, cruntime.TunnelHost{Name: "ts1", StateDir: root})
	if err != nil {
		t.Fatalf("tunnelStateDir: %v", err)
	}
	want := filepath.Join(root, "tunnels", "tailscale", "ts1")
	if dir != want {
		t.Fatalf("dir = %q, want %q", dir, want)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if !st.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	if mode := st.Mode().Perm(); mode != 0o700 {
		t.Fatalf("mode = %#o, want %#o", mode, 0o700)
	}
}

func TestTunnelStateDir_TunnelOverride(t *testing.T) {
	override := t.TempDir()
	dir, err := tunnelStateDir(
		&TailscaleTunnel{StateDir: override},
		cruntime.TunnelHost{Name: "ts1", StateDir: t.TempDir()},
	)
	if err != nil {
		t.Fatalf("tunnelStateDir: %v", err)
	}
	if dir != override {
		t.Fatalf("dir = %q, want override %q", dir, override)
	}
}

func TestTunnelStateDir_Empty(t *testing.T) {
	if _, err := tunnelStateDir(&TailscaleTunnel{}, cruntime.TunnelHost{Name: "ts1"}); err == nil {
		t.Fatal("expected error for empty state_dir")
	}
}

func TestOAuthSecretWithDefaults(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"tskey-client-abc", "tskey-client-abc?ephemeral=false&preauthorized=true"},
		// An operator-supplied query string is preserved verbatim.
		{"tskey-client-abc?ephemeral=true", "tskey-client-abc?ephemeral=true"},
	}
	for _, c := range cases {
		if got := oauthSecretWithDefaults(c.in); got != c.want {
			t.Errorf("oauthSecretWithDefaults(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEnvOAuthClientSecret(t *testing.T) {
	if got, want := envOAuthClientSecret("deno-tailnet-tunnel"), "CLAWPATROL_TUNNEL_DENO_TAILNET_TUNNEL_OAUTH_CLIENT_SECRET"; got != want {
		t.Errorf("envOAuthClientSecret = %q, want %q", got, want)
	}
}

func TestOAuthClientSecretResolution(t *testing.T) {
	// HCL field wins over the env fallback.
	t.Setenv("CLAWPATROL_TUNNEL_CORP_OAUTH_CLIENT_SECRET", "from-env")
	tn := &TailscaleTunnel{OAuthClientSecret: "from-hcl"}
	if got := tn.oauthClientSecret("corp"); got != "from-hcl" {
		t.Fatalf("oauthClientSecret = %q, want from-hcl", got)
	}
	// Falls back to the per-tunnel env var when the field is empty.
	if got := (&TailscaleTunnel{}).oauthClientSecret("corp"); got != "from-env" {
		t.Fatalf("oauthClientSecret (env) = %q, want from-env", got)
	}
}

func TestApplyOAuth(t *testing.T) {
	// Untagged OAuth config is rejected up front — Tailscale refuses to
	// mint untagged keys, and an untagged node would be owner-associated.
	if err := (&TailscaleTunnel{}).applyOAuth(&tsnet.Server{}, "corp", "tskey-client-abc"); err == nil {
		t.Fatal("applyOAuth without tags: expected error, got nil")
	}
	// With tags it lands the secret in AuthKey (so an ambient TS_AUTHKEY
	// can't shadow it) plus the advertised tags.
	var srv tsnet.Server
	tn := &TailscaleTunnel{Tags: []string{"tag:bot"}}
	if err := tn.applyOAuth(&srv, "corp", "tskey-client-abc"); err != nil {
		t.Fatalf("applyOAuth: %v", err)
	}
	if srv.AuthKey != "tskey-client-abc?ephemeral=false&preauthorized=true" {
		t.Errorf("AuthKey = %q", srv.AuthKey)
	}
	if len(srv.AdvertiseTags) != 1 || srv.AdvertiseTags[0] != "tag:bot" {
		t.Errorf("AdvertiseTags = %v", srv.AdvertiseTags)
	}
}
