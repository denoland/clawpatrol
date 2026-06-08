package tunnels

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestDialClosedServer(t *testing.T) {
	tc := &tailscaleTunnelConn{joined: make(chan struct{})}
	if _, err := tc.Dial(context.Background(), "tcp", "x:1"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("want tunnel-closed error, got %v", err)
	}
}

func TestDialReturnsUpErrAfterJoin(t *testing.T) {
	// joined already closed with a permanent up error: Dial surfaces it
	// without touching srv.Dial.
	tc := &tailscaleTunnelConn{name: "corp", srv: &tsnet.Server{}, joined: make(chan struct{})}
	tc.upErr.Store(errors.New("up boom"))
	close(tc.joined)
	if _, err := tc.Dial(context.Background(), "tcp", "x:1"); err == nil || !strings.Contains(err.Error(), "up boom") {
		t.Fatalf("want up boom, got %v", err)
	}
}

func TestDialCtxCancelWhileJoining(t *testing.T) {
	tc := &tailscaleTunnelConn{name: "corp", srv: &tsnet.Server{}, joined: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := tc.Dial(ctx, "tcp", "x:1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("ctx-cancel dial did not return promptly: %v", d)
	}
}

func TestDialTimesOutToActionableError(t *testing.T) {
	old := tunnelJoinWait
	tunnelJoinWait = 20 * time.Millisecond
	defer func() { tunnelJoinWait = old }()

	// credential variant -> "node not connected" dashboard hint
	cred := &tailscaleTunnelConn{name: "corp", credential: "corp-tailnet", srv: &tsnet.Server{}, joined: make(chan struct{})}
	if _, err := cred.Dial(context.Background(), "tcp", "x:1"); err == nil || !strings.Contains(err.Error(), "node not connected") {
		t.Fatalf("want node-not-connected, got %v", err)
	}
	// literal-authkey variant (no credential) -> "still joining"
	auth := &tailscaleTunnelConn{name: "corp", srv: &tsnet.Server{}, joined: make(chan struct{})}
	if _, err := auth.Dial(context.Background(), "tcp", "x:1"); err == nil || !strings.Contains(err.Error(), "still joining") {
		t.Fatalf("want still-joining, got %v", err)
	}
}

func TestDialWaitsForLateJoin(t *testing.T) {
	// The fix: a dial that lands while the tunnel is still joining waits
	// for the join instead of failing fast. joined closes ~30ms in; Dial
	// must block until then (not return immediately) and then proceed past
	// the join gate (observed here via the up error it surfaces).
	old := tunnelJoinWait
	tunnelJoinWait = 2 * time.Second
	defer func() { tunnelJoinWait = old }()

	tc := &tailscaleTunnelConn{name: "corp", srv: &tsnet.Server{}, joined: make(chan struct{})}
	tc.upErr.Store(errors.New("joined late"))
	go func() {
		time.Sleep(30 * time.Millisecond)
		close(tc.joined)
	}()
	start := time.Now()
	_, err := tc.Dial(context.Background(), "tcp", "x:1")
	d := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "joined late") {
		t.Fatalf("want late up error after waiting, got %v", err)
	}
	if d < 25*time.Millisecond {
		t.Fatalf("Dial returned before the join completed (%v) — it did not wait", d)
	}
	if d >= tunnelJoinWait {
		t.Fatalf("Dial hit the timeout (%v) instead of returning when joined closed", d)
	}
}
