package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

func TestGatewayTsnetDir_CreatesPath(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	root := t.TempDir()
	dir, err := gatewayTsnetDir(root)
	if err != nil {
		t.Fatalf("gatewayTsnetDir: %v", err)
	}
	want := filepath.Join(root, "tsnet")
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

func TestGatewayTsnetDir_EmptyStateDir(t *testing.T) {
	if _, err := gatewayTsnetDir(""); err == nil {
		t.Fatal("expected error for empty state_dir")
	}
}

// TestOpenListener_NoAuthKey covers the WireGuard-mode path: when
// neither authkey nor TS_AUTHKEY is set, openListener binds loopback
// regardless of cfg.Listen's host portion, and is unaffected by
// HOME / XDG_CONFIG_HOME being unset (no tsnet path is reached).
func TestOpenListener_NoAuthKey(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("TS_AUTHKEY", "")
	cfg := &config.Gateway{Control: "wireguard", Listen: "127.0.0.1:0"}
	_, ln, err := openListener(cfg, t.TempDir())
	if err != nil {
		t.Fatalf("openListener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	if host != "127.0.0.1" && host != "::1" {
		t.Errorf("expected loopback bind in WG mode, got %s", host)
	}
}

// TestOpenListener_NoAuthKey_PublicListenIsOverridden verifies that
// an operator-set "0.0.0.0:0" still results in a loopback bind in
// WireGuard mode — the F-19 open-proxy fix. Tailscale system-mode
// intentionally respects cfg.Listen as-is (the operator binds the
// tailnet IP directly); this test is WG-specific.
func TestOpenListener_NoAuthKey_PublicListenIsOverridden(t *testing.T) {
	t.Setenv("TS_AUTHKEY", "")
	cfg := &config.Gateway{Control: "wireguard", Listen: "0.0.0.0:0"}
	_, ln, err := openListener(cfg, t.TempDir())
	if err != nil {
		t.Fatalf("openListener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	if host != "127.0.0.1" && host != "::1" {
		t.Fatalf("expected loopback bind, got %s", host)
	}
}

// TestOpenListener_EnvIndependent verifies that with an authkey set but
// HOME and XDG_CONFIG_HOME unset, openListener does not fail with the
// "neither $XDG_CONFIG_HOME nor $HOME are defined" error from tsnet's
// default-dir resolver. The tsnet.Listen call itself may still error
// (no real control plane in tests), but the failure must not be the
// env-var fallback path.
func TestOpenListener_EnvIndependent(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	cfg := &config.Gateway{
		Listen:  "127.0.0.1:0",
		AuthKey: "tskey-test-invalid",
	}
	// Direct tsnet.Listen against an unreachable control URL avoids the
	// blocking join; we only care that Server construction picked up an
	// explicit Dir rather than consulting env vars.
	cfg.ControlURL = "https://127.0.0.1:1"
	_, _, err := openListener(cfg, t.TempDir())
	if err == nil {
		// A test environment that happens to bring tsnet up against a
		// reachable control plane is fine — just close and return.
		return
	}
	if strings.Contains(err.Error(), "$XDG_CONFIG_HOME") || strings.Contains(err.Error(), "$HOME") {
		t.Fatalf("openListener leaked env-var dependency: %v", err)
	}
}
