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

// TestOpenListener_WireGuardOnlyBindsLoopback covers the WG-only path:
// the loopback TCP listener at 127.0.0.1:8443 is for host-local
// agents (single-host deployments where the gateway runs under one
// UID and clawpatrol-run from another). No tsnet bring-up.
func TestOpenListener_WireGuardOnlyBindsLoopback(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("TS_AUTHKEY", "")
	cfg := &config.Gateway{
		Settings: &config.GatewaySettings{
			WireGuard: &config.WireGuardBlock{SubnetCIDR: "10.55.0.0/24"},
		},
	}
	s, ln, err := openListener(cfg, t.TempDir())
	if err != nil {
		// Address-already-in-use is fine (another test in the package
		// may hold :8443) — what we care about is that no tsnet path
		// was taken.
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("openListener: %v", err)
		}
		return
	}
	if s != nil {
		t.Fatal("expected nil tsnet server in WG-only mode")
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

// TestOpenListener_EnvIndependent verifies that with the tailscale
// block enabled (and an authkey set) but HOME and XDG_CONFIG_HOME
// unset, openListener does not fail with the "neither $XDG_CONFIG_HOME
// nor $HOME are defined" error from tsnet's default-dir resolver. The
// tsnet.Listen call itself may still error (no real control plane in
// tests), but the failure must not be the env-var fallback path.
func TestOpenListener_EnvIndependent(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	cfg := &config.Gateway{
		Settings: &config.GatewaySettings{
			Tailscale: &config.TailscaleBlock{
				AuthKey:    "tskey-test-invalid",
				ControlURL: "https://127.0.0.1:1",
			},
		},
	}
	_, _, err := openListener(cfg, t.TempDir())
	if err == nil {
		// A test environment that happens to bring tsnet up against a
		// reachable control plane is fine — just return.
		return
	}
	if strings.Contains(err.Error(), "$XDG_CONFIG_HOME") || strings.Contains(err.Error(), "$HOME") {
		t.Fatalf("openListener leaked env-var dependency: %v", err)
	}
}
