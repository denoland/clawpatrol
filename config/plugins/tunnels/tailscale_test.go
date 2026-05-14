package tunnels

import (
	"os"
	"path/filepath"
	"testing"

	cruntime "github.com/denoland/clawpatrol/config/runtime"
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
