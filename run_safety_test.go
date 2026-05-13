package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFindGatewayStateLeakHomeDB drops a fake gateway sqlite db into
// $HOME/.clawpatrol/state and checks that findGatewayStateLeak picks
// it up. HOME is rewritten for the duration of the test.
func TestFindGatewayStateLeakHomeDB(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".clawpatrol/state"), 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, ".clawpatrol/state/clawpatrol.db")
	if err := os.WriteFile(dbPath, []byte("fake sqlite\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	got := findGatewayStateLeak()
	if got != dbPath {
		t.Errorf("got %q, want %q", got, dbPath)
	}
}

// TestFindGatewayStateLeakNone confirms that an isolated HOME with
// no clawpatrol artifacts returns "". (The well-known absolute paths
// like /opt/clawpatrol/... are unlikely to exist on a CI runner, but
// we don't assert that — the test would be flaky on a developer
// machine that does run a local gateway.)
func TestFindGatewayStateLeakNone(t *testing.T) {
	if findGatewayStateLeak() != "" {
		t.Skip("a gateway state db exists in one of the candidate paths on this host; skipping the negative case")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if got := findGatewayStateLeak(); got != "" {
		t.Errorf("expected no leak with empty HOME; got %q", got)
	}
}
