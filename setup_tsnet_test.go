package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Round-trip: persistTsnetJoinConfig writes operator-supplied flags
// alongside the CA, and loadTsnetJoinConfig only declares ok once
// the tsnet state dir is also present (so a stale exit-node file
// from a previous join doesn't switch `clawpatrol run` to a path
// whose state dir was wiped).
func TestTsnetJoinConfigRoundTrip(t *testing.T) {
	caDir := t.TempDir()

	opts := tsnetJoinOpts{
		exitNode:   "clawpatrol-gateway",
		controlURL: "https://controlplane.example.com",
		hostname:   "laptop-alice",
		clientDir:  filepath.Join(caDir, tsnetClientDir),
	}
	if err := persistTsnetJoinConfig(caDir, opts); err != nil {
		t.Fatalf("persist: %v", err)
	}

	if _, ok := loadTsnetJoinConfig(caDir); ok {
		t.Fatalf("load returned ok=true with no state dir on disk")
	}

	if err := os.MkdirAll(opts.clientDir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}

	got, ok := loadTsnetJoinConfig(caDir)
	if !ok {
		t.Fatalf("load ok=false after persist + state dir created")
	}
	if got.exitNode != opts.exitNode {
		t.Fatalf("exitNode = %q, want %q", got.exitNode, opts.exitNode)
	}
	if got.controlURL != opts.controlURL {
		t.Fatalf("controlURL = %q, want %q", got.controlURL, opts.controlURL)
	}
	if got.hostname != opts.hostname {
		t.Fatalf("hostname = %q, want %q", got.hostname, opts.hostname)
	}
	if got.clientDir != opts.clientDir {
		t.Fatalf("clientDir = %q, want %q", got.clientDir, opts.clientDir)
	}

	// Persisted exit-node file must not be world-readable; it's not a
	// secret today but the join helpers also write secret-adjacent
	// material with these helpers, so we want 0600 baseline.
	st, err := os.Stat(filepath.Join(caDir, tsnetExitNodeFile))
	if err != nil {
		t.Fatalf("stat exit-node file: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("exit-node mode = %#o, want 0600", mode)
	}
}

func TestTsnetJoinConfigOmittedFieldsAreCleaned(t *testing.T) {
	caDir := t.TempDir()
	if err := persistTsnetJoinConfig(caDir, tsnetJoinOpts{
		exitNode:   "gw",
		controlURL: "https://controlplane.example.com",
	}); err != nil {
		t.Fatalf("persist 1: %v", err)
	}
	// Subsequent join with empty controlURL should remove the prior file.
	if err := persistTsnetJoinConfig(caDir, tsnetJoinOpts{
		exitNode: "gw2",
	}); err != nil {
		t.Fatalf("persist 2: %v", err)
	}
	if _, err := os.Stat(filepath.Join(caDir, tsnetControlURLFile)); !os.IsNotExist(err) {
		t.Fatalf("controlURL file should be gone after empty rewrite, stat err = %v", err)
	}
}
