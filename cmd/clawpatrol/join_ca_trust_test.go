package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestInstallTrustReinstallsOnCAChange (round-7 #1): trust installation is keyed
// on the on-disk CA's identity, not a bare boolean. A rejoin that replaces
// ca.crt with a different CA must re-install it — the old boolean guard treated
// any prior install (e.g. the previous gateway's CA installed by finishJoinSetup
// before the new CA was written) as "done" and left system trust on the old CA.
func TestInstallTrustReinstallsOnCAChange(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	oldCA, _, _ := mintCA(t, "old-gateway", 1)
	newCA, _, _ := mintCA(t, "new-gateway", 2)

	var installed [][]byte
	prev := installCATrustFn
	installCATrustFn = func(p string) error {
		b, _ := os.ReadFile(p)
		installed = append(installed, append([]byte(nil), b...))
		return nil
	}
	t.Cleanup(func() { installCATrustFn = prev })

	s := &joinSetup{caPath: caPath}

	// First join: old CA installed once; a redundant call is a no-op.
	if err := os.WriteFile(caPath, oldCA, 0o644); err != nil {
		t.Fatal(err)
	}
	s.installTrust(false)
	s.installTrust(false)
	if len(installed) != 1 {
		t.Fatalf("same CA should install exactly once, got %d", len(installed))
	}

	// Rejoin: ca.crt replaced with a different CA — must re-install.
	if err := os.WriteFile(caPath, newCA, 0o644); err != nil {
		t.Fatal(err)
	}
	s.installTrust(false)
	if len(installed) != 2 {
		t.Fatalf("a changed CA must re-install, got %d installs", len(installed))
	}
	if !bytes.Equal(bytes.TrimSpace(installed[1]), bytes.TrimSpace(newCA)) {
		t.Error("the re-install must carry the new CA, not the old one")
	}
}
