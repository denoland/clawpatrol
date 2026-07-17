package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// recordInstalls swaps installCATrustFn for a fake that records the bytes of
// whatever path it's handed, and returns the slice it appends to.
func recordInstalls(t *testing.T) *[][]byte {
	t.Helper()
	var installed [][]byte
	prev := installCATrustFn
	installCATrustFn = func(p string) error {
		b, _ := os.ReadFile(p)
		installed = append(installed, append([]byte(nil), b...))
		return nil
	}
	t.Cleanup(func() { installCATrustFn = prev })
	return &installed
}

// TestInstallTrustReinstallsOnCAChange (round-7 #1): trust installation is keyed
// on the on-disk CA's identity, not a bare boolean. A rejoin that replaces
// ca.crt with a different CA must re-install it.
func TestInstallTrustReinstallsOnCAChange(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	oldCA, _, _ := mintCA(t, "old-gateway", 1)
	newCA, _, _ := mintCA(t, "new-gateway", 2)
	installed := recordInstalls(t)

	s := &joinSetup{caPath: caPath}

	if err := os.WriteFile(caPath, oldCA, 0o644); err != nil {
		t.Fatal(err)
	}
	s.installTrust(false)
	s.installTrust(false)
	if len(*installed) != 1 {
		t.Fatalf("same CA should install exactly once, got %d", len(*installed))
	}

	if err := os.WriteFile(caPath, newCA, 0o644); err != nil {
		t.Fatal(err)
	}
	s.installTrust(false)
	if len(*installed) != 2 {
		t.Fatalf("a changed CA must re-install, got %d installs", len(*installed))
	}
	if !bytes.Equal(bytes.TrimSpace((*installed)[1]), bytes.TrimSpace(newCA)) {
		t.Error("the re-install must carry the new CA, not the old one")
	}
}

// TestInstallTrustRejectsFingerprintMismatch (round-8 #2): if the operator
// confirmed a fingerprint, a ca.crt that was swapped between approval and
// install (different fingerprint) must NOT be installed.
func TestInstallTrustRejectsFingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	approved, _, _ := mintCA(t, "approved", 1)
	approvedFP, err := caFingerprintFromPEM(approved)
	if err != nil {
		t.Fatal(err)
	}
	attacker, _, _ := mintCA(t, "attacker", 2)
	if err := os.WriteFile(caPath, attacker, 0o644); err != nil { // swapped on disk
		t.Fatal(err)
	}
	installed := recordInstalls(t)

	s := &joinSetup{caPath: caPath, caFingerprint: approvedFP}
	s.installTrust(false)
	if len(*installed) != 0 {
		t.Error("a ca.crt not matching the approved fingerprint must not be installed")
	}
}

// TestInstallTrustUsesPrivateSnapshot (round-8 #2): install happens from a
// private temp snapshot, never by re-opening the user-controlled ca.crt path.
func TestInstallTrustUsesPrivateSnapshot(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	ca, _, _ := mintCA(t, "ca", 1)
	if err := os.WriteFile(caPath, ca, 0o644); err != nil {
		t.Fatal(err)
	}
	var installedPath string
	prev := installCATrustFn
	installCATrustFn = func(p string) error { installedPath = p; return nil }
	t.Cleanup(func() { installCATrustFn = prev })

	s := &joinSetup{caPath: caPath}
	s.installTrust(false)
	if installedPath == "" || installedPath == caPath {
		t.Errorf("must install from a private snapshot, not the user ca.crt path (got %q)", installedPath)
	}
}

// TestCommitApprovedCARotation (round-8 #3 + macOS coverage): commitApprovedCA
// writes the approved CA and installs it; across a rejoin with SEPARATE
// joinSetup instances (installedCAFP is in-memory) the new CA is written and
// re-installed, so a gateway rotation doesn't leave the old CA as the only
// trusted one.
func TestCommitApprovedCARotation(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	v1, _, _ := mintCA(t, "gateway-A", 1)
	v2, _, _ := mintCA(t, "gateway-B", 2)
	installed := recordInstalls(t)

	// First join.
	s1 := &joinSetup{caPath: caPath}
	if err := s1.commitApprovedCA(v1, false); err != nil {
		t.Fatalf("commit v1: %v", err)
	}
	if got, _ := os.ReadFile(caPath); !bytes.Equal(got, v1) {
		t.Error("ca.crt must hold the committed CA v1")
	}

	// Rejoin to a rotated gateway with a fresh joinSetup.
	s2 := &joinSetup{caPath: caPath}
	if err := s2.commitApprovedCA(v2, false); err != nil {
		t.Fatalf("commit v2: %v", err)
	}
	if got, _ := os.ReadFile(caPath); !bytes.Equal(got, v2) {
		t.Error("ca.crt must hold the rotated CA v2")
	}
	if len(*installed) != 2 {
		t.Fatalf("rotation must re-install, got %d installs", len(*installed))
	}
	if !bytes.Equal(bytes.TrimSpace((*installed)[1]), bytes.TrimSpace(v2)) {
		t.Error("the second install must be the rotated CA v2")
	}
}

// TestCommitApprovedCARejectsEmpty guards the internal invariant that a
// tailscale path never commits without an approved CA.
func TestCommitApprovedCARejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	s := &joinSetup{caPath: filepath.Join(dir, "ca.crt")}
	if err := s.commitApprovedCA(nil, false); err == nil {
		t.Error("committing an empty CA must error")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err == nil {
		t.Error("no ca.crt should be written for an empty commit")
	}
}
