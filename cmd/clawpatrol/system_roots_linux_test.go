//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// isolateLinuxRoots points the reader at controlled fixtures and clears the
// SSL_CERT_* env so a test never reads the host's real trust store.
func isolateLinuxRoots(t *testing.T) {
	t.Helper()
	pf, pd := systemRootCertFiles, systemRootCertDirs
	t.Cleanup(func() { systemRootCertFiles = pf; systemRootCertDirs = pd })
	systemRootCertFiles = nil
	systemRootCertDirs = nil
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")
	t.Setenv("CLAWPATROL_ORIG_SSL_CERT_FILE", "")
}

func TestLinuxAggregateFileSelection(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	certPEM, _, _ := mintCA(t, "aggregate", 1)
	agg := filepath.Join(dir, "ca-certificates.crt")
	if err := os.WriteFile(agg, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// First candidate missing, second present → the second is used.
	systemRootCertFiles = []string{filepath.Join(dir, "missing.crt"), agg}

	got, ok := defaultSystemRootsReader("")
	if !ok || countPEMCerts(got) != 1 || !bytes.Contains(got, certPEM) {
		t.Fatalf("aggregate: ok=%v n=%d", ok, countPEMCerts(got))
	}
}

// TestLinuxSSLCertFileReplaces: SSL_CERT_FILE replaces the aggregate list and
// the default aggregate is NOT consulted (L1 fail-open guard).
func TestLinuxSSLCertFileReplaces(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	aggPEM, _, _ := mintCA(t, "aggregate", 1)
	ovrPEM, _, _ := mintCA(t, "corp", 2)
	agg := filepath.Join(dir, "ca-certificates.crt")
	ovr := filepath.Join(dir, "corp.pem")
	_ = os.WriteFile(agg, aggPEM, 0o644)
	_ = os.WriteFile(ovr, ovrPEM, 0o644)
	systemRootCertFiles = []string{agg}
	t.Setenv("SSL_CERT_FILE", ovr)

	got, ok := defaultSystemRootsReader("")
	if !ok || countPEMCerts(got) != 1 {
		t.Fatalf("override: ok=%v n=%d", ok, countPEMCerts(got))
	}
	if !bytes.Contains(got, ovrPEM) || bytes.Contains(got, aggPEM) {
		t.Error("SSL_CERT_FILE override must yield only the override cert, never the default aggregate")
	}
}

// TestLinuxSSLCertFileUnreadableNoFallback: an unreadable override must not
// fall back to the default aggregate (fail-open). Matches root_unix.go, which
// still scans dirs but never re-reads the default file list.
func TestLinuxSSLCertFileUnreadableNoFallback(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	aggPEM, _, _ := mintCA(t, "aggregate", 1)
	agg := filepath.Join(dir, "ca-certificates.crt")
	_ = os.WriteFile(agg, aggPEM, 0o644)
	systemRootCertFiles = []string{agg}
	systemRootCertDirs = nil // isolate: no dirs
	t.Setenv("SSL_CERT_FILE", filepath.Join(dir, "does-not-exist.pem"))

	if _, ok := defaultSystemRootsReader(""); ok {
		t.Error("unreadable SSL_CERT_FILE must not fall back to the default aggregate")
	}
}

// TestLinuxDirsAlwaysScanned: cert directories are scanned even when an
// aggregate file was found (L4). Roots present only in /etc/ssl/certs must
// appear in the bundle.
func TestLinuxDirsAlwaysScanned(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	aggPEM, _, _ := mintCA(t, "aggregate", 1)
	dirPEM, _, _ := mintCA(t, "dir-only", 2)
	agg := filepath.Join(dir, "ca-certificates.crt")
	_ = os.WriteFile(agg, aggPEM, 0o644)
	certDir := filepath.Join(dir, "certs")
	_ = os.Mkdir(certDir, 0o755)
	_ = os.WriteFile(filepath.Join(certDir, "dir-only.pem"), dirPEM, 0o644)
	systemRootCertFiles = []string{agg}
	systemRootCertDirs = []string{certDir}

	got, ok := defaultSystemRootsReader("")
	if !ok || countPEMCerts(got) != 2 {
		t.Fatalf("dirs+file: ok=%v n=%d", ok, countPEMCerts(got))
	}
	if !bytes.Contains(got, aggPEM) || !bytes.Contains(got, dirPEM) {
		t.Error("bundle must include both the aggregate and directory roots")
	}
}

// TestLinuxDirConcatNoCorruption reproduces the reviewer's finding: two valid
// PEM files where the first lacks a trailing newline must still parse as two
// certs (not zero) after concatenation.
func TestLinuxDirConcatNoCorruption(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	c1, _, _ := mintCA(t, "root1", 1)
	c2, _, _ := mintCA(t, "root2", 2)
	certDir := filepath.Join(dir, "certs")
	_ = os.Mkdir(certDir, 0o755)
	// root1 written WITHOUT a trailing newline.
	_ = os.WriteFile(filepath.Join(certDir, "a-root1.pem"), bytes.TrimRight(c1, "\n"), 0o644)
	_ = os.WriteFile(filepath.Join(certDir, "b-root2.pem"), c2, 0o644)
	// A non-cert file must be ignored.
	_ = os.WriteFile(filepath.Join(certDir, "README"), []byte("not a cert"), 0o644)
	systemRootCertDirs = []string{certDir}

	got, ok := defaultSystemRootsReader("")
	if !ok || countPEMCerts(got) != 2 {
		t.Fatalf("abutment: ok=%v n=%d (want 2)", ok, countPEMCerts(got))
	}
}

// TestLinuxSSLCertDirExplicit: an explicit SSL_CERT_DIR overrides the default
// directories.
func TestLinuxSSLCertDirExplicit(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	certPEM, _, _ := mintCA(t, "dir-root", 1)
	certDir := filepath.Join(dir, "mycerts")
	_ = os.Mkdir(certDir, 0o755)
	_ = os.WriteFile(filepath.Join(certDir, "root.pem"), certPEM, 0o644)
	systemRootCertDirs = []string{filepath.Join(dir, "ignored")} // default, should be overridden
	t.Setenv("SSL_CERT_DIR", certDir)

	got, ok := defaultSystemRootsReader("")
	if !ok || !bytes.Contains(got, certPEM) {
		t.Fatalf("SSL_CERT_DIR: ok=%v", ok)
	}
}

// TestLinuxSSLCertFileOrigPreserved reproduces the two-invocation corporate-CA
// loss (L2): after pushdown sets SSL_CERT_FILE=bundle, the reader must recover
// the original source from CLAWPATROL_ORIG_SSL_CERT_FILE, not fall back to the
// distro aggregate.
func TestLinuxSSLCertFileOrigPreserved(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	corpPEM, _, _ := mintCA(t, "corp", 1)
	aggPEM, _, _ := mintCA(t, "aggregate", 2)
	corp := filepath.Join(dir, "corp.pem")
	agg := filepath.Join(dir, "ca-certificates.crt")
	_ = os.WriteFile(corp, corpPEM, 0o644)
	_ = os.WriteFile(agg, aggPEM, 0o644)
	systemRootCertFiles = []string{agg}

	bundlePath := filepath.Join(dir, "ca-bundle.crt")
	// Second-invocation state: SSL_CERT_FILE already points at our bundle, and
	// the pre-pushdown source was stashed in CLAWPATROL_ORIG_SSL_CERT_FILE.
	_ = os.WriteFile(bundlePath, corpPEM, 0o644)
	t.Setenv("SSL_CERT_FILE", bundlePath)
	t.Setenv("CLAWPATROL_ORIG_SSL_CERT_FILE", corp)

	got, ok := defaultSystemRootsReader(bundlePath)
	if !ok || !bytes.Contains(got, corpPEM) {
		t.Fatalf("corp CA lost across pushdown: ok=%v", ok)
	}
	if bytes.Contains(got, aggPEM) {
		t.Error("must use the preserved corp source, not the distro aggregate")
	}
}

// TestLinuxSelfBundleSymlinkGuard (R2): a symlink in a cert dir pointing at our
// own bundle must be skipped, or the bundle would recursively re-absorb itself.
func TestLinuxSelfBundleSymlinkGuard(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	bundleCert, _, _ := mintCA(t, "bundle-only", 1)
	rootCert, _, _ := mintCA(t, "real-root", 2)
	bundlePath := filepath.Join(dir, "ca-bundle.crt")
	_ = os.WriteFile(bundlePath, bundleCert, 0o644)

	certDir := filepath.Join(dir, "certs")
	_ = os.Mkdir(certDir, 0o755)
	_ = os.WriteFile(filepath.Join(certDir, "real.pem"), rootCert, 0o644)
	// Symlink alias to the bundle (lexically distinct path).
	if err := os.Symlink(bundlePath, filepath.Join(certDir, "alias.pem")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	systemRootCertDirs = []string{certDir}

	got, ok := defaultSystemRootsReader(bundlePath)
	if !ok || !bytes.Contains(got, rootCert) {
		t.Fatalf("real root missing: ok=%v", ok)
	}
	if bytes.Contains(got, bundleCert) {
		t.Error("symlink alias to the bundle was not skipped — recursive growth")
	}
}
