//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// isolateLinuxRoots points the reader at controlled fixtures and clears the
// SSL_CERT_* env — the machine-store reader ignores that env, and clearing it
// keeps the test independent of the host it runs on.
func isolateLinuxRoots(t *testing.T) {
	t.Helper()
	pf, pd := systemRootCertFiles, systemRootCertDirs
	t.Cleanup(func() { systemRootCertFiles = pf; systemRootCertDirs = pd })
	systemRootCertFiles = nil
	systemRootCertDirs = nil
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")
}

// readRoots runs the reader and returns its normalized output, failing if it
// found nothing.
func readRoots(t *testing.T) []byte {
	t.Helper()
	b, ok := defaultSystemRootsReader()
	if !ok {
		t.Fatal("defaultSystemRootsReader returned no roots")
	}
	return normalizeCertsPEM(b)
}

// TestLinuxAggregateFileSelection: the first existing aggregate file is used.
func TestLinuxAggregateFileSelection(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	certPEM, _, _ := mintCA(t, "aggregate", 1)
	agg := filepath.Join(dir, "ca-certificates.crt")
	if err := os.WriteFile(agg, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	systemRootCertFiles = []string{filepath.Join(dir, "missing.crt"), agg}

	if n := countPEMCerts(readRoots(t)); n != 1 {
		t.Fatalf("aggregate: n=%d, want 1", n)
	}
}

// TestLinuxIgnoresSSLCertFileEnv: the machine-store reader does NOT honor
// SSL_CERT_FILE/SSL_CERT_DIR — the bundle must be a function of machine state,
// not the invoking shell's trust env (round-3 #1/#3). An ambient SSL_CERT_FILE
// must not change what the reader returns.
func TestLinuxIgnoresSSLCertFileEnv(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	aggPEM, _, _ := mintCA(t, "aggregate", 1)
	ovrPEM, _, _ := mintCA(t, "operator-override", 2)
	agg := filepath.Join(dir, "ca-certificates.crt")
	ovr := filepath.Join(dir, "operator.pem")
	_ = os.WriteFile(agg, aggPEM, 0o644)
	_ = os.WriteFile(ovr, ovrPEM, 0o644)
	systemRootCertFiles = []string{agg}

	t.Setenv("SSL_CERT_FILE", ovr) // must be ignored
	norm := readRoots(t)
	if !bytes.Contains(norm, aggPEM) || bytes.Contains(norm, ovrPEM) {
		t.Error("reader must use the machine aggregate, not the ambient SSL_CERT_FILE")
	}
}

// TestLinuxDirsAlwaysScanned: cert directories are scanned even when an
// aggregate file exists (root_unix.go parity) — roots present only in a cert
// dir must appear.
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

	norm := readRoots(t)
	if countPEMCerts(norm) != 2 || !bytes.Contains(norm, aggPEM) || !bytes.Contains(norm, dirPEM) {
		t.Errorf("bundle must include both aggregate and directory roots: n=%d", countPEMCerts(norm))
	}
}

// TestLinuxDirConcatNoCorruption reproduces the reviewer's finding: a dir cert
// file lacking a trailing newline must not corrupt its neighbor. The reader
// newline-separates each file and normalizeCertsPEM re-encodes, so both certs
// survive (not zero).
func TestLinuxDirConcatNoCorruption(t *testing.T) {
	isolateLinuxRoots(t)
	dir := t.TempDir()
	c1, _, _ := mintCA(t, "root1", 1)
	c2, _, _ := mintCA(t, "root2", 2)
	certDir := filepath.Join(dir, "certs")
	_ = os.Mkdir(certDir, 0o755)
	_ = os.WriteFile(filepath.Join(certDir, "a-root1.pem"), bytes.TrimRight(c1, "\n"), 0o644)
	_ = os.WriteFile(filepath.Join(certDir, "b-root2.pem"), c2, 0o644)
	_ = os.WriteFile(filepath.Join(certDir, "README"), []byte("not a cert"), 0o644)
	systemRootCertDirs = []string{certDir}

	if n := countPEMCerts(readRoots(t)); n != 2 {
		t.Fatalf("abutment: n=%d (want 2)", n)
	}
}
