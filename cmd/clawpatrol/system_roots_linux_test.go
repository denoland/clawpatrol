//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

const fakeRootPEM = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"

func TestLinuxSystemRootsAggregateFile(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "ca-certificates.crt")
	if err := os.WriteFile(present, []byte(fakeRootPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	prev := systemRootCertFiles
	prevDirs := systemRootCertDirs
	t.Cleanup(func() { systemRootCertFiles = prev; systemRootCertDirs = prevDirs })
	systemRootCertDirs = nil // isolate the aggregate-file path
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")

	// First candidate missing, second present → reader returns the second.
	systemRootCertFiles = []string{filepath.Join(dir, "missing.crt"), present}
	got, ok := defaultSystemRootsReader("")
	if !ok || string(got) != fakeRootPEM {
		t.Fatalf("aggregate file: got %q ok=%v", got, ok)
	}

	// No candidate + no dirs → (nil, false).
	systemRootCertFiles = []string{filepath.Join(dir, "nope.crt")}
	if _, ok := defaultSystemRootsReader(""); ok {
		t.Error("expected (nil,false) when nothing exists")
	}
}

// TestLinuxSystemRootsSSLCertFile: SSL_CERT_FILE overrides the aggregate list,
// but our own generated bundle is excluded to avoid a feedback loop.
func TestLinuxSystemRootsSSLCertFile(t *testing.T) {
	dir := t.TempDir()
	override := filepath.Join(dir, "custom-roots.pem")
	if err := os.WriteFile(override, []byte(fakeRootPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	aggregate := filepath.Join(dir, "ca-certificates.crt")
	if err := os.WriteFile(aggregate, []byte("AGGREGATE"), 0o644); err != nil {
		t.Fatal(err)
	}

	prev := systemRootCertFiles
	prevDirs := systemRootCertDirs
	t.Cleanup(func() { systemRootCertFiles = prev; systemRootCertDirs = prevDirs })
	systemRootCertFiles = []string{aggregate}
	systemRootCertDirs = nil
	t.Setenv("SSL_CERT_DIR", "")

	t.Setenv("SSL_CERT_FILE", override)
	got, ok := defaultSystemRootsReader("")
	if !ok || string(got) != fakeRootPEM {
		t.Fatalf("SSL_CERT_FILE override: got %q ok=%v", got, ok)
	}

	// SSL_CERT_FILE pointing at our own bundle must be ignored (feedback loop
	// guard) — reader falls back to the aggregate file instead.
	selfBundle := filepath.Join(dir, "ca-bundle.crt")
	if err := os.WriteFile(selfBundle, []byte(fakeRootPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", selfBundle)
	got, ok = defaultSystemRootsReader(selfBundle)
	if !ok || string(got) != "AGGREGATE" {
		t.Fatalf("self-bundle guard: got %q ok=%v (want fallback to aggregate)", got, ok)
	}
}

// TestLinuxSystemRootsCertDir: directory-only distros (no aggregate file) and
// explicit SSL_CERT_DIR are covered by scanning the cert directory.
func TestLinuxSystemRootsCertDir(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	if err := os.Mkdir(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "root1.pem"), []byte(fakeRootPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-cert file in the dir must be skipped.
	if err := os.WriteFile(filepath.Join(certDir, "README"), []byte("not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	prev := systemRootCertFiles
	prevDirs := systemRootCertDirs
	t.Cleanup(func() { systemRootCertFiles = prev; systemRootCertDirs = prevDirs })
	systemRootCertFiles = []string{filepath.Join(dir, "no-aggregate.crt")} // none exist
	systemRootCertDirs = []string{certDir}
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")

	got, ok := defaultSystemRootsReader("")
	if !ok || string(got) != fakeRootPEM {
		t.Fatalf("dir fallback: got %q ok=%v", got, ok)
	}

	// Explicit SSL_CERT_DIR is honored even when an aggregate file exists.
	systemRootCertFiles = nil
	t.Setenv("SSL_CERT_DIR", certDir)
	got, ok = defaultSystemRootsReader("")
	if !ok || string(got) != fakeRootPEM {
		t.Fatalf("SSL_CERT_DIR: got %q ok=%v", got, ok)
	}
}
