//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxSystemRootsReader(t *testing.T) {
	dir := t.TempDir()
	want := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	present := filepath.Join(dir, "ca-certificates.crt")
	if err := os.WriteFile(present, want, 0o644); err != nil {
		t.Fatal(err)
	}

	prev := systemRootCertFiles
	t.Cleanup(func() { systemRootCertFiles = prev })

	// First candidate missing, second present → reader returns the second.
	systemRootCertFiles = []string{filepath.Join(dir, "missing.crt"), present}
	got, ok := defaultSystemRootsReader()
	if !ok {
		t.Fatal("expected ok when a candidate exists")
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}

	// No candidate exists → (nil, false).
	systemRootCertFiles = []string{filepath.Join(dir, "nope.crt")}
	if _, ok := defaultSystemRootsReader(); ok {
		t.Error("expected (nil,false) when no candidate exists")
	}

	// An empty file is skipped, not returned as roots.
	empty := filepath.Join(dir, "empty.crt")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	systemRootCertFiles = []string{empty}
	if _, ok := defaultSystemRootsReader(); ok {
		t.Error("expected empty file to be skipped")
	}
}
