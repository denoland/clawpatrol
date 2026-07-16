//go:build darwin

package main

import (
	"bytes"
	"fmt"
	"testing"
)

// Note: the macOS CI job only runs -run 'Sandbox|Dial|Nosy|Plugin|
// ExternalCredential', so this test runs locally, not in CI.
func TestDarwinSystemRootsReader(t *testing.T) {
	prevKC := systemRootKeychain
	prevRun := runSecurityFindCerts
	t.Cleanup(func() {
		systemRootKeychain = prevKC
		runSecurityFindCerts = prevRun
	})

	// Only the curated SystemRoot keychain is dumped — never System.keychain,
	// whose certs aren't trust-evaluated.
	var dumped []string
	systemRootKeychain = "/curated/roots.keychain"
	runSecurityFindCerts = func(keychain string) ([]byte, error) {
		dumped = append(dumped, keychain)
		return []byte("PEM(" + keychain + ")\n"), nil
	}
	got, ok := defaultSystemRootsReader("")
	if !ok || !bytes.Equal(got, []byte("PEM(/curated/roots.keychain)\n")) {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	if len(dumped) != 1 || dumped[0] != "/curated/roots.keychain" {
		t.Errorf("expected exactly the SystemRoot keychain dumped, got %v", dumped)
	}

	// security failure → (nil, false), so ensureCABundle falls back safely.
	runSecurityFindCerts = func(string) ([]byte, error) { return nil, fmt.Errorf("boom") }
	if _, ok := defaultSystemRootsReader(""); ok {
		t.Error("expected (nil,false) when security fails")
	}

	// Empty output → (nil, false).
	runSecurityFindCerts = func(string) ([]byte, error) { return nil, nil }
	if _, ok := defaultSystemRootsReader(""); ok {
		t.Error("expected (nil,false) on empty security output")
	}
}
