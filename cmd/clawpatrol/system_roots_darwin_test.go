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
	prevKC := securityKeychains
	prevRun := runSecurityFindCerts
	t.Cleanup(func() {
		securityKeychains = prevKC
		runSecurityFindCerts = prevRun
	})

	securityKeychains = []string{"/kc/a", "/kc/b"}
	runSecurityFindCerts = func(keychain string) ([]byte, error) {
		return []byte(fmt.Sprintf("PEM(%s)\n", keychain)), nil
	}
	got, ok := defaultSystemRootsReader()
	if !ok {
		t.Fatal("expected ok")
	}
	want := []byte("PEM(/kc/a)\nPEM(/kc/b)\n")
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	// A keychain that errors is skipped; the other still contributes.
	runSecurityFindCerts = func(keychain string) ([]byte, error) {
		if keychain == "/kc/a" {
			return nil, fmt.Errorf("boom")
		}
		return []byte("PEM(b)\n"), nil
	}
	got, ok = defaultSystemRootsReader()
	if !ok || !bytes.Equal(got, []byte("PEM(b)\n")) {
		t.Errorf("partial failure: got %q ok=%v", got, ok)
	}

	// All keychains fail → (nil, false).
	runSecurityFindCerts = func(string) ([]byte, error) { return nil, fmt.Errorf("boom") }
	if _, ok := defaultSystemRootsReader(); ok {
		t.Error("expected (nil,false) when every keychain fails")
	}
}
