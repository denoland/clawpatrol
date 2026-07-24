//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWholeMachineEnvVars (round-5 #1): the whole-machine direct path must
// inject the local combined-bundle CA vars itself and must strip clawpatrol-
// owned CA names from the gateway list, so a plugin-provided SSL_CERT_FILE
// can't override the local bundle and the MITM CA is still trusted.
func TestWholeMachineEnvVars(t *testing.T) {
	isolateLinuxRoots(t)
	mitmPEM, _, _ := mintCA(t, "mitm", 1)
	sysPEM, _, _ := mintCA(t, "sysroot", 2)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// point the machine reader at a controlled aggregate
	agg := filepath.Join(dir, "ca-certificates.crt")
	if err := os.WriteFile(agg, sysPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	systemRootCertFiles = []string{agg}
	bundlePath := filepath.Join(dir, "ca-bundle.crt")

	prevGW := envPushdownGatewayFetcher
	t.Cleanup(func() { envPushdownGatewayFetcher = prevGW })
	envPushdownGatewayFetcher = func(string) ([]pushdownEnvVar, error) {
		return []pushdownEnvVar{
			{Name: "SSL_CERT_FILE", Value: "/gateway/evil.pem"},
			{Name: "CODEX_ACCESS_TOKEN", Value: "from-server"},
		}, nil
	}

	m := map[string]string{}
	for _, ev := range wholeMachineEnvVars(dir) {
		m[ev.Name] = ev.Value // last-wins, mirroring the consumer
	}
	if m["SSL_CERT_FILE"] != bundlePath {
		t.Errorf("SSL_CERT_FILE = %q, want local bundle %q (gateway value must be filtered)", m["SSL_CERT_FILE"], bundlePath)
	}
	if m["CODEX_ACCESS_TOKEN"] != "from-server" {
		t.Errorf("non-CA gateway var dropped: %q", m["CODEX_ACCESS_TOKEN"])
	}

	// Even when the gateway fetch fails, the local CA vars must still be present.
	envPushdownGatewayFetcher = func(string) ([]pushdownEnvVar, error) { return nil, os.ErrDeadlineExceeded }
	m = map[string]string{}
	for _, ev := range wholeMachineEnvVars(dir) {
		m[ev.Name] = ev.Value
	}
	if m["SSL_CERT_FILE"] != bundlePath {
		t.Errorf("gateway down: SSL_CERT_FILE = %q, want local bundle %q", m["SSL_CERT_FILE"], bundlePath)
	}
}
