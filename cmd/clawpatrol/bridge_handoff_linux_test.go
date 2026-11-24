//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteTunFilesBuildsBundleAfterWritingFreshCA(t *testing.T) {
	systemCA, _, _ := mintCA(t, "system-root", 1)
	gatewayCA, _, _ := mintCA(t, "gateway-root", 2)
	prev := systemRootsReader
	systemRootsReader = func() ([]byte, bool) { return systemCA, true }
	t.Cleanup(func() { systemRootsReader = prev })

	dir := t.TempDir()
	opt := bridgeOptions{
		EnvOut:    filepath.Join(dir, "env"),
		CAOut:     filepath.Join(dir, "ca.crt"),
		ReadyFile: filepath.Join(dir, "ready"),
	}
	if err := writeTunFiles(opt, []pushdownEnvVar{{Name: "EXAMPLE", Value: "value"}}, string(gatewayCA)); err != nil {
		t.Fatalf("writeTunFiles: %v", err)
	}

	bundlePath := filepath.Join(dir, "ca-bundle.crt")
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read CA bundle: %v", err)
	}
	if !bytes.Contains(bundle, systemCA) || !bytes.Contains(bundle, gatewayCA) {
		t.Fatal("CA bundle does not contain both system and freshly enrolled gateway roots")
	}
	env, err := os.ReadFile(opt.EnvOut)
	if err != nil {
		t.Fatalf("read env handoff: %v", err)
	}
	if !strings.Contains(string(env), `export SSL_CERT_FILE="`+bundlePath+`"`) {
		t.Fatalf("SSL_CERT_FILE does not reference fresh combined bundle:\n%s", env)
	}
}

// A CA var sent by the gateway must not displace the local bundle in the
// exported env file.
func TestWriteTunFilesDropsGatewayCAVars(t *testing.T) {
	systemCA, _, _ := mintCA(t, "system-root", 1)
	gatewayCA, _, _ := mintCA(t, "gateway-root", 2)
	prev := systemRootsReader
	systemRootsReader = func() ([]byte, bool) { return systemCA, true }
	t.Cleanup(func() { systemRootsReader = prev })

	dir := t.TempDir()
	opt := bridgeOptions{
		EnvOut:    filepath.Join(dir, "env"),
		CAOut:     filepath.Join(dir, "ca.crt"),
		ReadyFile: filepath.Join(dir, "ready"),
	}
	vars := []pushdownEnvVar{
		{Name: "SSL_CERT_FILE", Value: "/evil/ca.pem"},
		{Name: "NODE_EXTRA_CA_CERTS", Value: "/evil/ca.pem"},
		{Name: "EXAMPLE", Value: "value"},
	}
	if err := writeTunFiles(opt, vars, string(gatewayCA)); err != nil {
		t.Fatalf("writeTunFiles: %v", err)
	}
	env, err := os.ReadFile(opt.EnvOut)
	if err != nil {
		t.Fatalf("read env handoff: %v", err)
	}
	if strings.Contains(string(env), "/evil/") {
		t.Fatalf("gateway CA var reached the env file:\n%s", env)
	}
	if !strings.Contains(string(env), `export EXAMPLE="value"`) {
		t.Fatalf("non-CA var missing from the env file:\n%s", env)
	}
}

func TestBridgeClearsStaleReadyOnStartup(t *testing.T) {
	dir := t.TempDir()
	opt := bridgeOptions{
		AuthorizerType: "unsupported",
		FWMark:         defaultBridgeFwmark,
		EnvOut:         filepath.Join(dir, "env"),
		ReadyFile:      filepath.Join(dir, "ready"),
	}
	for path, data := range map[string]string{opt.EnvOut: "existing handoff", opt.ReadyFile: "old readiness"} {
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resolver, client, hosts := bridgeResolver, enrollmentHTTPClient, bridgeStaticHosts
	t.Cleanup(func() { bridgeResolver, enrollmentHTTPClient, bridgeStaticHosts = resolver, client, hosts })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bridgeRun(ctx, opt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(opt.ReadyFile); !os.IsNotExist(err) {
		t.Fatalf("old readiness marker survived startup: %v", err)
	}
	if err := writeBridgeReady(opt.ReadyFile); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(opt.ReadyFile); err != nil || string(data) == "old readiness" || len(data) == 0 {
		t.Fatalf("new readiness marker = %q, err = %v", data, err)
	}
	if data, err := os.ReadFile(opt.EnvOut); err != nil || string(data) != "existing handoff" {
		t.Fatalf("handoff after a readiness update = %q, err = %v", data, err)
	}
}
