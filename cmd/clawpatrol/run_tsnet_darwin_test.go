//go:build darwin

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The macOS init used to send every env-pushdown fetch through the
// Network Extension. That extension answers getenv only when it has a
// tsnet config, so a WireGuard run printed "NE refused getenv" and
// skipped the placeholders. WireGuard mode reaches the gateway on the
// host network and must use the direct fetch.
func TestEnvPushdownFetcherFollowsTransportMode(t *testing.T) {
	prevGW, prevNE := envPushdownGatewayFetcher, envPushdownNEFetcher
	t.Cleanup(func() { envPushdownGatewayFetcher, envPushdownNEFetcher = prevGW, prevNE })
	var neCalls atomic.Int32
	envPushdownNEFetcher = func(string) ([]pushdownEnvVar, error) {
		neCalls.Add(1)
		return []pushdownEnvVar{{Name: "FOO", Value: "from-extension"}}, nil
	}

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/api/env-pushdown" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vars": []map[string]string{{"name": "FOO", "value": "from-gateway"}},
		})
	}))
	t.Cleanup(srv.Close)

	writePushdownDir := func(t *testing.T, mode string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "gateway"), []byte(srv.URL+"\n"), 0o644); err != nil {
			t.Fatalf("write gateway: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "api-token"), []byte("test-token\n"), 0o600); err != nil {
			t.Fatalf("write api-token: %v", err)
		}
		if mode != "" {
			if err := os.WriteFile(filepath.Join(dir, "mode"), []byte(mode+"\n"), 0o644); err != nil {
				t.Fatalf("write mode: %v", err)
			}
		}
		return dir
	}

	for _, tc := range []struct {
		mode      string
		wantValue string
		wantHits  int32
		wantNE    int32
	}{
		{mode: "wireguard", wantValue: "from-gateway", wantHits: 1},
		{mode: "", wantValue: "from-gateway", wantHits: 1},
		{mode: "tailscale", wantValue: "from-extension", wantNE: 1},
	} {
		name := tc.mode
		if name == "" {
			name = "no_mode_file"
		}
		t.Run(name, func(t *testing.T) {
			hits.Store(0)
			neCalls.Store(0)
			got, err := fetchEnvPushdownForMode(writePushdownDir(t, tc.mode))
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if hits.Load() != tc.wantHits || neCalls.Load() != tc.wantNE {
				t.Fatalf("gateway hits = %d, extension calls = %d; want %d, %d",
					hits.Load(), neCalls.Load(), tc.wantHits, tc.wantNE)
			}
			if len(got) != 1 || got[0].Name != "FOO" || got[0].Value != tc.wantValue {
				t.Fatalf("vars = %#v, want FOO=%s", got, tc.wantValue)
			}
		})
	}
}

// The WireGuard run path calls envPushdownGatewayFetcher, so init must
// install the mode-aware fetcher rather than the extension call.
func TestDarwinInitInstallsModeAwareFetcher(t *testing.T) {
	prevNE := envPushdownNEFetcher
	t.Cleanup(func() { envPushdownNEFetcher = prevNE })
	envPushdownNEFetcher = func(string) ([]pushdownEnvVar, error) {
		t.Fatal("wireguard mode called the extension fetcher")
		return nil, nil
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mode"), []byte("wireguard\n"), 0o644); err != nil {
		t.Fatalf("write mode: %v", err)
	}
	_, err := envPushdownGatewayFetcher(dir)
	if err == nil || !strings.Contains(err.Error(), "gateway URL not persisted") {
		t.Fatalf("err = %v, want the direct fetch's missing gateway URL error", err)
	}
}
