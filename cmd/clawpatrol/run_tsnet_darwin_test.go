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

	t.Run("wireguard", func(t *testing.T) {
		hits.Store(0)
		got, err := envPushdownGatewayFetcher(writePushdownDir(t, "wireguard"))
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if hits.Load() != 1 {
			t.Fatalf("gateway hits = %d, want 1", hits.Load())
		}
		if len(got) != 1 || got[0].Name != "FOO" || got[0].Value != "from-gateway" {
			t.Fatalf("vars = %#v", got)
		}
	})

	t.Run("no_mode_file", func(t *testing.T) {
		hits.Store(0)
		if _, err := envPushdownGatewayFetcher(writePushdownDir(t, "")); err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if hits.Load() != 1 {
			t.Fatalf("gateway hits = %d, want 1", hits.Load())
		}
	})

	t.Run("tailscale", func(t *testing.T) {
		hits.Store(0)
		_, err := envPushdownGatewayFetcher(writePushdownDir(t, "tailscale"))
		if hits.Load() != 0 {
			t.Fatalf("tailscale mode called the gateway %d times", hits.Load())
		}
		// No tsnet config in CI or in a WireGuard install: the extension
		// refuses, or the session socket is not there. Either way the
		// fetch must have gone to the extension, not to the gateway.
		if err == nil || (!strings.Contains(err.Error(), "NE refused getenv") && !strings.Contains(err.Error(), "dial NE session socket")) {
			t.Fatalf("tailscale fetch error = %v, want the extension path", err)
		}
	})
}
