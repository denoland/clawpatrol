package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestFetchEnvPushdownFromGateway verifies the client-side decoder
// against the wire format the server-side apiEnvPushdown handler
// emits. Stands up a tiny httptest server returning the same JSON
// shape and confirms the client surfaces it as pushdownEnvVar
// records.
func TestFetchEnvPushdownFromGateway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/env-pushdown" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vars": []map[string]string{
				{"name": "FOO", "value": "1", "description": "d1", "plugin_type": "p1"},
				{"name": "", "value": "skipped"},
				{"name": "BAR", "value": "2"},
			},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gateway"), []byte(srv.URL+"\n"), 0o644); err != nil {
		t.Fatalf("write gateway file: %v", err)
	}

	got, ok := fetchEnvPushdownFromGateway(dir)
	if !ok {
		t.Fatalf("expected ok")
	}
	if len(got) != 2 {
		t.Fatalf("got %d vars want 2: %#v", len(got), got)
	}
	if got[0].Name != "FOO" || got[0].Value != "1" || got[0].Description != "d1" || got[0].PluginType != "p1" {
		t.Errorf("FOO mismatch: %#v", got[0])
	}
	if got[1].Name != "BAR" || got[1].Value != "2" {
		t.Errorf("BAR mismatch: %#v", got[1])
	}
}

// TestFetchEnvPushdownFallback covers the every-failure-mode path:
// no gateway file, unreachable server, 404 from older gateway. All
// must return (nil, false) so envPushdownVars falls back to local
// plugin enumeration without surfacing an error.
func TestFetchEnvPushdownFallback(t *testing.T) {
	t.Run("no_gateway_file", func(t *testing.T) {
		dir := t.TempDir()
		if _, ok := fetchEnvPushdownFromGateway(dir); ok {
			t.Fatal("expected not ok")
		}
	})
	t.Run("server_404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer srv.Close()
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "gateway"), []byte(srv.URL), 0o644)
		if _, ok := fetchEnvPushdownFromGateway(dir); ok {
			t.Fatal("expected not ok on 404")
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		dir := t.TempDir()
		// Bind+close to claim a port nothing listens on.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := l.Addr().String()
		l.Close()
		_ = os.WriteFile(filepath.Join(dir, "gateway"), []byte("http://"+addr), 0o644)
		if _, ok := fetchEnvPushdownFromGateway(dir); ok {
			t.Fatal("expected not ok on unreachable")
		}
	})
}

// TestEnvPushdownVarsServerDriven confirms envPushdownVars uses the
// gateway response when present and surfaces both the CA-bundle
// vars (client-side) plus the server-supplied ones in a single
// flat list.
func TestEnvPushdownVarsServerDriven(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vars": []map[string]string{{"name": "CODEX_ACCESS_TOKEN", "value": "from-server"}},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(caPath, []byte("dummy"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "gateway"), []byte(srv.URL), 0o644)

	got := envPushdownVars(caPath)
	hasSSL, hasCodex := false, false
	for _, ev := range got {
		if ev.Name == "SSL_CERT_FILE" && ev.Value == caPath {
			hasSSL = true
		}
		if ev.Name == "CODEX_ACCESS_TOKEN" && ev.Value == "from-server" {
			hasCodex = true
		}
		// No plugin should have produced a CODEX_ACCESS_TOKEN with
		// our client-side openai_codex_https plugin too — server-
		// driven path short-circuits the local iteration.
		if ev.Name == "CODEX_ACCESS_TOKEN" && ev.Value != "from-server" {
			t.Errorf("CODEX_ACCESS_TOKEN came from local fallback: %#v", ev)
		}
	}
	if !hasSSL {
		t.Errorf("missing SSL_CERT_FILE")
	}
	if !hasCodex {
		t.Errorf("missing CODEX_ACCESS_TOKEN from server")
	}
}
