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
		// Verify the client sent the per-peer bearer; the
		// production handler returns 401 without it.
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
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
	if err := os.WriteFile(filepath.Join(dir, "api-token"), []byte("test-token\n"), 0o600); err != nil {
		t.Fatalf("write api-token: %v", err)
	}

	got, err := fetchEnvPushdownFromGateway(dir)
	if err != nil {
		t.Fatalf("fetch: %v", err)
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

// TestFetchEnvPushdownErrors covers the error paths: no gateway URL
// persisted, server unreachable, server 404. Each must return a
// non-nil error so envPushdownVars can surface it to the caller
// (server-only — there's no local fallback).
func TestFetchEnvPushdownErrors(t *testing.T) {
	t.Run("no_gateway_file", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := fetchEnvPushdownFromGateway(dir); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("no_api_token", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "gateway"), []byte("http://127.0.0.1:1"), 0o644)
		// no api-token file
		if _, err := fetchEnvPushdownFromGateway(dir); err == nil {
			t.Fatal("expected error when token missing")
		}
	})
	t.Run("server_404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer srv.Close()
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "gateway"), []byte(srv.URL), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "api-token"), []byte("t"), 0o600)
		if _, err := fetchEnvPushdownFromGateway(dir); err == nil {
			t.Fatal("expected error on 404")
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
		_ = os.WriteFile(filepath.Join(dir, "api-token"), []byte("t"), 0o600)
		if _, err := fetchEnvPushdownFromGateway(dir); err == nil {
			t.Fatal("expected error on unreachable")
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
	_ = os.WriteFile(filepath.Join(dir, "api-token"), []byte("t"), 0o600)

	got, err := envPushdownVars(caPath)
	if err != nil {
		t.Fatalf("envPushdownVars: %v", err)
	}
	hasSSL, hasCodex := false, false
	for _, ev := range got {
		if ev.Name == "SSL_CERT_FILE" && ev.Value == caPath {
			hasSSL = true
		}
		if ev.Name == "CODEX_ACCESS_TOKEN" && ev.Value == "from-server" {
			hasCodex = true
		}
	}
	if !hasSSL {
		t.Errorf("missing SSL_CERT_FILE")
	}
	if !hasCodex {
		t.Errorf("missing CODEX_ACCESS_TOKEN from server")
	}
}

// TestEnvPushdownVarsErrorReturnsCAOnly: when the gateway is
// unreachable, the function should still return the CA-bundle vars
// (so TLS verification keeps working) but surface the error so the
// caller can warn the operator.
func TestEnvPushdownVarsErrorReturnsCAOnly(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(caPath, []byte("dummy"), 0o644)
	// no gateway file

	got, err := envPushdownVars(caPath)
	if err == nil {
		t.Fatal("expected error when gateway URL missing")
	}
	for _, ev := range got {
		if ev.Name == "SSL_CERT_FILE" && ev.Value == caPath {
			return
		}
	}
	t.Errorf("expected SSL_CERT_FILE in fallback CA vars; got %#v", got)
}
