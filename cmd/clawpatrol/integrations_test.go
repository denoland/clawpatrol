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
		_ = l.Close()
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
	prev := envPushdownGatewayFetcher
	envPushdownGatewayFetcher = fetchEnvPushdownFromGateway
	t.Cleanup(func() { envPushdownGatewayFetcher = prev })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	// Pin the gateway fetcher to the direct-HTTP path — on darwin the
	// init() in run_tsnet_darwin.go rewires this to the NE session
	// socket, which would dial /tmp/clawpatrol.sock and return whatever
	// the host's running NE happens to have to say, instead of the
	// gateway-URL-missing error this test exercises.
	prev := envPushdownGatewayFetcher
	envPushdownGatewayFetcher = fetchEnvPushdownFromGateway
	t.Cleanup(func() { envPushdownGatewayFetcher = prev })

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

// shimCreds is the decoded shape of the synthesized .credentials.json.
type shimCreds struct {
	ClaudeAiOauth struct {
		AccessToken      string   `json:"accessToken"`
		RefreshToken     string   `json:"refreshToken"`
		ExpiresAt        int64    `json:"expiresAt"`
		Scopes           []string `json:"scopes"`
		SubscriptionType string   `json:"subscriptionType"`
	} `json:"claudeAiOauth"`
}

func readShimCreds(t *testing.T, path string) shimCreds {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var got shimCreds
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal %s: %v\nbody: %s", path, err, raw)
	}
	return got
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// TestInstallClaudeCodeOAuthShim covers the `clawpatrol run claude`
// workaround when the operator has opted in with
// CLAWPATROL_CLAUDE_OAUTH_SHIM=1: with ANTHROPIC_AUTH_TOKEN in the env,
// the wrapped command `claude`, and no operator CLAUDE_CONFIG_DIR, the
// shim must (1) carve out a managed CLAUDE_CONFIG_DIR and point the env
// var at it, (2) write a synthesized credentials.json with
// `user:sessions:claude_code` in the scopes list, and (3) strip
// ANTHROPIC_AUTH_TOKEN so Claude Code's local auth-mode gate falls
// through to subscription OAuth (precedence #6).
func TestInstallClaudeCodeOAuthShim(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-oat01-clawpatrol-placeholder-do-not-use")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CLAWPATROL_CLAUDE_OAUTH_SHIM", "1")

	installClaudeCodeOAuthShim([]string{"/usr/local/bin/claude", "--help"})

	if got := os.Getenv("ANTHROPIC_AUTH_TOKEN"); got != "" {
		t.Errorf("ANTHROPIC_AUTH_TOKEN should be stripped, got %q", got)
	}
	cfgDir := os.Getenv("CLAUDE_CONFIG_DIR")
	if cfgDir == "" {
		t.Fatalf("CLAUDE_CONFIG_DIR should be set")
	}
	path := filepath.Join(cfgDir, ".credentials.json")
	got := readShimCreds(t, path)
	if got.ClaudeAiOauth.AccessToken == "" {
		t.Errorf("accessToken empty")
	}
	if got.ClaudeAiOauth.RefreshToken == "" {
		t.Errorf("refreshToken empty")
	}
	if got.ClaudeAiOauth.ExpiresAt <= 0 {
		t.Errorf("expiresAt should be a large future timestamp, got %d", got.ClaudeAiOauth.ExpiresAt)
	}
	if !hasScope(got.ClaudeAiOauth.Scopes, "user:sessions:claude_code") {
		t.Errorf("scopes missing user:sessions:claude_code: got %v", got.ClaudeAiOauth.Scopes)
	}
	if got.ClaudeAiOauth.SubscriptionType == "" {
		t.Errorf("subscriptionType empty")
	}

	// File mode must be 0600 — credentials.json holds a (placeholder
	// but token-shaped) bearer that we don't want world-readable.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("credentials.json mode = %o, want 0600", mode)
	}
}

// TestInstallClaudeCodeOAuthShim_OperatorConfigDir: when the operator
// has set CLAUDE_CONFIG_DIR (so Claude Code keeps its settings/MCP/state
// there), the shim writes the synthesized credentials INTO that dir
// rather than overriding the env var, and still strips the bearer.
func TestInstallClaudeCodeOAuthShim_OperatorConfigDir(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-oat01-clawpatrol-placeholder-do-not-use")
	t.Setenv("CLAUDE_CONFIG_DIR", cfg)
	t.Setenv("CLAWPATROL_CLAUDE_OAUTH_SHIM", "1")

	installClaudeCodeOAuthShim([]string{"claude"})

	if got := os.Getenv("ANTHROPIC_AUTH_TOKEN"); got != "" {
		t.Errorf("ANTHROPIC_AUTH_TOKEN should be stripped, got %q", got)
	}
	if got := os.Getenv("CLAUDE_CONFIG_DIR"); got != cfg {
		t.Errorf("CLAUDE_CONFIG_DIR should be left as operator's %q, got %q", cfg, got)
	}
	got := readShimCreds(t, filepath.Join(cfg, ".credentials.json"))
	if !hasScope(got.ClaudeAiOauth.Scopes, "user:sessions:claude_code") {
		t.Errorf("scopes missing user:sessions:claude_code: got %v", got.ClaudeAiOauth.Scopes)
	}
}

// TestInstallClaudeCodeOAuthShim_PreservesRealLogin: a real
// .credentials.json already in an operator-set CLAUDE_CONFIG_DIR must
// not be clobbered — dropping ANTHROPIC_AUTH_TOKEN lets that login win
// on its own.
func TestInstallClaudeCodeOAuthShim_PreservesRealLogin(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-oat01-clawpatrol-placeholder-do-not-use")
	t.Setenv("CLAUDE_CONFIG_DIR", cfg)
	t.Setenv("CLAWPATROL_CLAUDE_OAUTH_SHIM", "1")

	credPath := filepath.Join(cfg, ".credentials.json")
	realLogin := []byte(`{"claudeAiOauth":{"accessToken":"real-login-token"}}`)
	if err := os.WriteFile(credPath, realLogin, 0o600); err != nil {
		t.Fatalf("seed real creds: %v", err)
	}

	installClaudeCodeOAuthShim([]string{"claude"})

	if got := os.Getenv("ANTHROPIC_AUTH_TOKEN"); got != "" {
		t.Errorf("ANTHROPIC_AUTH_TOKEN should be stripped, got %q", got)
	}
	raw, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatalf("read creds: %v", err)
	}
	if string(raw) != string(realLogin) {
		t.Errorf("real login was clobbered: got %s", raw)
	}
}

// TestInstallClaudeCodeOAuthShim_NoOpPaths covers every case where the
// shim should leave the environment alone: not opted in (the default),
// empty argv, non-claude binary, ANTHROPIC_AUTH_TOKEN unset.
func TestInstallClaudeCodeOAuthShim_NoOpPaths(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T)
		cmd     []string
		wantEnv string // expected ANTHROPIC_AUTH_TOKEN after the call
	}{
		{
			// Default: no opt-in → print guidance, touch nothing. This
			// is the R&D-decided behavior (don't silently overwrite).
			name: "not_opted_in",
			setup: func(t *testing.T) {
				t.Setenv("CLAWPATROL_CLAUDE_OAUTH_SHIM", "")
				t.Setenv("ANTHROPIC_AUTH_TOKEN", "keep")
			},
			cmd:     []string{"claude"},
			wantEnv: "keep",
		},
		{
			name: "empty_argv",
			setup: func(t *testing.T) {
				t.Setenv("CLAWPATROL_CLAUDE_OAUTH_SHIM", "1")
				t.Setenv("ANTHROPIC_AUTH_TOKEN", "keep")
			},
			cmd:     nil,
			wantEnv: "keep",
		},
		{
			name: "non_claude_binary",
			setup: func(t *testing.T) {
				t.Setenv("CLAWPATROL_CLAUDE_OAUTH_SHIM", "1")
				t.Setenv("ANTHROPIC_AUTH_TOKEN", "keep")
			},
			cmd:     []string{"/usr/bin/python3", "script.py"},
			wantEnv: "keep",
		},
		{
			name: "no_anthropic_token",
			setup: func(t *testing.T) {
				t.Setenv("CLAWPATROL_CLAUDE_OAUTH_SHIM", "1")
				t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
			},
			cmd:     []string{"claude"},
			wantEnv: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("CLAUDE_CONFIG_DIR", "")
			tc.setup(t)
			installClaudeCodeOAuthShim(tc.cmd)
			if got := os.Getenv("ANTHROPIC_AUTH_TOKEN"); got != tc.wantEnv {
				t.Errorf("ANTHROPIC_AUTH_TOKEN: got %q, want %q", got, tc.wantEnv)
			}
			if cfg := os.Getenv("CLAUDE_CONFIG_DIR"); cfg != "" {
				t.Errorf("CLAUDE_CONFIG_DIR should be empty, got %q", cfg)
			}
		})
	}
}
