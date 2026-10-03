//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envVal returns the (last-wins) value of key in a NAME=VALUE slice, and
// whether it was present at all.
func envVal(env []string, key string) (string, bool) {
	pre := key + "="
	val, ok := "", false
	for _, kv := range env {
		if strings.HasPrefix(kv, pre) {
			val, ok = kv[len(pre):], true
		}
	}
	return val, ok
}

// TestApplyClaudeCodeOAuthShimSudo is the regression test for cl-ulck:
// on the passwordless-sudo run path the OAuth shim must fire against the
// privileged child's built env (where the gateway pushdown has injected
// ANTHROPIC_AUTH_TOKEN), strip the bearer, point CLAUDE_CONFIG_DIR at a
// managed dir under the *child's* HOME, and write a synthesized
// credentials.json the dropped-to-user command can read.
func TestApplyClaudeCodeOAuthShimSudo(t *testing.T) {
	home := t.TempDir()
	// The managed dir is carved out of $HOME/.clawpatrol, which already
	// exists on a joined host (ca.crt lives there).
	if err := os.MkdirAll(filepath.Join(home, ".clawpatrol"), 0o700); err != nil {
		t.Fatalf("seed .clawpatrol: %v", err)
	}
	env := []string{
		"HOME=" + home,
		"PATH=/usr/bin",
		"ANTHROPIC_AUTH_TOKEN=sk-ant-oat01-clawpatrol-placeholder-do-not-use",
		"CLAWPATROL_CLAUDE_OAUTH_SHIM=1",
	}

	got := applyClaudeCodeOAuthShimSudo(env, []string{"claude"}, os.Getuid(), os.Getgid())

	if _, ok := envVal(got, "ANTHROPIC_AUTH_TOKEN"); ok {
		t.Errorf("ANTHROPIC_AUTH_TOKEN should be stripped from child env, got %v", got)
	}
	cfgDir, ok := envVal(got, "CLAUDE_CONFIG_DIR")
	if !ok {
		t.Fatalf("CLAUDE_CONFIG_DIR should be set, got %v", got)
	}
	wantDir := filepath.Join(home, ".clawpatrol", "claude-config")
	if cfgDir != wantDir {
		t.Errorf("CLAUDE_CONFIG_DIR = %q, want %q", cfgDir, wantDir)
	}
	// Unrelated vars survive.
	if v, _ := envVal(got, "PATH"); v != "/usr/bin" {
		t.Errorf("PATH not preserved: %q", v)
	}

	path := filepath.Join(cfgDir, ".credentials.json")
	creds := readShimCreds(t, path)
	if !hasScope(creds.ClaudeAiOauth.Scopes, "user:sessions:claude_code") {
		t.Errorf("scopes missing user:sessions:claude_code: %v", creds.ClaudeAiOauth.Scopes)
	}
	if creds.ClaudeAiOauth.AccessToken == "" {
		t.Errorf("accessToken empty")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("credentials.json mode = %o, want 0600", mode)
	}
}

// TestApplyClaudeCodeOAuthShimSudo_NotOptedIn: without the opt-in, the
// child env is returned untouched (bearer kept, no managed dir, no file)
// — default behavior must be unchanged.
func TestApplyClaudeCodeOAuthShimSudo_NotOptedIn(t *testing.T) {
	home := t.TempDir()
	env := []string{
		"HOME=" + home,
		"ANTHROPIC_AUTH_TOKEN=sk-ant-oat01-clawpatrol-placeholder-do-not-use",
	}

	got := applyClaudeCodeOAuthShimSudo(env, []string{"claude"}, os.Getuid(), os.Getgid())

	if v, ok := envVal(got, "ANTHROPIC_AUTH_TOKEN"); !ok || v == "" {
		t.Errorf("ANTHROPIC_AUTH_TOKEN should be kept when not opted in, got %v", got)
	}
	if _, ok := envVal(got, "CLAUDE_CONFIG_DIR"); ok {
		t.Errorf("CLAUDE_CONFIG_DIR should not be set when not opted in")
	}
	if _, err := os.Stat(filepath.Join(home, ".clawpatrol", "claude-config", ".credentials.json")); err == nil {
		t.Errorf("credentials.json should not be written when not opted in")
	}
}

// TestApplyClaudeCodeOAuthShimSudo_OperatorConfigDir: when the operator
// set CLAUDE_CONFIG_DIR, the shim writes the synthesized credentials INTO
// that dir and leaves the env var pointing at it (rather than carving out
// a managed dir), still stripping the bearer.
func TestApplyClaudeCodeOAuthShimSudo_OperatorConfigDir(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	env := []string{
		"HOME=" + home,
		"ANTHROPIC_AUTH_TOKEN=sk-ant-oat01-clawpatrol-placeholder-do-not-use",
		"CLAWPATROL_CLAUDE_OAUTH_SHIM=1",
		"CLAUDE_CONFIG_DIR=" + cfg,
	}

	got := applyClaudeCodeOAuthShimSudo(env, []string{"claude"}, os.Getuid(), os.Getgid())

	if _, ok := envVal(got, "ANTHROPIC_AUTH_TOKEN"); ok {
		t.Errorf("ANTHROPIC_AUTH_TOKEN should be stripped, got %v", got)
	}
	if v, _ := envVal(got, "CLAUDE_CONFIG_DIR"); v != cfg {
		t.Errorf("CLAUDE_CONFIG_DIR = %q, want operator's %q", v, cfg)
	}
	creds := readShimCreds(t, filepath.Join(cfg, ".credentials.json"))
	if !hasScope(creds.ClaudeAiOauth.Scopes, "user:sessions:claude_code") {
		t.Errorf("scopes missing user:sessions:claude_code: %v", creds.ClaudeAiOauth.Scopes)
	}
}
