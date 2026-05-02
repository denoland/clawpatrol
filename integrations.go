package main

// Built-in OAuth defaults for popular providers (claude / codex /
// github), the `clawpatrol env` shell-shim, and the litellm
// context-window cache used to label agent sessions with their
// model's max input window.

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Placeholder tokens. Agent CLIs (claude, gh, codex) refuse to start
// without these env vars set, even though the gateway swaps in the
// real OAuth-issued token server-side via the credential plugin.
const (
	envClaudePlaceholder = "sk-ant-oat01-clawpatrol-placeholder-token-do-not-use-as-real-key"
	envGitHubPlaceholder = "ghp_clawpatrol_placeholder_token_do_not_use_as_real_key"
	// codex CLI / OpenAI SDKs validate OPENAI_API_KEY starts with `sk-`
	// before sending. The real OAuth bearer is swapped in at MITM time
	// via the codex integration's Authorization header rewrite.
	envCodexPlaceholder = "sk-clawpatrol-placeholder-token-do-not-use-as-real-key"
)

// resolveTemplate expands `{{secret:NAME}}` placeholders in s by
// looking NAME up in the process environment. Used by config-loading
// helpers that pull provider-specific secrets at runtime instead of
// hard-coding them in the file.
func resolveTemplate(s string) string {
	out := s
	for {
		i := strings.Index(out, "{{secret:")
		if i < 0 {
			break
		}
		j := strings.Index(out[i:], "}}")
		if j < 0 {
			break
		}
		name := out[i+9 : i+j]
		val := os.Getenv(name)
		out = out[:i] + val + out[i+j+2:]
	}
	return out
}

// runEnv is the `clawpatrol env` subcommand: prints export lines for
// the agent CLIs, pointing them at our CA bundle and stuffing
// placeholder tokens into the slots they require.
func runEnv(args []string) {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	caDir := fs.String("ca-dir", defaultClawpatrolDir(), "directory containing ca.crt")
	_ = fs.Parse(args)

	caPath := filepath.Join(*caDir, "ca.crt")
	if _, err := os.Stat(caPath); err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol: ca not found at %s — run `clawpatrol login` first\n", caPath)
		os.Exit(2)
	}
	for _, k := range []string{
		"SSL_CERT_FILE",
		"NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE",
		"CURL_CA_BUNDLE",
		"GIT_SSL_CAINFO",
	} {
		fmt.Printf("export %s=%q\n", k, caPath)
	}
	fmt.Printf("export ANTHROPIC_AUTH_TOKEN=%q\n", envClaudePlaceholder)
	fmt.Printf("export GH_TOKEN=%q\n", envGitHubPlaceholder)
	fmt.Printf("export GITHUB_TOKEN=%q\n", envGitHubPlaceholder)
	// codex OPENAI_API_KEY pushes the CLI into api-key mode, which
	// targets api.openai.com — wrong endpoint for ChatGPT OAuth.
	// OAuth-mode codex reads strictly from ~/.codex/auth.json; once
	// `clawpatrol run -- codex` wraps that, we emit it conditionally.
}

// Built-in integration defaults. Operators reference by name in config:
//
//   integrations: [claude, codex, github]
//
// Each entry contributes its OAuth definition (if any) plus rules. User
// can override any field by also defining the same id in config; user
// values win.

// integrationDefault bundles an OAuth definition with the hosts it
// applies to. Auto-MITM happens for any host in `Hosts` whenever the
// integration is named in `integrations = [...]`.
type integrationDefault struct {
	OAuth *OAuthIntegration
	Hosts []string // SNI hosts this integration covers
}

var defaultIntegrations = map[string]integrationDefault{
	"claude": {
		Hosts: []string{"api.anthropic.com"},
		OAuth: &OAuthIntegration{
			ID:     "claude",
			Type:   "oauth2",
			Header: "Authorization",
			Prefix: "Bearer ",
			OAuth: OAuthConfig{
				ClientID:     "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
				AuthURL:      "https://claude.ai/oauth/authorize",
				TokenURL:     "https://console.anthropic.com/v1/oauth/token",
				RedirectURI:  "https://console.anthropic.com/oauth/code/callback",
				Scopes:       []string{"org:create_api_key", "user:profile", "user:inference"},
				RefreshToken: "{{secret:CLAUDE_REFRESH}}",
			},
		},
	},
	"codex": {
		Hosts: []string{"api.openai.com", "chatgpt.com"},
		OAuth: &OAuthIntegration{
			ID:     "codex",
			Type:   "oauth2",
			Header: "Authorization",
			Prefix: "Bearer ",
			OAuth: OAuthConfig{
				ClientID:     "app_EMoamEEZ73f0CkXaXp7hrann",
				AuthURL:      "https://auth.openai.com/oauth/authorize",
				TokenURL:     "https://auth.openai.com/oauth/token",
				RedirectURI:  "http://localhost:1455/auth/callback",
				Scopes:       []string{"openid", "profile", "email", "offline_access"},
				RefreshToken: "{{secret:CODEX_REFRESH}}",
			},
		},
	},
	"github": {
		Hosts: []string{"api.github.com", "raw.githubusercontent.com"},
		OAuth: &OAuthIntegration{
			// gh CLI's published OAuth client_id (no secret needed —
			// device flow is designed for public clients).
			ID:     "github",
			Type:   "oauth2",
			Header: "Authorization",
			Prefix: "Bearer ",
			Flow:   "device",
			OAuth: OAuthConfig{
				ClientID:  "178c6fc778ccc68e1d6a",
				DeviceURL: "https://github.com/login/device/code",
				TokenURL:  "https://github.com/login/oauth/access_token",
				Scopes:    []string{"repo", "read:org", "gist", "workflow"},
			},
		},
	},
}

func defaultOAuthByID(id string) *OAuthIntegration {
	if d, ok := defaultIntegrations[id]; ok {
		return d.OAuth
	}
	return nil
}

func defaultOAuthKeys() []string {
	out := make([]string, 0, len(defaultIntegrations))
	for k := range defaultIntegrations {
		out = append(out, k)
	}
	return out
}

// Model context-window lookup. Sourced from litellm's
// model_prices_and_context_window.json (refreshed at startup, hourly).
// Avoids hardcoding ctx_max per model — litellm tracks all major
// provider models with up-to-date max_input_tokens values.

const litellmModelsURL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"

type modelInfo struct {
	MaxInputTokens flexInt `json:"max_input_tokens"`
}

// flexInt accepts JSON numbers OR numeric strings. The litellm dataset
// is hand-maintained and a handful of entries store max_input_tokens
// as a quoted string instead of a number.
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		var n int64
		if _, err := fmt.Sscan(s, &n); err != nil {
			return nil // leave as 0
		}
		*f = flexInt(n)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return nil
	}
	*f = flexInt(n)
	return nil
}

type modelDB struct {
	mu      sync.RWMutex
	byModel map[string]int64 // model name -> max_input_tokens
}

var models = &modelDB{byModel: map[string]int64{}}

// startModelRefresh kicks off the litellm context-window refresh loop.
// Called from runGateway() — NOT init(), since CLI subcommands
// (login/join/env/auth) don't need the data and shouldn't be hitting
// github on every invocation.
func startModelRefresh() {
	go models.refreshLoop()
}

func (m *modelDB) refreshLoop() {
	for {
		if err := m.fetch(); err != nil {
			log.Printf("models: refresh failed: %v", err)
		}
		time.Sleep(time.Hour)
	}
}

func (m *modelDB) fetch() error {
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Get(litellmModelsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var raw map[string]modelInfo
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	out := map[string]int64{}
	for k, v := range raw {
		if v.MaxInputTokens > 0 {
			out[strings.ToLower(k)] = int64(v.MaxInputTokens)
		}
	}
	m.mu.Lock()
	m.byModel = out
	m.mu.Unlock()
	log.Printf("models: loaded %d entries from litellm", len(out))
	return nil
}

// ctxMax returns the max input-token window for a model name. Tries
// exact match first, then loose substring match against known keys.
// Returns 0 when unknown — callers should not display a percentage.
func (m *modelDB) ctxMax(model string) int64 {
	if model == "" {
		return 0
	}
	key := strings.ToLower(model)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v, ok := m.byModel[key]; ok {
		return v
	}
	// Some providers prefix model name with vendor (e.g. "anthropic/claude-...").
	if i := strings.LastIndex(key, "/"); i >= 0 {
		if v, ok := m.byModel[key[i+1:]]; ok {
			return v
		}
	}
	return 0
}
