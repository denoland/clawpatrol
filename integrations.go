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

	"github.com/denoland/clawpatrol/config"
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

// pushdownEnvVar carries one env var contributed by the credential
// plugins' EnvPushdownProvider impls plus the CA-bundle vars. Used
// by both `clawpatrol env` (prints export lines) and `clawpatrol run`
// (sets them on the wrapped child process via os.Setenv).
type pushdownEnvVar struct {
	Name        string
	Value       string
	Description string // shown only by `env`; `run` ignores
	PluginType  string
}

// envPushdownVars returns every var the operator's CLI environment
// needs: CA bundle paths + per-credential placeholder tokens. caPath
// must be the absolute path to ca.crt. Plugin order is registry-
// stable (alphabetical by Type); first writer wins on duplicate
// names so the same env var across two plugins doesn't double up.
func envPushdownVars(caPath string) []pushdownEnvVar {
	var out []pushdownEnvVar
	for _, k := range []string{
		"SSL_CERT_FILE",
		"NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE",
		"CURL_CA_BUNDLE",
		"GIT_SSL_CAINFO",
		"DENO_CERT",
		"PIP_CERT",
	} {
		out = append(out, pushdownEnvVar{Name: k, Value: caPath})
	}
	seen := map[string]bool{}
	// Both credential and endpoint plugins can declare env push-down
	// vars. Credentials cover the bearer-placeholder case
	// (ANTHROPIC_AUTH_TOKEN, GH_TOKEN, ...) — the env var IS the
	// secret slot. Endpoints cover routing-control envs that don't
	// correspond to a single credential
	// (CODEX_ACCESS_TOKEN flips codex into Agent Identity mode and
	// points it at chatgpt.com — a property of the openai_codex_https
	// endpoint, not the underlying bearer credential).
	for _, kind := range []config.Kind{config.KindCredential, config.KindEndpoint} {
		for _, p := range config.AllPlugins(kind) {
			body := p.New()
			provider, ok := body.(config.EnvPushdownProvider)
			if !ok {
				continue
			}
			for _, ev := range provider.EnvVars() {
				if seen[ev.Name] {
					continue
				}
				seen[ev.Name] = true
				out = append(out, pushdownEnvVar{
					Name:        ev.Name,
					Value:       ev.Value,
					Description: ev.Description,
					PluginType:  p.Type,
				})
			}
		}
	}
	return out
}

// runEnv is the `clawpatrol env` subcommand: prints export lines for
// the agent CLIs, pointing them at the CA bundle and stuffing
// placeholder tokens into the slots they require. The gateway
// overwrites the auth slot at MITM time, so the placeholder bytes
// never reach the upstream.
func runEnv(args []string) {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	caDir := fs.String("ca-dir", defaultClawpatrolDir(), "directory containing ca.crt")
	_ = fs.Parse(args)

	caPath := filepath.Join(*caDir, "ca.crt")
	if _, err := os.Stat(caPath); err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol: ca not found at %s — run `clawpatrol login` first\n", caPath)
		os.Exit(2)
	}
	for _, ev := range envPushdownVars(caPath) {
		if ev.Description != "" {
			if ev.PluginType != "" {
				fmt.Printf("# %s — %s\n", ev.Description, ev.PluginType)
			} else {
				fmt.Printf("# %s\n", ev.Description)
			}
		}
		fmt.Printf("export %s=%q\n", ev.Name, ev.Value)
	}
}

// applyEnvPushdown sets every pushdown var on the current process
// environment. Called by `clawpatrol run` before exec'ing the child
// command, so the wrapped agent CLI inherits the placeholders + CA
// paths without the operator having to source `clawpatrol env`
// separately.
//
// Opt-out: setting CLAWPATROL_NO_ENV=1 disables the entire pushdown.
// Use when an agent CLI is incompatible with one of the pushed vars
// (e.g. an OPENAI_API_KEY placeholder that forces a CLI into API
// mode when its native auth would have worked through the tunnel).
func applyEnvPushdown(caDir string) {
	if os.Getenv("CLAWPATROL_NO_ENV") == "1" {
		return
	}
	caPath := filepath.Join(caDir, "ca.crt")
	if _, err := os.Stat(caPath); err != nil {
		// CA not set up yet — `clawpatrol join` hasn't run. Don't
		// silently skip; the agent CLI will fail TLS verification
		// and the operator will be confused. Log and continue.
		fmt.Fprintf(os.Stderr, "clawpatrol: ca not found at %s — env pushdown skipped (run `clawpatrol join` first)\n", caPath)
		return
	}
	for _, ev := range envPushdownVars(caPath) {
		// Don't clobber values the operator already set deliberately.
		if os.Getenv(ev.Name) != "" {
			continue
		}
		_ = os.Setenv(ev.Name, ev.Value)
	}
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
