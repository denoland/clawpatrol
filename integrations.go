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
// needs: CA-bundle vars (which point at a path on the *client's*
// disk so the client owns them) plus the gateway's declared
// push-down list. caPath must be the absolute path to ca.crt.
//
// The placeholder tokens come from the gateway's /api/env-pushdown
// endpoint — the gateway is the only source of truth for which
// plugins the operator has actually configured. Returns CA vars
// only with an error when the gateway URL hasn't been persisted
// (no `clawpatrol join` yet) or the gateway is unreachable;
// callers surface the error so the operator knows their agents
// won't get the placeholder tokens.
func envPushdownVars(caPath string) ([]pushdownEnvVar, error) {
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
	vars, err := fetchEnvPushdownFromGateway(filepath.Dir(caPath))
	if err != nil {
		return out, err
	}
	return append(out, vars...), nil
}

// fetchEnvPushdownFromGateway hits the gateway's /api/env-pushdown
// endpoint and returns its declared push-down vars. Authenticated
// with the per-peer bearer `clawpatrol join` persisted at
// <caDir>/api-token. Errors when the gateway URL or token isn't
// persisted, the network call fails, or the server returned
// non-200.
func fetchEnvPushdownFromGateway(caDir string) ([]pushdownEnvVar, error) {
	gw := readGatewayURL(caDir)
	if gw == "" {
		return nil, fmt.Errorf("gateway URL not persisted (run `clawpatrol join` first)")
	}
	token := readPeerAPIToken(caDir)
	if token == "" {
		return nil, fmt.Errorf("peer api token not persisted (run `clawpatrol join` first)")
	}
	url := strings.TrimRight(gw, "/") + "/api/env-pushdown"
	cli := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build %s: %w", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	var body struct {
		Vars []struct {
			Name        string `json:"name"`
			Value       string `json:"value"`
			Description string `json:"description"`
			PluginType  string `json:"plugin_type"`
		} `json:"vars"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}
	out := make([]pushdownEnvVar, 0, len(body.Vars))
	for _, v := range body.Vars {
		if v.Name == "" {
			continue
		}
		out = append(out, pushdownEnvVar{
			Name:        v.Name,
			Value:       v.Value,
			Description: v.Description,
			PluginType:  v.PluginType,
		})
	}
	return out, nil
}

// readGatewayURL returns the dashboard URL `clawpatrol join`
// persisted next to the CA bundle. Empty when the file is missing
// or unreadable.
func readGatewayURL(caDir string) string {
	b, err := os.ReadFile(filepath.Join(caDir, "gateway"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readPeerAPIToken returns the per-peer bearer minted at onboard
// time, persisted at <caDir>/api-token by `clawpatrol join`.
// Empty when the file is missing.
func readPeerAPIToken(caDir string) string {
	b, err := os.ReadFile(filepath.Join(caDir, "api-token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
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
	vars, err := envPushdownVars(caPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol: %v\n", err)
	}
	for _, ev := range vars {
		if ev.Description != "" {
			if ev.PluginType != "" {
				fmt.Printf("# %s — %s\n", ev.Description, ev.PluginType)
			} else {
				fmt.Printf("# %s\n", ev.Description)
			}
		}
		fmt.Printf("export %s=%q\n", ev.Name, ev.Value)
	}
	if err != nil {
		os.Exit(1)
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
	vars, err := envPushdownVars(caPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol: %v — agent will run without placeholder push-down\n", err)
	}
	for _, ev := range vars {
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
