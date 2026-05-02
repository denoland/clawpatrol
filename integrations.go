package main

// Integrations: secret swaps in proxied bytes/headers, built-in OAuth
// defaults for popular providers (claude/codex/github), the `clawpatrol
// env` shell-shim, and the litellm context-window cache used to label
// agent sessions with their model's max input window.

import (
	"bytes"
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
// without these env vars set, even though our gateway swaps in the real
// OAuth-issued token server-side. The placeholder must match the
// provider's expected format closely enough to pass client-side
// validation — but the bytes never reach the API.
const (
	envClaudePlaceholder = "sk-ant-oat01-clawpatrol-placeholder-token-do-not-use-as-real-key"
	envGitHubPlaceholder = "ghp_clawpatrol_placeholder_token_do_not_use_as_real_key"
	// codex CLI / OpenAI SDKs validate OPENAI_API_KEY starts with `sk-`
	// before sending. The real OAuth bearer is swapped in at MITM time
	// via the codex integration's Authorization header rewrite.
	envCodexPlaceholder = "sk-clawpatrol-placeholder-token-do-not-use-as-real-key"
)

// scanReplaceBytes runs every Swap entry across b in order. Each
// placeholder is searched verbatim and replaced with resolved secret.
func scanReplaceBytes(b []byte, swaps []Swap) []byte {
	for _, s := range swaps {
		if s.Placeholder == "" {
			continue
		}
		b = bytes.ReplaceAll(b, []byte(s.Placeholder), []byte(resolveTemplate(s.Secret)))
	}
	return b
}

// scanReplaceHeaders rewrites every header value that contains a
// placeholder. Multi-value headers handled per-value.
func scanReplaceHeaders(h http.Header, swaps []Swap) {
	if len(swaps) == 0 {
		return
	}
	for k, vals := range h {
		for i, v := range vals {
			for _, s := range swaps {
				if s.Placeholder == "" {
					continue
				}
				if strings.Contains(v, s.Placeholder) {
					v = strings.ReplaceAll(v, s.Placeholder, resolveTemplate(s.Secret))
				}
			}
			vals[i] = v
		}
		h[k] = vals
	}
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

// expandDefaults walks every Profile (resolving `extend` first) and
// folds in:
//   - parent profiles' integrations / rulesets / inline rules
//     (recursively, child wins on host conflicts)
//   - inline `rule {}` blocks declared in the profile
//   - rules from any `ruleset "name"` referenced via `rules = [...]`
//   - auto-derived rules for each named integration's hosts (skipped
//     when the profile already declared a rule for that host)
//
// Validation:
//   - every name in `Approve` must be "dashboard" or a declared Approver.
//   - every name in `RulesetRefs` must resolve to a declared Ruleset.
//   - every `IntegrationNames` entry must be a known built-in.
//   - `extend` chain must not contain cycles.
//
// Every emitted rule is tagged with Profile=<profile-name> so
// selectHostRule can filter by peer→profile mapping.
func expandDefaults(cfg *Config) error {
	if err := validateIntegrations(cfg.Integrations); err != nil {
		return err
	}
	topRules := cfg.TopRules
	cfg.Rules = nil
	haveOAuth := map[string]bool{}
	for _, o := range cfg.OAuth {
		haveOAuth[o.ID] = true
	}
	rulesetByName := map[string][]Rule{}
	for _, rs := range cfg.Rulesets {
		rulesetByName[rs.Name] = rs.Rules
	}
	profileByName := map[string]*Profile{}
	for i := range cfg.Profiles {
		profileByName[cfg.Profiles[i].Name] = &cfg.Profiles[i]
	}
	approverNames := map[string]bool{"dashboard": true}
	for _, a := range cfg.Approvers {
		if a.Name == "dashboard" {
			return fmt.Errorf("approver name %q is reserved (built-in)", a.Name)
		}
		approverNames[a.Name] = true
	}
	validateApprove := func(profile string, r Rule) error {
		for _, n := range r.Approve {
			if !approverNames[n] {
				return fmt.Errorf("profile %q rule for %q: unknown approver %q (declare it via `approver %q { ... }`)",
					profile, r.Host, n, n)
			}
		}
		return nil
	}
	// resolved[name] = the flattened (integrations, ruleset-refs,
	// inline rules) for that profile, parents already merged in.
	type resolved struct {
		integrations []string
		rulesets     []string
		rules        []Rule
	}
	cache := map[string]resolved{}
	visiting := map[string]bool{}
	var resolve func(name string) (resolved, error)
	resolve = func(name string) (resolved, error) {
		if r, ok := cache[name]; ok {
			return r, nil
		}
		if visiting[name] {
			return resolved{}, fmt.Errorf("profile %q: cycle in extend chain", name)
		}
		visiting[name] = true
		defer delete(visiting, name)
		p, ok := profileByName[name]
		if !ok {
			return resolved{}, fmt.Errorf("profile %q: extends unknown profile", name)
		}
		out := resolved{}
		for _, parent := range p.Extends {
			pr, err := resolve(parent)
			if err != nil {
				return resolved{}, err
			}
			out.integrations = append(out.integrations, pr.integrations...)
			out.rulesets = append(out.rulesets, pr.rulesets...)
			out.rules = append(out.rules, pr.rules...)
		}
		out.integrations = append(out.integrations, p.IntegrationNames...)
		out.rulesets = append(out.rulesets, p.RulesetRefs...)
		out.rules = append(out.rules, p.Rules...)
		cache[name] = out
		return out, nil
	}
	for _, p := range cfg.Profiles {
		flat, err := resolve(p.Name)
		if err != nil {
			return err
		}
		// declared tracks hosts that already have a CATCH-ALL rule
		// (Match == nil). Subsequent catch-alls for the same host
		// (e.g. integration-derived auto-rules) are skipped.
		// Rules with a Match are always emitted — they're specific
		// policy and should coexist with other specific rules.
		declared := map[string]bool{}
		emit := func(r Rule) error {
			if r.Device == "" && r.Match == nil && declared[r.Host] {
				return nil
			}
			r.Profile = p.Name
			if err := validateApprove(p.Name, r); err != nil {
				return err
			}
			cfg.Rules = append(cfg.Rules, r)
			if r.Device == "" && r.Match == nil {
				declared[r.Host] = true
			}
			return nil
		}
		// Walk in REVERSE so child contributions (appended last) are
		// emitted first and win the host-declared check above.
		for i := len(flat.rules) - 1; i >= 0; i-- {
			if err := emit(flat.rules[i]); err != nil {
				return err
			}
		}
		for i := len(flat.rulesets) - 1; i >= 0; i-- {
			rs, ok := rulesetByName[flat.rulesets[i]]
			if !ok {
				return fmt.Errorf("profile %q: unknown ruleset %q", p.Name, flat.rulesets[i])
			}
			for j := len(rs) - 1; j >= 0; j-- {
				if err := emit(rs[j]); err != nil {
					return err
				}
			}
		}
		// Integrations: dedupe across the whole extend chain.
		// Built-ins are wired (auto-rules from default hosts).
		// Operator-declared `integration "name" {}` blocks register
		// the name + (optional) host list — auto-rules emit too;
		// secret-injection behavior is per-owner via dashboard
		// (wired in a later pass).
		custom := map[string]Integration{}
		for _, in := range cfg.Integrations {
			custom[in.Name] = in
		}
		seenInt := map[string]bool{}
		for _, name := range flat.integrations {
			if seenInt[name] {
				continue
			}
			seenInt[name] = true
			if def, ok := defaultIntegrations[name]; ok {
				if def.OAuth != nil && !haveOAuth[def.OAuth.ID] {
					cfg.OAuth = append(cfg.OAuth, *def.OAuth)
					haveOAuth[def.OAuth.ID] = true
				}
				// host→integration is recorded on cfg.HostIntegration
				// instead of being expanded into visible Rules. The
				// MITM path consults the map when no user rule matches
				// a host, synthesizing an in-memory Rule with the
				// right Auth field for credential injection.
				for _, host := range def.Hosts {
					if cfg.HostIntegration == nil {
						cfg.HostIntegration = map[string]string{}
					}
					if _, set := cfg.HostIntegration[host]; !set {
						cfg.HostIntegration[host] = name
					}
				}
				continue
			}
			if in, ok := custom[name]; ok {
				for _, host := range in.Hosts {
					if cfg.HostIntegration == nil {
						cfg.HostIntegration = map[string]string{}
					}
					if _, set := cfg.HostIntegration[host]; !set {
						cfg.HostIntegration[host] = name
					}
				}
				continue
			}
			available := append(defaultIntegrationKeys(), customIntegrationKeys(cfg.Integrations)...)
			return fmt.Errorf("profile %q: unknown integration %q (available: %v)",
				p.Name, name, available)
		}
	}
	// Fold profile-less top-level rule blocks into the expanded rules.
	// These are device-scoped overrides + standalone operator rules
	// not bound to any profile. They keep their empty Profile so the
	// writer round-trips them back to top-level on the next save.
	cfg.Rules = append(cfg.Rules, topRules...)
	cfg.TopRules = topRules
	return nil
}

// validateIntegrations checks that every operator-declared integration
// has a known type and that any nested auth / tunnel block names a
// supported subtype. Catches typos at config-load time so a request
// path doesn't silently fall through.
func validateIntegrations(ins []Integration) error {
	allowedType := map[string]bool{
		"oauth": true, "bearer": true, "header": true, "cookie": true,
		"mtls": true, "postgres": true, "clickhouse": true, "kubernetes": true,
	}
	allowedAuth := map[string]bool{"aws-eks-token": true}
	allowedTunnel := map[string]bool{"kubectl-portforward-ssh": true}
	seen := map[string]bool{}
	for _, in := range ins {
		if in.Name == "" {
			return fmt.Errorf("integration: missing name label")
		}
		if seen[in.Name] {
			return fmt.Errorf("integration %q: duplicate declaration", in.Name)
		}
		seen[in.Name] = true
		if !allowedType[in.Type] {
			return fmt.Errorf("integration %q: unknown type %q (allowed: oauth, bearer, header, cookie, mtls, postgres, clickhouse, kubernetes)",
				in.Name, in.Type)
		}
		if in.Auth != nil && !allowedAuth[in.Auth.Type] {
			return fmt.Errorf("integration %q: unknown auth.type %q (allowed: aws-eks-token)", in.Name, in.Auth.Type)
		}
		if in.Tunnel != nil && !allowedTunnel[in.Tunnel.Type] {
			return fmt.Errorf("integration %q: unknown tunnel.type %q (allowed: kubectl-portforward-ssh)", in.Name, in.Tunnel.Type)
		}
		acctNames := map[string]bool{}
		for _, ac := range in.Accounts {
			if acctNames[ac.Name] {
				return fmt.Errorf("integration %q: duplicate account %q", in.Name, ac.Name)
			}
			acctNames[ac.Name] = true
		}
		secretNames := map[string]bool{}
		for _, s := range in.Secrets {
			if secretNames[s.Name] {
				return fmt.Errorf("integration %q: duplicate secret %q", in.Name, s.Name)
			}
			secretNames[s.Name] = true
		}
	}
	return nil
}

func defaultIntegrationKeys() []string {
	out := make([]string, 0, len(defaultIntegrations))
	for k := range defaultIntegrations {
		out = append(out, k)
	}
	return out
}

func customIntegrationKeys(ins []Integration) []string {
	out := make([]string, 0, len(ins))
	for _, in := range ins {
		out = append(out, in.Name)
	}
	return out
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
