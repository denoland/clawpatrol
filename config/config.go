package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// Gateway is the fully-loaded clawpatrol gateway config: every
// singleton attribute at the top, plus a resolved policy.
//
// All scalar gateway settings — listen addresses, paths, control-plane
// joining, WireGuard endpoint, and policy defaults — are top-level
// attributes. Labeled blocks (`credential "x" "y" {}`, etc.) are the
// things you have N of and dispatch to the plugin registry.
type Gateway struct {
	Listen     string `hcl:"listen,optional"`
	InfoListen string `hcl:"info_listen,optional"`
	PublicURL  string `hcl:"public_url,optional"`
	AdminEmail string `hcl:"admin_email,optional"`
	// StateDir is the directory holding clawpatrol.db (and anything
	// else a plugin persists to disk under it). Defaults to
	// ${HOME}/.clawpatrol when unset.
	StateDir        string `hcl:"state_dir,optional"`
	Resolver        string `hcl:"resolver,optional"`
	LogPath         string `hcl:"log_path,optional"`
	DashboardSecret string `hcl:"dashboard_secret,optional"`
	// InsecureNoDashboardSecret opts out of dashboard auth. Required
	// (alongside an empty DashboardSecret) for the gateway to serve
	// the dashboard at all — otherwise the secret gate replies with a
	// misconfiguration page on every request. Verbose by design so
	// you can't disable auth by accident.
	InsecureNoDashboardSecret bool `hcl:"insecure_no_dashboard_secret,optional"`

	// Telemetry opts in/out of the update-checker / anonymous usage
	// ping (doc/telemetry.md). nil = default on; explicit `telemetry
	// = false` silences the goroutine. Env vars CLAWPATROL_TELEMETRY=0
	// and DO_NOT_TRACK=1 also work.
	Telemetry *bool `hcl:"telemetry,optional"`

	// SessionKeep is the hard retention floor for the sessions table.
	// Sessions whose last_at is older than this get deleted by the
	// background sweeper. Sessions can revive on new activity at any
	// time, so there's no "closed but kept" intermediate state — only
	// last_at matters. Default 720h (30d), "0" / "off" disables.
	// Format accepts time.ParseDuration strings ("30m", "168h", etc.).
	SessionKeep string `hcl:"session_keep,optional"`

	AuthKey           string `hcl:"authkey,optional"`
	ControlURL        string `hcl:"control_url,optional"`
	Hostname          string `hcl:"hostname,optional"`
	Control           string `hcl:"control,optional"`
	OAuthClientID     string `hcl:"oauth_client_id,optional"`
	OAuthClientSecret string `hcl:"oauth_client_secret,optional"`
	// TailscaleTags is the Tailscale device-tag list applied to keys
	// the gateway mints for onboarded clients (`tag:client` etc.).
	// Tailscale-only — ignored in WireGuard mode.
	TailscaleTags []string `hcl:"tailscale_tags,optional"`
	WGInterface   string   `hcl:"wg_interface,optional"`
	WGEndpoint    string   `hcl:"wg_endpoint,optional"`
	WGServerPub   string   `hcl:"wg_server_pub,optional"`
	WGSubnetCIDR  string   `hcl:"wg_subnet_cidr,optional"`

	UnknownHost    string `hcl:"unknown_host,optional"`
	LLMFailMode    string `hcl:"llm_fail_mode,optional"`
	LLMCacheTTL    int    `hcl:"llm_cache_ttl,optional"`
	HumanTimeout   int    `hcl:"human_timeout,optional"`
	HumanOnTimeout string `hcl:"human_on_timeout,optional"`

	// Plugins lists every `plugin "<name>" { source = "..." }` block
	// at the top of the file. The loader spawns each subprocess
	// (and registers its declared types) before running pass-1
	// symbol building, so plugin-supplied (kind, type) pairs are
	// available by the time policy blocks are dispatched.
	Plugins []PluginSource `hcl:"plugin,block"`

	// Policy holds the v14-grammar block contents. Populated after
	// the operational decode by Load's pass-1 / pass-2 walk. Set to
	// a non-nil empty value if the file declared no policy blocks.
	Policy *Policy `hcl:"-"`

	// Remain is the part of the file gohcl didn't consume — i.e.
	// every policy block. Pass-2 reads from this. Not exposed in
	// the public API but kept on the struct so gohcl knows to
	// preserve it.
	Remain hcl.Body `hcl:",remain"`
}

// JoinConfig is a parameter bundle of the join/transport-related
// Gateway fields. Not an HCL block — the fields live flat on Gateway.
// This struct exists purely so functions like StartWGServer /
// newOnboarder can take one argument instead of twelve.
type JoinConfig struct {
	AuthKey           string
	ControlURL        string
	Hostname          string
	StateDir          string
	Control           string
	OAuthClientID     string
	OAuthClientSecret string
	TailscaleTags     []string
	WGInterface       string
	WGEndpoint        string
	WGServerPub       string
	WGSubnetCIDR      string
	// PublicURL is the operator-facing gateway URL. The WG onboarder
	// uses its host as the default client dial target when
	// WGEndpoint's host portion is wildcard / unset.
	PublicURL string
}

// Join returns the join-related fields as a JoinConfig value bundle.
// Cheap to call — it's a small struct copy.
func (g *Gateway) Join() JoinConfig {
	return JoinConfig{
		AuthKey:           g.AuthKey,
		ControlURL:        g.ControlURL,
		Hostname:          g.Hostname,
		StateDir:          g.StateDir,
		Control:           g.Control,
		OAuthClientID:     g.OAuthClientID,
		OAuthClientSecret: g.OAuthClientSecret,
		TailscaleTags:     g.TailscaleTags,
		WGInterface:       g.WGInterface,
		WGEndpoint:        g.WGEndpoint,
		WGServerPub:       g.WGServerPub,
		WGSubnetCIDR:      g.WGSubnetCIDR,
		PublicURL:         g.PublicURL,
	}
}

// Policy is the resolved set of named policy entities. Maps are keyed
// by entity name (the second label of two-label kinds, the only label
// of one-label kinds). Insertion order is preserved in the parallel
// slices for deterministic emit / dump output.
type Policy struct {
	Approvers   map[string]*Entity
	Credentials map[string]*Entity
	Endpoints   map[string]*Entity
	Rules       map[string]*Entity
	Tunnels     map[string]*Entity

	Policies map[string]*PolicyText
	Profiles map[string]*Profile

	// Order preserves declaration order across all kinds combined.
	// Useful for dashboard rendering and emit round-tripping.
	Order []string
}

// Entity is a successfully-loaded named entity for one of the
// plugin-dispatched kinds. The Body field is whatever the plugin's
// Build returned — the canonical record the runtime reads.
type Entity struct {
	Symbol *Symbol
	Plugin *Plugin
	Body   any
	Refs   *Refs
	// Framework holds the resolved values of framework-level attrs
	// (the FrameworkAttrSpec entries declared for this kind). The
	// loader extracts these from the block body via
	// body.PartialContent before invoking the plugin's gohcl
	// decode, so plugin authors get cross-cutting features
	// (`tunnel = X` on every endpoint) without per-plugin schema
	// boilerplate.
	Framework FrameworkAttrs
}

// FrameworkAttrs is the per-Entity bag of framework-level attr
// values. Keyed by FrameworkAttrSpec.Name; values are the resolved
// bare-name references for ref-typed attrs.
type FrameworkAttrs struct {
	Refs map[string]string
}

// Ref returns the resolved reference for the named framework attr,
// or "" if unset.
func (f FrameworkAttrs) Ref(name string) string {
	if f.Refs == nil {
		return ""
	}
	return f.Refs[name]
}

// PolicyText defines a named, reusable chunk of policy prose that
// `llm_approver` blocks reference by name. The single `text` attribute
// is typically a heredoc.
type PolicyText struct {
	Name string
	Text string `hcl:"text"`
}

// PluginSource is a top-level `plugin "<name>" { source = "..." }`
// declaration. Name is informational (the manifest name from the
// subprocess wins for type namespacing); Source is a path to the
// plugin binary. v1 only supports literal local paths; future
// versions will add git-based fetching with a lockfile.
type PluginSource struct {
	Name   string `hcl:"name,label"`
	Source string `hcl:"source"`
}

// PluginLoader is the gateway-side hook the loader calls before
// policy decoding. It spawns each declared plugin subprocess and
// registers the manifest types in the global plugin registry.
// Returning hcl.Diagnostics with errors aborts the load.
//
// Implemented by *extplugin.Manager — the package-cycle-safe seam
// (config can't import extplugin since extplugin imports config).
type PluginLoader interface {
	LoadPlugins(specs []PluginSource) hcl.Diagnostics
}

// pluginLoader is the package-global hook every Load call uses.
// main.go installs the real *extplugin.Manager via SetPluginLoader
// at startup; the default is a no-op that quietly accepts configs
// with no `plugin {}` blocks. Tests that exercise plugin loading
// install their own loader the same way.
var pluginLoader PluginLoader = noopPluginLoader{}

// SetPluginLoader installs the loader used by every subsequent Load
// / LoadBytes call. Pass nil to revert to the default no-op.
func SetPluginLoader(p PluginLoader) {
	if p == nil {
		pluginLoader = noopPluginLoader{}
		return
	}
	pluginLoader = p
}

// noopPluginLoader is the zero-cost default. Configs without
// `plugin {}` blocks load identically against it; configs with
// such blocks pass them through without spawning anything, which
// then surfaces as an "unknown endpoint type" diagnostic for the
// referencing endpoint blocks.
type noopPluginLoader struct{}

func (noopPluginLoader) LoadPlugins([]PluginSource) hcl.Diagnostics { return nil }

// Profile is the lowered shape of a profile "<name>" {} block. Name
// is the block's single label (set by the loader). Endpoints is the
// only body attribute; rules ride along automatically because they're
// attached to endpoints.
type Profile struct {
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints"`
}

// profileBody is the gohcl decode target for the profile body — the
// label is read separately from the block.
type profileBody struct {
	Endpoints []string `hcl:"endpoints"`
}

// Load parses, validates, and resolves the gateway config at path.
// Returns a populated *Gateway plus any diagnostics. Callers should
// check diagnostics first — a non-nil Gateway can still carry errors
// (some recovery is best-effort).
//
// Plugin loading goes through the package-global PluginLoader
// installed via SetPluginLoader. main.go installs the real
// *extplugin.Manager once at startup; the default is a no-op so
// non-plugin configs and tests need no setup.
func Load(path string) (*Gateway, hcl.Diagnostics) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Cannot read config file",
			Detail:   err.Error(),
		}}
	}
	return LoadBytes(src, path)
}

// LoadBytes is Load over an in-memory buffer. Used by tests so
// fixtures don't need to round-trip through the filesystem.
func LoadBytes(src []byte, filename string) (*Gateway, hcl.Diagnostics) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, diags
	}

	// Decode operational fields. Policy blocks land in gw.Remain.
	gw := &Gateway{}
	if d := gohcl.DecodeBody(file.Body, nil, gw); d.HasErrors() {
		// Don't bail — gohcl is strict about unknown fields; we
		// downgrade unknown-attribute errors at the file root only
		// after pass-1 has had a chance to catch them as policy
		// blocks. For now, append and continue.
		diags = append(diags, d...)
	}

	gw.Policy = &Policy{
		Approvers:   make(map[string]*Entity),
		Credentials: make(map[string]*Entity),
		Endpoints:   make(map[string]*Entity),
		Rules:       make(map[string]*Entity),
		Tunnels:     make(map[string]*Entity),
		Policies:    make(map[string]*PolicyText),
		Profiles:    make(map[string]*Profile),
	}

	// Spawn external plugins before we look at policy blocks so the
	// types they declare are visible to pass-1 symbol building. The
	// loader is package-global; see SetPluginLoader.
	if len(gw.Plugins) > 0 {
		d := pluginLoader.LoadPlugins(gw.Plugins)
		if d.HasErrors() {
			return gw, append(diags, d...)
		}
		diags = append(diags, d...)
	}

	diags = append(diags, validateOperational(gw)...)

	// Pass 1: extract the policy blocks from the remainder body.
	policyBlocks, polDiags := extractPolicyBlocks(gw.Remain)
	diags = append(diags, polDiags...)

	table, symDiags := buildSymbols(policyBlocks)
	diags = append(diags, symDiags...)

	// Pass 2: build the eval context with every name → string, then
	// decode each policy block against its plugin's schema.
	evalCtx := buildEvalContext(table)
	configDir := filepath.Dir(filename)
	resolveDiags := decodePolicyBlocks(gw.Policy, table, evalCtx, configDir)
	diags = append(diags, resolveDiags...)

	// Post-decode pass: substitute `<<file:NAME>>` markers in plugin
	// body fields that opted in via FileIncludable. Runs after Build
	// so plugins see fully-populated Bodies; the raw markers reach
	// dump / golden-test output as a side effect, which is fine —
	// goldens compare structural shape, not file contents.
	includeDiags := expandFileIncludes(gw.Policy, configDir)
	diags = append(diags, includeDiags...)

	return gw, diags
}

// dedupGohclDiags filters out gohcl's "Unsuitable value type — value
// must be known" follow-up that always pairs with an "Unknown
// variable" error at the same source location. The follow-up is a
// gohcl artifact (it's the cty conversion failing to coerce the
// unknown sentinel), and surfacing both produces noise the user
// can't act on. Dropping it leaves the precise "Unknown variable"
// pointer at the typo site.
func dedupGohclDiags(in hcl.Diagnostics) hcl.Diagnostics {
	if len(in) == 0 {
		return in
	}
	unknownAt := map[string]bool{}
	for _, d := range in {
		if d.Summary == "Unknown variable" && d.Subject != nil {
			unknownAt[d.Subject.String()] = true
		}
	}
	if len(unknownAt) == 0 {
		return in
	}
	var out hcl.Diagnostics
	for _, d := range in {
		if d.Summary == "Unsuitable value type" && d.Subject != nil && unknownAt[d.Subject.String()] {
			continue
		}
		out = append(out, d)
	}
	return out
}

// validateOperational checks cross-field consistency on the operational
// fields that gohcl can't express in a struct tag. Catches the typical
// shapes that boot a gateway in a degraded state (silent fallback to
// plain TCP, missing WireGuard endpoint, dashboard-with-no-auth).
func validateOperational(gw *Gateway) hcl.Diagnostics {
	var diags hcl.Diagnostics

	switch strings.ToLower(gw.Control) {
	case "", "wireguard", "tailscale":
		// ok
	default:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid control value",
			Detail: fmt.Sprintf(
				"control = %q. Expected \"wireguard\", \"tailscale\", or omitted.",
				gw.Control),
		})
	}

	if strings.EqualFold(gw.Control, "wireguard") {
		if gw.WGSubnetCIDR == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Missing wg_subnet_cidr",
				Detail:   "control = \"wireguard\" requires wg_subnet_cidr (e.g. \"10.55.0.0/24\").",
			})
		}
		// Clients dial host(public_url):port(wg_endpoint). Need a host
		// from somewhere. wg_endpoint with a non-wildcard host is the
		// escape hatch when public_url isn't reachable from clients
		// (split-host deployments).
		if !hasWGDialTarget(gw.PublicURL, gw.WGEndpoint) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "WireGuard client dial target not configured",
				Detail:   "set public_url, or set wg_endpoint to a non-wildcard host:port (e.g. \"gw.example.com:51820\") — onboarded clients need one of these to know where to dial.",
			})
		}
	}

	if gw.InfoListen != "" && gw.DashboardSecret == "" && !gw.InsecureNoDashboardSecret {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Dashboard auth not configured",
			Detail:   "info_listen is set but the dashboard has no auth: set dashboard_secret = \"<long random string>\", or set insecure_no_dashboard_secret = true to explicitly opt out.",
		})
	}

	return diags
}

// hasWGDialTarget reports whether the config provides a host clients
// can dial for WireGuard. Either public_url is set (we use its host),
// or wg_endpoint pins a non-wildcard host (the split-host escape
// hatch).
func hasWGDialTarget(publicURL, wgEndpoint string) bool {
	if publicURL != "" {
		return true
	}
	if wgEndpoint == "" {
		return false
	}
	h, _, err := net.SplitHostPort(wgEndpoint)
	if err != nil {
		return false
	}
	return h != "" && h != "0.0.0.0" && h != "::"
}

// extractPolicyBlocks pulls every recognized top-level block out of
// the remainder body returned by the operational gohcl decode.
// Uses Content (not PartialContent) so unknown block types — left over
// from a stale config file the new loader doesn't know about — surface
// as diagnostics instead of getting silently dropped. (Past incident:
// PR #225 renamed `gateway {}` to top-level fields; a brief deploy
// ordering meant the new binary booted against an old config and
// silently ran without a WireGuard endpoint.)
func extractPolicyBlocks(body hcl.Body) (hcl.Blocks, hcl.Diagnostics) {
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "approver", LabelNames: []string{"type", "name"}},
			{Type: "credential", LabelNames: []string{"type", "name"}},
			{Type: "endpoint", LabelNames: []string{"type", "name"}},
			{Type: "rule", LabelNames: []string{"name"}},
			{Type: "policy", LabelNames: []string{"name"}},
			{Type: "profile", LabelNames: []string{"name"}},
			{Type: "tunnel", LabelNames: []string{"type", "name"}},
		},
	}
	content, diags := body.Content(schema)
	if content == nil {
		return nil, diags
	}
	return content.Blocks, diags
}

// builtinApproverNames are approvers the gateway provides without
// requiring an HCL declaration. They resolve as bare names anywhere
// an approver reference is allowed.
var builtinApproverNames = []string{"dashboard"}

// buildEvalContext installs every declared name as a string variable
// in an hcl.EvalContext. Bare-name references in HCL expressions
// (`endpoint = github-avocet`) then evaluate to the string "github-
// avocet"; the kind / family check happens after decode.
//
// Built-in approver names (currently just `dashboard`) are added so
// `approve = [dashboard]` resolves without a matching approver block.
func buildEvalContext(table *SymbolTable) *hcl.EvalContext {
	vars := make(map[string]cty.Value, len(table.allNames)+len(builtinApproverNames))
	for name := range table.allNames {
		vars[name] = cty.StringVal(name)
	}
	for _, name := range builtinApproverNames {
		vars[name] = cty.StringVal(name)
	}
	return &hcl.EvalContext{Variables: vars}
}

// decodePolicyBlocks runs pass 2: per-block plugin dispatch + decode +
// ref resolution + Validate + Build, plus the fixed-schema policy /
// profile decoders.
func decodePolicyBlocks(p *Policy, table *SymbolTable, evalCtx *hcl.EvalContext, configDir string) hcl.Diagnostics {
	var diags hcl.Diagnostics

	for _, sym := range table.byKind[KindPolicy] {
		pt := &PolicyText{Name: sym.Name}
		if d := gohcl.DecodeBody(sym.Block.Body, evalCtx, pt); d.HasErrors() {
			diags = append(diags, d...)
		}
		p.Policies[sym.Name] = pt
		p.Order = append(p.Order, sym.Name)
	}

	for _, sym := range table.byKind[KindProfile] {
		var body profileBody
		if d := gohcl.DecodeBody(sym.Block.Body, evalCtx, &body); d.HasErrors() {
			diags = append(diags, d...)
		}
		pr := &Profile{Name: sym.Name, Endpoints: body.Endpoints}
		// Cross-check: each endpoint name resolves to an endpoint.
		for _, ep := range pr.Endpoints {
			if table.Get(KindEndpoint, ep) != nil {
				continue
			}
			if alt := table.GetAny(ep); alt != nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Wrong reference kind in profile %q", sym.Name),
					Detail:   fmt.Sprintf("%q is a %s, but profile.endpoints expects an endpoint.", ep, alt.Kind),
					Subject:  &sym.Block.DefRange,
				})
			} else {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Unknown endpoint %q", ep),
					Detail:   fmt.Sprintf("Profile %q references endpoint %q which is not declared.", sym.Name, ep),
					Subject:  &sym.Block.DefRange,
				})
			}
		}
		p.Profiles[sym.Name] = pr
		p.Order = append(p.Order, sym.Name)
	}

	// Decode order: credentials and tunnels first (no cross-deps on
	// other kinds), then endpoints (which reference both), then rules
	// (which reference endpoints), then approvers (referenced by
	// rules but with no body-level dep on them at decode time).
	// Symbol-table-backed ref resolution doesn't actually require this
	// ordering — symbols are populated in pass 1 — but matching decode
	// order to compile order keeps Order[] stable across the file's
	// declaration sequence and avoids surprising readers.
	for _, kind := range []Kind{KindApprover, KindCredential, KindTunnel, KindEndpoint, KindRule} {
		for _, sym := range table.byKind[kind] {
			plugin := Lookup(sym.Kind, sym.Type)
			if plugin == nil {
				// Already reported in pass 1.
				continue
			}
			// Peel off framework-level attrs (e.g. `tunnel = X` on
			// endpoints) before gohcl sees the body. The plugin's
			// schema doesn't need to know about them; the loader
			// resolves the refs against the symbol table here.
			fw, body, fwDiags := extractFramework(sym.Block.Body, kind, evalCtx, table)
			diags = append(diags, fwDiags...)
			target := plugin.New()
			var decodeDiags hcl.Diagnostics
			if plugin.DecodeBody != nil {
				decodeDiags = plugin.DecodeBody(body, evalCtx, target)
			} else {
				decodeDiags = dedupGohclDiags(gohcl.DecodeBody(body, evalCtx, target))
			}
			diags = append(diags, decodeDiags...)
			// When decode errors, the struct may be partially populated
			// and feeding it through Validate / Build typically produces
			// cascading "missing required" / "unknown reference" noise
			// pointing at fields gohcl already complained about. Skip
			// the plugin-level passes — the user has actionable errors
			// at the precise expression range from gohcl itself.
			if decodeDiags.HasErrors() {
				continue
			}
			refs, refDiags := resolveRefs(target, sym.Name, plugin, table, sym.Block.DefRange)
			diags = append(diags, refDiags...)
			ctx := &BuildCtx{Refs: refs, Symbols: table, Block: sym.Block}
			if plugin.Validate != nil {
				diags = append(diags, plugin.Validate(target, sym.Name, ctx)...)
			}
			built, buildDiags := plugin.Build(target, sym.Name, ctx)
			diags = append(diags, buildDiags...)
			ent := &Entity{
				Symbol:    sym,
				Plugin:    plugin,
				Body:      built,
				Refs:      refs,
				Framework: fw,
			}
			switch kind {
			case KindApprover:
				p.Approvers[sym.Name] = ent
			case KindCredential:
				p.Credentials[sym.Name] = ent
			case KindTunnel:
				p.Tunnels[sym.Name] = ent
			case KindEndpoint:
				p.Endpoints[sym.Name] = ent
			case KindRule:
				p.Rules[sym.Name] = ent
			}
			p.Order = append(p.Order, sym.Name)
		}
	}

	_ = configDir // file-include resolution will use this in a follow-up
	return diags
}
