package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// Gateway is the fully-loaded clawpatrol gateway config: operational
// fields at the top, plus a resolved policy.
//
// Operational fields are still decoded via plain gohcl struct tags —
// they're not pluggable. Anything below `tailscale {}` is dispatched
// to the plugin registry.
type Gateway struct {
	Listen          string `hcl:"listen,optional"`
	InfoListen      string `hcl:"info_listen,optional"`
	PublicURL       string `hcl:"public_url,optional"`
	AdminEmail      string `hcl:"admin_email,optional"`
	CADir           string `hcl:"ca_dir,optional"`
	Resolver        string `hcl:"resolver,optional"`
	LogPath         string `hcl:"log_path,optional"`
	OAuthDir        string `hcl:"oauth_dir,optional"`
	DashboardSecret string `hcl:"dashboard_secret,optional"`

	Tailscale *Tailscale `hcl:"tailscale,block"`

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

// Tailscale mirrors main.go's existing block layout. Kept here so
// config.Gateway is self-contained; the operational runtime can read
// from this type after Load.
type Tailscale struct {
	AuthKey           string   `hcl:"authkey,optional"`
	ControlURL        string   `hcl:"control_url,optional"`
	Hostname          string   `hcl:"hostname,optional"`
	StateDir          string   `hcl:"state_dir,optional"`
	Control           string   `hcl:"control,optional"`
	OAuthClientID     string   `hcl:"oauth_client_id,optional"`
	OAuthClientSecret string   `hcl:"oauth_client_secret,optional"`
	Tags              []string `hcl:"tags,optional"`
	WGInterface       string   `hcl:"wg_interface,optional"`
	WGEndpoint        string   `hcl:"wg_endpoint,optional"`
	WGServerPub       string   `hcl:"wg_server_pub,optional"`
	WGSubnetCIDR      string   `hcl:"wg_subnet_cidr,optional"`
}

// Policy is the resolved set of named policy entities. Maps are keyed
// by entity name (the second label of two-label kinds, the only label
// of one-label kinds). Insertion order is preserved in the parallel
// slices for deterministic emit / dump output.
type Policy struct {
	Defaults Defaults

	Approvers   map[string]*Entity
	Credentials map[string]*Entity
	Endpoints   map[string]*Entity
	Rules       map[string]*Entity

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
}

// Defaults captures the singleton defaults {} block.
type Defaults struct {
	UnknownHost    string `hcl:"unknown_host,optional"`
	LLMFailMode    string `hcl:"llm_fail_mode,optional"`
	LLMCacheTTL    int    `hcl:"llm_cache_ttl,optional"`
	HumanTimeout   int    `hcl:"human_timeout,optional"`
	HumanOnTimeout string `hcl:"human_on_timeout,optional"`
}

// PolicyText is the lowered shape of a policy "<name>" {} block:
// the heredoc text plus its source range for diagnostic messages.
type PolicyText struct {
	Name string
	Text string `hcl:"text"`
}

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
		Policies:    make(map[string]*PolicyText),
		Profiles:    make(map[string]*Profile),
	}

	// Pass 1: extract the policy blocks from the remainder body.
	policyBlocks, defaultsBlocks, polDiags := extractPolicyBlocks(gw.Remain)
	diags = append(diags, polDiags...)

	table, symDiags := buildSymbols(policyBlocks)
	diags = append(diags, symDiags...)

	// defaults {} (singleton, no labels)
	if len(defaultsBlocks) > 1 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Duplicate defaults block",
			Detail:   "Only one defaults {} block is allowed.",
			Subject:  &defaultsBlocks[1].DefRange,
		})
	}
	if len(defaultsBlocks) >= 1 {
		var d Defaults
		if dd := gohcl.DecodeBody(defaultsBlocks[0].Body, nil, &d); dd.HasErrors() {
			diags = append(diags, dd...)
		}
		gw.Policy.Defaults = d
	}

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

// extractPolicyBlocks pulls every recognized top-level block out of
// the remainder body returned by the operational gohcl decode.
// Defaults blocks are returned separately because they have a fixed
// schema (no labels, no plugin dispatch).
func extractPolicyBlocks(body hcl.Body) (hcl.Blocks, hcl.Blocks, hcl.Diagnostics) {
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "defaults"},
			{Type: "approver", LabelNames: []string{"type", "name"}},
			{Type: "credential", LabelNames: []string{"type", "name"}},
			{Type: "endpoint", LabelNames: []string{"type", "name"}},
			{Type: "rule", LabelNames: []string{"type", "name"}},
			{Type: "policy", LabelNames: []string{"name"}},
			{Type: "profile", LabelNames: []string{"name"}},
		},
	}
	content, _, diags := body.PartialContent(schema)
	var policy, defaults hcl.Blocks
	for _, b := range content.Blocks {
		if b.Type == "defaults" {
			defaults = append(defaults, b)
		} else {
			policy = append(policy, b)
		}
	}
	return policy, defaults, diags
}

// buildEvalContext installs every declared name as a string variable
// in an hcl.EvalContext. Bare-name references in HCL expressions
// (`endpoint = github-avocet`) then evaluate to the string "github-
// avocet"; the kind / family check happens after decode.
func buildEvalContext(table *SymbolTable) *hcl.EvalContext {
	vars := make(map[string]cty.Value, len(table.allNames))
	for name := range table.allNames {
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

	for _, kind := range []Kind{KindApprover, KindCredential, KindEndpoint, KindRule} {
		for _, sym := range table.byKind[kind] {
			plugin := Lookup(sym.Kind, sym.Type)
			if plugin == nil {
				// Already reported in pass 1.
				continue
			}
			target := plugin.New()
			decodeDiags := dedupGohclDiags(gohcl.DecodeBody(sym.Block.Body, evalCtx, target))
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
			body, buildDiags := plugin.Build(target, sym.Name, ctx)
			diags = append(diags, buildDiags...)
			ent := &Entity{
				Symbol: sym,
				Plugin: plugin,
				Body:   body,
				Refs:   refs,
			}
			switch kind {
			case KindApprover:
				p.Approvers[sym.Name] = ent
			case KindCredential:
				p.Credentials[sym.Name] = ent
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
