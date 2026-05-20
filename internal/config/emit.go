package config

import (
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// RefIndex resolves a (kind, name) pair to the typed traversal string
// the emitter should write. Two-label kinds become `type.name`; one-
// label kinds become `kind.name` (e.g. `rule.foo`). Built into Emit
// from the loaded *Policy so plugin Emit hooks don't each re-derive
// the type lookup.
type RefIndex struct {
	credType    map[string]string
	approverTyp map[string]string
	tunnelType  map[string]string
	endpointTyp map[string]string
	envType     map[string]string
}

func newRefIndex(p *Policy) *RefIndex {
	r := &RefIndex{
		credType:    map[string]string{},
		approverTyp: map[string]string{},
		tunnelType:  map[string]string{},
		endpointTyp: map[string]string{},
		envType:     map[string]string{},
	}
	if p == nil {
		return r
	}
	for n, e := range p.Credentials {
		if e != nil && e.Plugin != nil {
			r.credType[n] = e.Plugin.Type
		}
	}
	for n, e := range p.Approvers {
		if e != nil && e.Plugin != nil {
			r.approverTyp[n] = e.Plugin.Type
		}
	}
	for n, e := range p.Tunnels {
		if e != nil && e.Plugin != nil {
			r.tunnelType[n] = e.Plugin.Type
		}
	}
	for n, e := range p.Endpoints {
		if e != nil && e.Plugin != nil {
			r.endpointTyp[n] = e.Plugin.Type
		}
	}
	for n, e := range p.Environments {
		if e != nil && e.Plugin != nil {
			r.envType[n] = e.Plugin.Type
		}
	}
	// Built-in approvers (e.g. dashboard) carry the synthetic "builtin"
	// type so `approve = [builtin.dashboard]` resolves the same way.
	for _, name := range builtinApproverNames {
		if _, ok := r.approverTyp[name]; !ok {
			r.approverTyp[name] = "builtin"
		}
	}
	return r
}

// Ref returns the dotted traversal string for a (kind, name). Falls
// back to the bare name if the kind isn't known.
func (r *RefIndex) Ref(kind Kind, name string) string {
	if r == nil || name == "" {
		return name
	}
	switch kind {
	case KindCredential:
		if t := r.credType[name]; t != "" {
			return t + "." + name
		}
	case KindApprover:
		if t := r.approverTyp[name]; t != "" {
			return t + "." + name
		}
	case KindTunnel:
		if t := r.tunnelType[name]; t != "" {
			return t + "." + name
		}
	case KindEndpoint:
		if t := r.endpointTyp[name]; t != "" {
			return t + "." + name
		}
	case KindEnvironment:
		if t := r.envType[name]; t != "" {
			return t + "." + name
		}
	case KindRule, KindPolicy, KindProfile:
		return string(kind) + "." + name
	}
	return name
}

// Refs is a slice variant.
func (r *RefIndex) Refs(kind Kind, names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = r.Ref(kind, n)
	}
	return out
}

// emitRI is the RefIndex active for the current Emit call. Plugin
// Emit hooks read it via the package-level SetIdent / SetIdentList
// helpers so they don't need to thread a RefIndex through their own
// signatures. Guarded by emitRIMu because Emit is documented to be
// safe to call from any goroutine, but never concurrently with itself.
var (
	emitRIMu sync.Mutex
	emitRI   *RefIndex
)

// EmitRefIndex returns the current emit's RefIndex. Plugin Emit hooks
// call this to resolve a bare entity name to its typed-traversal form
// (e.g. "anthropic" → "https.anthropic") before calling SetIdent /
// SetIdentList. Returns a non-nil pointer even when no Emit is in
// progress so callers don't have to nil-check before Ref / Refs.
func EmitRefIndex() *RefIndex {
	if emitRI != nil {
		return emitRI
	}
	return &RefIndex{}
}

// TraversalTokens is the exported form of traversalTokens, for plugin
// Emit hooks that build attribute token lists by hand (e.g. the rule
// plugin's `approve = [a, b, c]` list).
func TraversalTokens(s string) hclwrite.Tokens {
	return traversalTokens(s)
}

// Emit serializes a loaded *Gateway back to HCL. The output is
// deterministic (operational fields first, then kind-grouped policy
// blocks in source order) and re-parsable by Load — round-tripping
// fixtures through Emit + Load produces a structurally identical
// *Gateway, modulo comment loss (hclwrite can't preserve operator
// comments through gohcl decode).
//
// Per-block emission delegates to the plugin's Emit hook so each
// plugin owns its own body shape — credential bindings, match
// objects, family-specific endpoint fields all live next to the
// schema they correspond to.
func Emit(gw *Gateway) ([]byte, error) {
	f := hclwrite.NewEmptyFile()
	body := f.Body()

	emitOperational(body, gw)

	if gw.Policy == nil {
		return f.Bytes(), nil
	}
	p := gw.Policy

	// Install the per-Emit RefIndex so plugin Emit hooks can resolve
	// typed traversals via SetIdent / SetIdentList.
	emitRIMu.Lock()
	defer emitRIMu.Unlock()
	emitRI = newRefIndex(p)
	defer func() { emitRI = nil }()

	// Per-kind groups in a deterministic order: approvers → policies →
	// credentials → endpoints → rules → profiles. Within a group, walk
	// p.Order (source order) and filter to that kind, falling back to
	// alphabetical for entries Order doesn't cover (defensive — every
	// loaded entry is in Order in practice).
	emitGroup(body, p, KindApprover)
	emitGroup(body, p, KindPolicy)
	emitGroup(body, p, KindCredential)
	emitGroup(body, p, KindTunnel)
	emitGroup(body, p, KindEndpoint)
	emitGroup(body, p, KindEnvironment)
	emitGroup(body, p, KindRule)
	emitGroup(body, p, KindProfile)

	return f.Bytes(), nil
}

func emitOperational(body *hclwrite.Body, gw *Gateway) {
	setStr := func(name, v string) {
		if v != "" {
			body.SetAttributeValue(name, cty.StringVal(v))
		}
	}
	setInt := func(name string, v int) {
		if v != 0 {
			body.SetAttributeValue(name, cty.NumberIntVal(int64(v)))
		}
	}
	setStr("listen", gw.Listen)
	setStr("info_listen", gw.InfoListen)
	setStr("public_url", gw.PublicURL)
	setStr("admin_email", gw.AdminEmail)
	setStr("resolver", gw.Resolver)
	setStr("log_path", gw.LogPath)
	if len(gw.DashboardOperators) > 0 {
		body.SetAttributeValue("dashboard_operators", StringListVal(gw.DashboardOperators))
	}
	setStr("dashboard_session_ttl", gw.DashboardSessionTTL)
	setStr("session_keep", gw.SessionKeep)

	setStr("authkey", gw.AuthKey)
	setStr("control_url", gw.ControlURL)
	setStr("hostname", gw.Hostname)
	setStr("state_dir", gw.StateDir)
	setStr("control", gw.Control)
	setStr("oauth_client_id", gw.OAuthClientID)
	setStr("oauth_client_secret", gw.OAuthClientSecret)
	if len(gw.TailscaleTags) > 0 {
		body.SetAttributeValue("tailscale_tags", StringListVal(gw.TailscaleTags))
	}
	setStr("wg_interface", gw.WGInterface)
	setStr("wg_endpoint", gw.WGEndpoint)
	setStr("wg_server_pub", gw.WGServerPub)
	setStr("wg_subnet_cidr", gw.WGSubnetCIDR)

	setStr("unknown_host", gw.UnknownHost)
	setStr("llm_fail_mode", gw.LLMFailMode)
	setInt("llm_cache_ttl", gw.LLMCacheTTL)
	setInt("human_timeout", gw.HumanTimeout)
	setStr("human_on_timeout", gw.HumanOnTimeout)
}

// emitGroup walks p.Order, filters by kind, and emits each entry's
// block. Entries not in Order (shouldn't happen for properly loaded
// configs) are appended afterward in alphabetical name order so emit
// is deterministic.
func emitGroup(body *hclwrite.Body, p *Policy, kind Kind) {
	emitted := map[string]bool{}
	for _, name := range p.Order {
		if emitted[name] {
			// p.Order is a flat list across kinds; cross-kind name
			// reuse (allowed under typed traversals) can put the same
			// name in twice. Skip the second visit so we don't emit a
			// duplicate block.
			continue
		}
		if !emitOne(body, p, kind, name) {
			continue
		}
		emitted[name] = true
	}
	// Defensive sweep for entries Order missed.
	leftover := leftoverNames(p, kind, emitted)
	for _, name := range leftover {
		emitOne(body, p, kind, name)
	}
}

func leftoverNames(p *Policy, kind Kind, emitted map[string]bool) []string {
	var out []string
	switch kind {
	case KindApprover:
		for n := range p.Approvers {
			if !emitted[n] {
				out = append(out, n)
			}
		}
	case KindPolicy:
		for n := range p.Policies {
			if !emitted[n] {
				out = append(out, n)
			}
		}
	case KindCredential:
		for n := range p.Credentials {
			if !emitted[n] {
				out = append(out, n)
			}
		}
	case KindEndpoint:
		for n := range p.Endpoints {
			if !emitted[n] {
				out = append(out, n)
			}
		}
	case KindEnvironment:
		for n := range p.Environments {
			if !emitted[n] {
				out = append(out, n)
			}
		}
	case KindRule:
		for n := range p.Rules {
			if !emitted[n] {
				out = append(out, n)
			}
		}
	case KindTunnel:
		for n := range p.Tunnels {
			if !emitted[n] {
				out = append(out, n)
			}
		}
	case KindProfile:
		for n := range p.Profiles {
			if !emitted[n] {
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

func emitOne(body *hclwrite.Body, p *Policy, kind Kind, name string) bool {
	switch kind {
	case KindApprover:
		ent, ok := p.Approvers[name]
		if !ok {
			return false
		}
		emitEntityBlock(body, "approver", ent, name)
	case KindPolicy:
		pt, ok := p.Policies[name]
		if !ok {
			return false
		}
		body.AppendNewline()
		b := body.AppendNewBlock("policy", []string{name}).Body()
		// Heredoc preservation isn't hclwrite's strong suit; emit as
		// a normal string. Operators editing through the dashboard
		// see the heredoc collapse to a single quoted string — fine
		// for now; preserving the heredoc shape on round-trip is a
		// follow-up.
		b.SetAttributeValue("text", cty.StringVal(pt.Text))
	case KindCredential:
		ent, ok := p.Credentials[name]
		if !ok {
			return false
		}
		emitEntityBlock(body, "credential", ent, name)
	case KindEndpoint:
		ent, ok := p.Endpoints[name]
		if !ok {
			return false
		}
		emitEntityBlock(body, "endpoint", ent, name)
	case KindEnvironment:
		ent, ok := p.Environments[name]
		if !ok {
			return false
		}
		emitEntityBlock(body, "environment", ent, name)
	case KindRule:
		ent, ok := p.Rules[name]
		if !ok {
			return false
		}
		emitEntityBlock(body, "rule", ent, name)
	case KindTunnel:
		ent, ok := p.Tunnels[name]
		if !ok {
			return false
		}
		emitEntityBlock(body, "tunnel", ent, name)
	case KindProfile:
		pr, ok := p.Profiles[name]
		if !ok {
			return false
		}
		body.AppendNewline()
		b := body.AppendNewBlock("profile", []string{name}).Body()
		if len(pr.Credentials) > 0 {
			setProfileCredentials(b, pr.Credentials, pr.Disambiguators)
		}
		if len(pr.Environments) > 0 {
			setProfileEnvironments(b, pr.Environments)
		}
		if pr.HITLAsyncGrants {
			b.SetAttributeValue("hitl_async_grants", cty.True)
		}
	default:
		return false
	}
	return true
}

func emitEntityBlock(body *hclwrite.Body, kind string, ent *Entity, name string) {
	body.AppendNewline()
	labels := []string{ent.Plugin.Type, name}
	if ent.Symbol.Kind.LabelCount() == 1 {
		// Single-label kinds (rule) omit the type label — the block
		// header is `rule "<name>" { ... }` and the plugin is the
		// kind's single registered entry.
		labels = []string{name}
	}
	block := body.AppendNewBlock(kind, labels).Body()
	if ent.Plugin.Emit != nil {
		ent.Plugin.Emit(ent.Body, name, block)
	}
	emitFrameworkAttrs(block, ent)
}

// emitFrameworkAttrs writes the framework-level attrs (tunnel,
// credential.endpoint(s), …) onto the block body after the plugin's
// own Emit. Mirrors the loader's extractFramework — the loader peels
// these off, this puts them back, so HCL → load → emit round-trips.
func emitFrameworkAttrs(b *hclwrite.Body, ent *Entity) {
	ri := EmitRefIndex()
	for _, spec := range pluginFrameworkAttrs(ent.Plugin) {
		switch {
		case spec.Kind == "":
			if s := ent.Framework.Str(spec.Name); s != "" {
				b.SetAttributeValue(spec.Name, cty.StringVal(s))
			}
		case spec.List:
			if list := ent.Framework.RefList(spec.Name); len(list) > 0 {
				SetIdentList(b, spec.Name, ri.Refs(spec.Kind, list))
			}
		default:
			if ref := ent.Framework.Ref(spec.Name); ref != "" {
				SetIdent(b, spec.Name, ri.Ref(spec.Kind, ref))
			}
		}
	}
}

// StringListVal lifts a Go []string into a cty.ListVal. Exported so
// plugin Emit hooks can use it for `hosts = [...]` style attributes.
// cty.ListValEmpty is required for the empty case because
// cty.ListVal(nil) panics — gocty inference can't pick the element
// type from an empty slice.
func StringListVal(xs []string) cty.Value {
	if len(xs) == 0 {
		return cty.ListValEmpty(cty.String)
	}
	out := make([]cty.Value, len(xs))
	for i, s := range xs {
		out[i] = cty.StringVal(s)
	}
	return cty.ListVal(out)
}

// SetIdentList writes `name = [a.x, b.y, c.z]` where each element is
// a dotted traversal expression. Used for typed ref lists like
// `endpoints = [https.github, slack_tokens.dev]`. Pass each entry
// as its fully-qualified traversal string (use RefIndex.Ref to build).
//
// Exported so plugin Emit hooks can use it for fields like a rule's
// `endpoints = [...]` ref list.
func SetIdentList(b *hclwrite.Body, name string, idents []string) {
	tokens := hclwrite.Tokens{
		{Type: hclsyntax.TokenOBrack, Bytes: []byte("[")},
	}
	for i, id := range idents {
		if i > 0 {
			tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(", ")})
		}
		tokens = append(tokens, traversalTokens(id)...)
	}
	tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenCBrack, Bytes: []byte("]")})
	b.SetAttributeRaw(name, tokens)
}

// setProfileEnvironments emits the `environments = [a, b, c]` list on
// a profile block. Names are bare-name idents; the package-level
// emitRI rewrites them to typed traversals at serialize time.
func setProfileEnvironments(b *hclwrite.Body, envs []string) {
	ri := EmitRefIndex()
	SetIdentList(b, "environments", ri.Refs(KindEnvironment, envs))
}

// traversalTokens splits a dotted string into HCL ident / dot tokens.
// "type.name" → [Ident("type"), Dot, Ident("name")]; a bare "name"
// stays a single Ident token.
func traversalTokens(s string) hclwrite.Tokens {
	parts := strings.Split(s, ".")
	out := make(hclwrite.Tokens, 0, len(parts)*2-1)
	for i, p := range parts {
		if i > 0 {
			out = append(out, &hclwrite.Token{Type: hclsyntax.TokenDot, Bytes: []byte(".")})
		}
		out = append(out, &hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(p)})
	}
	return out
}

// setProfileCredentials emits the mixed-shape `credentials = [...]`
// attribute on a profile block. Entries with associated profile-side
// disambiguators render as `{ credential = name, <field> = "...", ... }`
// object literals (fields sorted alphabetically for stable output);
// entries without any render as bare-name idents.
func setProfileCredentials(b *hclwrite.Body, creds []string, disambig map[string]map[string]string) {
	ri := EmitRefIndex()
	tokens := hclwrite.Tokens{
		{Type: hclsyntax.TokenOBrack, Bytes: []byte("[")},
	}
	for i, c := range creds {
		if i > 0 {
			tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(", ")})
		}
		credRef := ri.Ref(KindCredential, c)
		if d := disambig[c]; len(d) > 0 {
			keys := make([]string, 0, len(d))
			for k := range d {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenOBrace, Bytes: []byte("{ ")})
			tokens = append(tokens,
				&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte("credential")},
				&hclwrite.Token{Type: hclsyntax.TokenEqual, Bytes: []byte(" = ")},
			)
			tokens = append(tokens, traversalTokens(credRef)...)
			for _, k := range keys {
				tokens = append(tokens,
					&hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(", ")},
					&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(k)},
					&hclwrite.Token{Type: hclsyntax.TokenEqual, Bytes: []byte(" = ")},
					&hclwrite.Token{Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`)},
					&hclwrite.Token{Type: hclsyntax.TokenQuotedLit, Bytes: []byte(d[k])},
					&hclwrite.Token{Type: hclsyntax.TokenCQuote, Bytes: []byte(`"`)},
				)
			}
			tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenCBrace, Bytes: []byte(" }")})
			continue
		}
		tokens = append(tokens, traversalTokens(credRef)...)
	}
	tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenCBrack, Bytes: []byte("]")})
	b.SetAttributeRaw("credentials", tokens)
}

// SetIdent writes `name = a.b` where the value is a dotted traversal
// (e.g. `credential = header_token.github`). The ident string
// may be a single identifier or a dotted traversal — splitting on
// '.' yields the token sequence.
func SetIdent(b *hclwrite.Body, name, ident string) {
	b.SetAttributeRaw(name, traversalTokens(ident))
}
