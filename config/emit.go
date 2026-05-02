package config

import (
	"sort"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// Emit serializes a loaded *Gateway back to HCL. The output is
// deterministic (operational fields first, then defaults, then
// kind-grouped policy blocks in source order) and re-parsable by
// Load — round-tripping fixtures through Emit + Load produces a
// structurally identical *Gateway, modulo comment loss (hclwrite
// can't preserve operator comments through gohcl decode).
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

	// Defaults first if any field is non-zero.
	if d := gw.Policy.Defaults; d != (Defaults{}) {
		body.AppendNewline()
		emitDefaults(body, d)
	}

	// Per-kind groups in a deterministic order: approvers → policies →
	// credentials → endpoints → rules → profiles. Within a group, walk
	// p.Order (source order) and filter to that kind, falling back to
	// alphabetical for entries Order doesn't cover (defensive — every
	// loaded entry is in Order in practice).
	emitGroup(body, p, KindApprover)
	emitGroup(body, p, KindPolicy)
	emitGroup(body, p, KindCredential)
	emitGroup(body, p, KindEndpoint)
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
	setStr("listen", gw.Listen)
	setStr("info_listen", gw.InfoListen)
	setStr("public_url", gw.PublicURL)
	setStr("admin_email", gw.AdminEmail)
	setStr("ca_dir", gw.CADir)
	setStr("resolver", gw.Resolver)
	setStr("log_path", gw.LogPath)
	setStr("oauth_dir", gw.OAuthDir)
	setStr("dashboard_secret", gw.DashboardSecret)

	if gw.Tailscale != nil && !isZeroTailscale(gw.Tailscale) {
		body.AppendNewline()
		ts := body.AppendNewBlock("tailscale", nil).Body()
		emitTailscale(ts, gw.Tailscale)
	}
}

func emitTailscale(b *hclwrite.Body, t *Tailscale) {
	setStr := func(name, v string) {
		if v != "" {
			b.SetAttributeValue(name, cty.StringVal(v))
		}
	}
	setStr("authkey", t.AuthKey)
	setStr("control_url", t.ControlURL)
	setStr("hostname", t.Hostname)
	setStr("state_dir", t.StateDir)
	setStr("control", t.Control)
	setStr("oauth_client_id", t.OAuthClientID)
	setStr("oauth_client_secret", t.OAuthClientSecret)
	if len(t.Tags) > 0 {
		b.SetAttributeValue("tags", StringListVal(t.Tags))
	}
	setStr("wg_interface", t.WGInterface)
	setStr("wg_endpoint", t.WGEndpoint)
	setStr("wg_server_pub", t.WGServerPub)
	setStr("wg_subnet_cidr", t.WGSubnetCIDR)
}

func emitDefaults(body *hclwrite.Body, d Defaults) {
	b := body.AppendNewBlock("defaults", nil).Body()
	if d.UnknownHost != "" {
		b.SetAttributeValue("unknown_host", cty.StringVal(d.UnknownHost))
	}
	if d.LLMFailMode != "" {
		b.SetAttributeValue("llm_fail_mode", cty.StringVal(d.LLMFailMode))
	}
	if d.LLMCacheTTL != 0 {
		b.SetAttributeValue("llm_cache_ttl", cty.NumberIntVal(int64(d.LLMCacheTTL)))
	}
	if d.HumanTimeout != 0 {
		b.SetAttributeValue("human_timeout", cty.NumberIntVal(int64(d.HumanTimeout)))
	}
	if d.HumanOnTimeout != "" {
		b.SetAttributeValue("human_on_timeout", cty.StringVal(d.HumanOnTimeout))
	}
}

// emitGroup walks p.Order, filters by kind, and emits each entry's
// block. Entries not in Order (shouldn't happen for properly loaded
// configs) are appended afterward in alphabetical name order so emit
// is deterministic.
func emitGroup(body *hclwrite.Body, p *Policy, kind Kind) {
	emitted := map[string]bool{}
	for _, name := range p.Order {
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
	case KindRule:
		for n := range p.Rules {
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
	case KindRule:
		ent, ok := p.Rules[name]
		if !ok {
			return false
		}
		emitEntityBlock(body, "rule", ent, name)
	case KindProfile:
		pr, ok := p.Profiles[name]
		if !ok {
			return false
		}
		body.AppendNewline()
		b := body.AppendNewBlock("profile", []string{name}).Body()
		if len(pr.Endpoints) > 0 {
			SetIdentList(b, "endpoints", pr.Endpoints)
		}
	default:
		return false
	}
	return true
}

func emitEntityBlock(body *hclwrite.Body, kind string, ent *Entity, name string) {
	body.AppendNewline()
	block := body.AppendNewBlock(kind, []string{ent.Plugin.Type, name}).Body()
	if ent.Plugin.Emit != nil {
		ent.Plugin.Emit(ent.Body, name, block)
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

// SetIdentList writes `name = [a, b, c]` where each element is a
// bare identifier (traversal expression), not a quoted string. Used
// for `endpoints = [github, slack-avocet]` style references.
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
		tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(id)})
	}
	tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenCBrack, Bytes: []byte("]")})
	b.SetAttributeRaw(name, tokens)
}

// SetIdent writes `name = ident` where the value is a bare
// identifier (traversal). Used for singular ref attributes like
// `credential = github-pat` or `endpoint = github`.
func SetIdent(b *hclwrite.Body, name, ident string) {
	tokens := hclwrite.Tokens{
		{Type: hclsyntax.TokenIdent, Bytes: []byte(ident)},
	}
	b.SetAttributeRaw(name, tokens)
}
