// Package rules registers the single `rule` block kind. Each rule is
// one policy decision targeting one or more endpoints; the rule's
// protocol family (https / sql / k8s) is inferred from the resolved
// endpoints at validate/build time. Mixed-family endpoint sets are
// rejected with a clean diagnostic.
//
// The match predicate is expressed as a single CEL string in the
// `condition` attribute, evaluated against the facet-owned environment
// for the rule's family (see config/plugins/facets/{https,sql,k8s}/).
// `approve` is a list whose elements are bare-name approver
// references.
package rules

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
)

// RuleBody is the gohcl-tagged decode target. The match predicate is
// family-agnostic at the HCL layer (just a CEL string); the facet's
// *cel.Env decides which variables are valid once the family has
// been inferred from the endpoint refs.
type RuleBody struct {
	Endpoint  string   `hcl:"endpoint,optional"`
	Endpoints []string `hcl:"endpoints,optional"`
	Priority  int      `hcl:"priority,optional"`
	Disabled  bool     `hcl:"disabled,optional"`

	// Condition is a CEL expression evaluated against the
	// family-specific variable set. An absent / empty condition
	// matches everything — the catch-all pattern (`rule
	// "X-default" { priority = -100; verdict = "deny" }`) relies
	// on this.
	Condition string `hcl:"condition,optional"`

	// Match is the declarative glob-and-suffix grammar alternative to
	// `condition`. Body is `match = { method_any = [...], path_none =
	// [...] }`-shaped: each key is `<facet-key>[_any|_all|_none]`, each
	// value is a glob (filepath.Match style). Mutually exclusive with
	// `condition`. Lowered to an equivalent CEL expression at load
	// time, so the runtime sees a uniform shape.
	Match cty.Value `hcl:"match,optional"`

	// Credential, if set, is a bare-name reference to a credential
	// block. The runtime treats it as an extra match predicate
	// (request must have been dispatched against this credential)
	// evaluated before the CEL expression.
	Credential string `hcl:"credential,optional"`

	// Verdict is the outcome when the rule matches. Set exactly one
	// of `verdict` (`"allow"` / `"deny"`) or `approve`.
	Verdict string `hcl:"verdict,optional"`
	Reason  string `hcl:"reason,optional"`
	// Approve is a list of bare-name approver references. The
	// approvers run in order; the request is allowed only if every
	// stage approves. Set this *or* `verdict`, not both.
	Approve cty.Value `hcl:"approve,optional"`
}

// Rule is the canonical, family-stamped record stored in
// Policy.Rules[name].Body.
//
// MatchBlock, when non-nil, is the parsed source form of a
// declarative `match = {...}` body. Condition still holds the
// compiled CEL expression — the runtime always reads from there —
// but emit prefers MatchBlock so a round-trip preserves the
// operator's chosen surface syntax.
type Rule struct {
	Name       string                `json:"name"`
	Family     string                `json:"family"` // "https" | "sql" | "k8s"
	Endpoints  []string              `json:"endpoints"`
	Priority   int                   `json:"priority,omitempty"`
	Disabled   bool                  `json:"disabled,omitempty"`
	Condition  string                `json:"condition,omitempty"`
	Credential string                `json:"credential,omitempty"`
	Verdict    string                `json:"verdict,omitempty"` // "allow" | "deny" | "" (when Approve is set)
	Reason     string                `json:"reason,omitempty"`
	Approve    []config.ApproveStage `json:"approve,omitempty"`

	MatchBlock *match.Block `json:"-"`
}

// Compile lowers a built rule into the runtime-friendly *CompiledRule
// the request handler consumes. The match.Matcher is constructed
// via the facet registry so per-family quirks live with the plugin
// that owns them.
//
// Returns the compiled rule plus the list of endpoint names this
// rule attaches to.
func (r *Rule) Compile() (*config.CompiledRule, []string, error) {
	matcher, err := facet.NewMatcher(r.Family, r.Condition)
	if err != nil {
		return nil, nil, fmt.Errorf("condition: %w", err)
	}
	return &config.CompiledRule{
		Name:       r.Name,
		Priority:   r.Priority,
		Disabled:   r.Disabled,
		Condition:  r.Condition,
		Credential: r.Credential,
		Matcher:    matcher,
		Outcome: config.Outcome{
			Verdict: r.Verdict,
			Reason:  r.Reason,
			Approve: r.Approve,
		},
	}, r.Endpoints, nil
}

// inferFamily walks the rule's endpoint list, looks each one up in
// the symbol table, and reports the common endpoint family. Returns
// "" plus a diagnostic if the endpoints span more than one family
// (the rule's CEL env can only bind one facet's variables) or if no
// endpoint is set (caught separately by the shape check, but a
// defensive empty-set check keeps the family lookup safe). Unknown
// endpoint names are skipped — the framework's ref-resolution pass
// already emitted "unknown endpoint" diagnostics for those.
func inferFamily(endpoints []string, name string, ctx *config.BuildCtx) (string, *hcl.Diagnostic) {
	seen := map[string]struct{}{}
	for _, ep := range endpoints {
		sym := ctx.Symbols.Get(config.KindEndpoint, ep)
		if sym == nil || sym.Family == "" {
			continue
		}
		seen[sym.Family] = struct{}{}
	}
	if len(seen) == 0 {
		return "", nil
	}
	if len(seen) > 1 {
		fams := make([]string, 0, len(seen))
		for f := range seen {
			fams = append(fams, f)
		}
		sort.Strings(fams)
		return "", &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Rule %q targets endpoints from mixed families", name),
			Detail:   fmt.Sprintf("Endpoints span families %v. A rule's CEL condition is evaluated against a single facet's variable set; split into one rule per family.", fams),
			Subject:  &ctx.Block.DefRange,
		}
	}
	for f := range seen {
		return f, nil
	}
	return "", nil
}

func endpointList(rb *RuleBody) []string {
	if rb.Endpoint != "" {
		return []string{rb.Endpoint}
	}
	return rb.Endpoints
}

func validate(body any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
	rb := body.(*RuleBody)
	var diags hcl.Diagnostics

	// Exactly one of endpoint / endpoints. Catch shape errors first
	// so the family-inference diagnostic doesn't fire on a rule that
	// already has a clearer problem to fix.
	if rb.Endpoint != "" && len(rb.Endpoints) > 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Both endpoint and endpoints set on rule %q", name),
			Detail:   "Use exactly one of `endpoint = X` or `endpoints = [X, Y]`.",
			Subject:  &ctx.Block.DefRange,
		})
	}
	if rb.Endpoint == "" && len(rb.Endpoints) == 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Rule %q has no endpoints", name),
			Detail:   "Set `endpoint = X` or `endpoints = [X, Y]`.",
			Subject:  &ctx.Block.DefRange,
		})
	}

	// Infer family from the endpoint set so condition compilation
	// can pick the right facet env.
	fam, famDiag := inferFamily(endpointList(rb), name, ctx)
	if famDiag != nil {
		diags = append(diags, famDiag)
	}

	hasMatch := !rb.Match.IsNull()
	if rb.Condition != "" && hasMatch {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Both condition and match set on rule %q", name),
			Detail:   "Use exactly one of `condition = \"<CEL>\"` or `match = { ... }`. The match form lowers to CEL at load time, so the two are interchangeable in expressivity for the keys match supports.",
			Subject:  &ctx.Block.DefRange,
		})
	}

	// CEL condition syntactic + type validation. Compile against the
	// inferred facet's environment so unknown variables and result-
	// type mismatches are caught at Load time. With no family
	// (unknown endpoints, etc.) skip the compile — the unknown-
	// endpoint diagnostic is enough.
	if rb.Condition != "" && fam != "" {
		if _, err := facet.NewMatcher(fam, rb.Condition); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Invalid CEL condition on rule %q", name),
				Detail:   err.Error(),
				Subject:  &ctx.Block.DefRange,
			})
		}
	}

	// Validate the declarative match attribute against the family's
	// facet keys, then sanity-check the lowered CEL by feeding it
	// back through the facet's matcher compiler. With no family,
	// skip — same reason as above.
	if hasMatch && fam != "" {
		_, mDiags := compileMatch(fam, rb.Match, name, ctx.Block.DefRange)
		diags = append(diags, mDiags...)
	}

	// Outcome: exactly one of verdict / approve.
	hasVerdict := rb.Verdict != ""
	hasApprove := !rb.Approve.IsNull() && rb.Approve.LengthInt() > 0
	if hasVerdict && hasApprove {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Both verdict and approve set on rule %q", name),
			Detail:   "Use exactly one of `verdict = ...` or `approve = [...]`.",
			Subject:  &ctx.Block.DefRange,
		})
	}
	if !hasVerdict && !hasApprove {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Rule %q has no outcome", name),
			Detail:   "Set `verdict = \"allow\"`, `verdict = \"deny\"`, or `approve = [...]`.",
			Subject:  &ctx.Block.DefRange,
		})
	}
	if hasVerdict && rb.Verdict != "allow" && rb.Verdict != "deny" {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Invalid verdict %q on rule %q", rb.Verdict, name),
			Detail:   "verdict must be \"allow\" or \"deny\".",
			Subject:  &ctx.Block.DefRange,
		})
	}

	return diags
}

func build(body any, name string, ctx *config.BuildCtx) (any, hcl.Diagnostics) {
	rb := body.(*RuleBody)
	var diags hcl.Diagnostics

	endpoints := endpointList(rb)
	fam, famDiag := inferFamily(endpoints, name, ctx)
	if famDiag != nil {
		// Already reported by validate; don't double-emit.
		_ = famDiag
	}

	r := &Rule{
		Name:       name,
		Family:     fam,
		Endpoints:  endpoints,
		Priority:   rb.Priority,
		Disabled:   rb.Disabled,
		Condition:  rb.Condition,
		Credential: rb.Credential,
		Verdict:    rb.Verdict,
		Reason:     rb.Reason,
	}

	// Lower the declarative match into CEL and stash both the
	// compiled string (so the runtime path is uniform) and the
	// parsed block (so emit can round-trip the operator's source
	// shape). validate already surfaced any diagnostics for this
	// match block — discard them here to avoid duplication. With no
	// family the validate pass already reported the unknown endpoint;
	// the lowering is silent in that case.
	if !rb.Match.IsNull() && fam != "" {
		specs := matchKeysFor(fam)
		block, _ := match.DecodeAttribute(rb.Match, specs, name, ctx.Block.DefRange)
		if block != nil {
			r.MatchBlock = block
			if expr, err := block.Compile(specs); err == nil {
				r.Condition = expr
			}
		}
	}

	// Approve chain.
	if !rb.Approve.IsNull() {
		stages, stageDiags := decodeApproveChain(rb.Approve, name, ctx)
		diags = append(diags, stageDiags...)
		r.Approve = stages
	}

	return r, diags
}

// decodeApproveChain walks the cty.Value approve = [...] list. Each
// element is a bare-name reference to an approver block; LLM policy
// text and cache TTL ride on the approver block itself.
func decodeApproveChain(v cty.Value, ruleName string, ctx *config.BuildCtx) ([]config.ApproveStage, hcl.Diagnostics) {
	var stages []config.ApproveStage
	var diags hcl.Diagnostics
	if !v.Type().IsTupleType() && !v.Type().IsListType() {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Rule %q approve must be a list", ruleName),
			Subject:  &ctx.Block.DefRange,
		})
		return stages, diags
	}
	it := v.ElementIterator()
	for it.Next() {
		_, el := it.Element()
		t := el.Type()
		if t != cty.String {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Rule %q approve stage must be a bare-name reference", ruleName),
				Detail:   "Each stage is a bare approver name (e.g. `approve = [claude-judge]`). Bind policy text on the approver block itself.",
				Subject:  &ctx.Block.DefRange,
			})
			continue
		}
		name := el.AsString()
		if d := requireKind(ctx, name, config.KindApprover, ruleName, "approve stage"); d != nil {
			diags = append(diags, d)
		}
		stages = append(stages, config.ApproveStage{Name: name})
	}
	return stages, diags
}

func requireKind(ctx *config.BuildCtx, name string, kind config.Kind, ruleName, what string) *hcl.Diagnostic {
	if name == "" {
		return nil
	}
	if ctx.Symbols.Get(kind, name) != nil {
		return nil
	}
	if alt := ctx.Symbols.GetAny(name); alt != nil {
		return &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Wrong reference kind for %q", name),
			Detail:   fmt.Sprintf("Rule %q %s expects a %s but %q is a %s.", ruleName, what, kind, name, alt.Kind),
			Subject:  &ctx.Block.DefRange,
		}
	}
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  fmt.Sprintf("Unknown %s %q", kind, name),
		Detail:   fmt.Sprintf("Rule %q %s references undeclared %s %q.", ruleName, what, kind, name),
		Subject:  &ctx.Block.DefRange,
	}
}

// emitRule serializes a built *Rule back to HCL block body. Endpoints
// are emitted as bare-name idents (singular vs list forms preserved
// to round-trip the operator's choice). Condition emits as a quoted
// string; credential as a bare-name ident; approve mixes bare-name
// idents. When the rule was originally written with a `match = {...}`
// block, emit prefers that form over the lowered CEL so a load /
// emit cycle preserves the operator's chosen surface syntax.
func emitRule(body any, _ string, b *hclwrite.Body) {
	r := body.(*Rule)
	if len(r.Endpoints) == 1 {
		config.SetIdent(b, "endpoint", r.Endpoints[0])
	} else if len(r.Endpoints) > 1 {
		config.SetIdentList(b, "endpoints", r.Endpoints)
	}
	if r.Priority != 0 {
		b.SetAttributeValue("priority", cty.NumberIntVal(int64(r.Priority)))
	}
	if r.Disabled {
		b.SetAttributeValue("disabled", cty.True)
	}
	if r.Credential != "" {
		config.SetIdent(b, "credential", r.Credential)
	}
	if r.MatchBlock != nil {
		b.SetAttributeValue("match", matchBlockToCty(r.MatchBlock))
	} else if r.Condition != "" {
		b.SetAttributeValue("condition", cty.StringVal(r.Condition))
	}
	if r.Verdict != "" {
		b.SetAttributeValue("verdict", cty.StringVal(r.Verdict))
	}
	if r.Reason != "" {
		b.SetAttributeValue("reason", cty.StringVal(r.Reason))
	}
	if len(r.Approve) > 0 {
		b.SetAttributeRaw("approve", approveToTokens(r.Approve))
	}
}

// matchBlockToCty serializes a parsed match.Block into the cty
// object literal that emits as `match = { key_op = [...], ... }`.
func matchBlockToCty(b *match.Block) cty.Value {
	if b == nil || len(b.Predicates) == 0 {
		return cty.EmptyObjectVal
	}
	attrs := make(map[string]cty.Value, len(b.Predicates))
	for _, p := range b.Predicates {
		key := p.Key + p.Op.Suffix()
		vals := make([]cty.Value, len(p.Values))
		for i, v := range p.Values {
			vals[i] = cty.StringVal(v)
		}
		if len(vals) == 0 {
			attrs[key] = cty.ListValEmpty(cty.String)
		} else {
			attrs[key] = cty.TupleVal(vals)
		}
	}
	return cty.ObjectVal(attrs)
}

// approveToTokens emits the approve list as bare-name idents.
func approveToTokens(stages []config.ApproveStage) hclwrite.Tokens {
	tokens := hclwrite.Tokens{
		{Type: hclsyntax.TokenOBrack, Bytes: []byte("[")},
	}
	for i, s := range stages {
		if i > 0 {
			tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(", ")})
		}
		tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(s.Name)})
	}
	tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenCBrack, Bytes: []byte("]")})
	return tokens
}

// compileMatch decodes the cty.Value attached to `match = {...}`,
// validates each (key, op, values) triple against the family's
// declared MatchKeys, and confirms the lowered CEL compiles cleanly
// against the family's facet env. Returns the parsed *match.Block
// alongside any diagnostics — callers may use the parsed block to
// re-emit the source form via emitRule.
func compileMatch(family string, val cty.Value, ruleName string, subject hcl.Range) (*match.Block, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	specs := matchKeysFor(family)
	if len(specs) == 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Rule %q match: family %q does not support the match block", ruleName, family),
			Detail:   "This protocol family hasn't declared any match keys yet — use `condition = \"<CEL>\"` instead.",
			Subject:  &subject,
		})
		return nil, diags
	}
	block, dDiags := match.DecodeAttribute(val, specs, ruleName, subject)
	diags = append(diags, dDiags...)
	if block == nil {
		return nil, diags
	}
	expr, err := block.Compile(specs)
	if err != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Could not lower match block on rule %q", ruleName),
			Detail:   err.Error(),
			Subject:  &subject,
		})
		return nil, diags
	}
	if _, err := facet.NewMatcher(family, expr); err != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Rule %q match block compiles to invalid CEL", ruleName),
			Detail:   fmt.Sprintf("%s\nLowered expression: %s", err.Error(), expr),
			Subject:  &subject,
		})
		return nil, diags
	}
	return block, diags
}

// matchKeysFor returns the per-family match-key list by asking the
// facet's runtime via the optional MatchKeyer interface. Returns nil
// when the facet does not declare any keys (or the family is unknown
// — the caller treats both as "match block not supported here").
func matchKeysFor(family string) []match.KeySpec {
	rt := facet.Lookup(family)
	if rt == nil {
		return nil
	}
	mk, ok := rt.(match.MatchKeyer)
	if !ok {
		return nil
	}
	return mk.MatchKeys()
}

// Plugin returns the single config.Plugin that registers `rule` as
// a one-label config.KindRule. Family inference happens at validate
// time based on the resolved endpoints, so this plugin doesn't carry
// a family constraint on its endpoint refs — the inferFamily walk
// reports mixed-family endpoint sets directly.
func Plugin() *config.Plugin {
	return &config.Plugin{
		Kind: config.KindRule,
		Type: "",
		New:  func() any { return &RuleBody{} },
		Refs: []config.RefSpec{
			{Path: "Endpoint", Kind: config.KindEndpoint, Optional: true},
			{Path: "Endpoints[*]", Kind: config.KindEndpoint, Optional: true},
			{Path: "Credential", Kind: config.KindCredential, Optional: true},
		},
		Validate:    validate,
		Build:       build,
		CompileRule: func(body any, _ string) (*config.CompiledRule, []string, error) { return body.(*Rule).Compile() },
		Emit:        emitRule,
	}
}

func init() {
	config.Register(Plugin())
}
