// Package rules registers the three rule kinds: http_rule, sql_rule,
// and k8s_rule. Each rule is one policy decision targeting one or more
// endpoints of a matching protocol family.
//
// A rule's predicate is expressed as a single CEL string in the
// `condition` attribute. The set of variables a rule may reference
// is owned by the facet that registered the rule type (see
// config/plugins/facets/{https,sql,k8s}/).
//
// `approve` is a list whose elements are bare-name approver
// references.
//
// Rule type ↔ endpoint family compatibility is enforced via RefSpec
// FamilyConstraint.
package rules

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
)

// RuleBody is the shared shape across all three rule types. The
// match predicate is family-agnostic at the HCL layer (just a CEL
// string); the facet's *cel.Env decides which variables are valid.
type RuleBody struct {
	Endpoint  string   `hcl:"endpoint,optional"`
	Endpoints []string `hcl:"endpoints,optional"`
	Priority  int      `hcl:"priority,optional"`
	Disabled  bool     `hcl:"disabled,optional"`

	// Condition is a CEL expression evaluated against the
	// family-specific variable set. An absent / empty condition
	// matches everything — the v14 catch-all pattern (`rule "..."
	// "X-default" { priority = -100; verdict = "deny" }`) relies
	// on this.
	Condition string `hcl:"condition,optional"`

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

// validatedFamily defines the family + endpoint family-constraint
// for one rule type.
type validatedFamily struct {
	family           string
	endpointFamilies []string
}

func validate(body any, name string, ctx *config.BuildCtx, fam validatedFamily) hcl.Diagnostics {
	rb := body.(*RuleBody)
	var diags hcl.Diagnostics

	// CEL condition syntactic + type validation. Compile against
	// the facet's environment so unknown variables and result-type
	// mismatches are caught at Load time.
	if rb.Condition != "" {
		if _, err := facet.NewMatcher(fam.family, rb.Condition); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Invalid CEL condition on rule %q", name),
				Detail:   err.Error(),
				Subject:  &ctx.Block.DefRange,
			})
		}
	}

	// Exactly one of endpoint / endpoints.
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

func build(body any, name string, ctx *config.BuildCtx, fam validatedFamily) (any, hcl.Diagnostics) {
	rb := body.(*RuleBody)
	var diags hcl.Diagnostics

	endpoints := rb.Endpoints
	if rb.Endpoint != "" {
		endpoints = []string{rb.Endpoint}
	}

	r := &Rule{
		Name:       name,
		Family:     fam.family,
		Endpoints:  endpoints,
		Priority:   rb.Priority,
		Disabled:   rb.Disabled,
		Condition:  rb.Condition,
		Credential: rb.Credential,
		Verdict:    rb.Verdict,
		Reason:     rb.Reason,
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
// idents.
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
	if r.Condition != "" {
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

// PluginFor returns the config.Plugin that registers `<facet>_rule`
// as a config.KindRule. Each facet package calls this from its init()
// to install a rule type for its protocol family, so adding a new
// facet plugin doesn't require touching the rules package at all.
//
// The returned Plugin closes over the facet's identity so the rule
// loader's validation, build, and compile paths emit the right
// family stamp on the built Rule.
func PluginFor(f facet.Runtime) *config.Plugin {
	fam := validatedFamily{
		family:           f.Name(),
		endpointFamilies: f.EndpointFamilies(),
	}
	return &config.Plugin{
		Kind:     config.KindRule,
		Type:     f.RuleType(),
		Families: fam.endpointFamilies,
		New:      func() any { return &RuleBody{} },
		Refs: []config.RefSpec{
			{Path: "Endpoint", Kind: config.KindEndpoint, FamilyConstraint: fam.endpointFamilies, Optional: true},
			{Path: "Endpoints[*]", Kind: config.KindEndpoint, FamilyConstraint: fam.endpointFamilies, Optional: true},
			{Path: "Credential", Kind: config.KindCredential, Optional: true},
		},
		Validate: func(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
			return validate(d, name, ctx, fam)
		},
		Build: func(d any, name string, ctx *config.BuildCtx) (any, hcl.Diagnostics) {
			return build(d, name, ctx, fam)
		},
		CompileRule: func(body any, _ string) (*config.CompiledRule, []string, error) {
			return body.(*Rule).Compile()
		},
		Emit: emitRule,
	}
}
