// Package rules registers the three rule kinds: http_rule, sql_rule,
// and k8s_rule. Each rule is one policy decision targeting one or more
// endpoints of a matching protocol family.
//
// The match block is decoded as a raw cty.Value because its keys are
// family-specific (http_rule has `path`/`method`, k8s_rule has
// `resource`/`verb`/`namespace`) and each value can be either a single
// string or a list. After gohcl decoding, Build interprets the cty
// shape into a typed Match record per family.
//
// `approve` is similarly heterogeneous: a list whose elements are
// either bare-name approver references or struct stages with
// `name` / `policy` / `cache_ttl`.
//
// Rule type ↔ endpoint family compatibility is enforced via RefSpec
// FamilyConstraint.
package rules

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
)

// RuleBody is the shared shape across all three rule types. The
// match keys vary by family (interpreted in Build), but the outer
// frame is identical: endpoint targeting, priority, outcome.
type RuleBody struct {
	Endpoint  string   `hcl:"endpoint,optional"`
	Endpoints []string `hcl:"endpoints,optional"`
	Priority  int      `hcl:"priority,optional"`
	Disabled  bool     `hcl:"disabled,optional"`

	// Match is decoded raw and interpreted per family in Build. An
	// absent match block matches everything — the v14 catch-all
	// pattern (`rule "..." "X-default" { priority = -100; verdict =
	// "deny" }`) relies on this.
	Match cty.Value `hcl:"match,optional"`

	// Outcome: exactly one of verdict / approve.
	Verdict string    `hcl:"verdict,optional"`
	Reason  string    `hcl:"reason,optional"`
	Approve cty.Value `hcl:"approve,optional"`
}

// Rule is the canonical, family-stamped record stored in
// Policy.Rules[name].Body. Match is a JSON-friendly Go shape produced
// at Build time from the raw HCL object; family-specific matchers
// added when wiring runtime walk this shape.
type Rule struct {
	Name      string                `json:"name"`
	Family    string                `json:"family"` // "https" | "sql" | "k8s"
	Endpoints []string              `json:"endpoints"`
	Priority  int                   `json:"priority,omitempty"`
	Disabled  bool                  `json:"disabled,omitempty"`
	Match     map[string]any        `json:"match"`
	Verdict   string                `json:"verdict,omitempty"` // "allow" | "deny" | "" (when Approve is set)
	Reason    string                `json:"reason,omitempty"`
	Approve   []config.ApproveStage `json:"approve,omitempty"`
	// CredentialRef, if set, is the resolved bare-name reference from
	// `match = { credential = X }`. The runtime treats it as an extra
	// match predicate (request must have been dispatched against this
	// credential).
	CredentialRef string `json:"credential_ref,omitempty"`
}

// Compile lowers a built rule into the runtime-friendly *CompiledRule
// the request handler consumes. The match.Matcher is constructed
// via the facet registry so per-family quirks live with the plugin
// that owns them.
//
// Returns the compiled rule plus the list of endpoint names this
// rule attaches to.
func (r *Rule) Compile() (*config.CompiledRule, []string, error) {
	matcher, err := facet.NewMatcher(r.Family, r.Match)
	if err != nil {
		return nil, nil, fmt.Errorf("match: %w", err)
	}
	return &config.CompiledRule{
		Name:     r.Name,
		Priority: r.Priority,
		Disabled: r.Disabled,
		Match:    r.Match,
		Matcher:  matcher,
		Outcome: config.Outcome{
			Verdict: r.Verdict,
			Reason:  r.Reason,
			Approve: r.Approve,
		},
	}, r.Endpoints, nil
}

// validatedFamily defines the family + endpoint family-constraint
// for one rule type. The set of valid match keys comes from
// facet.KnownKeys at validate time so the validator and the matcher
// can't drift apart — adding a match key in a facet plugin
// automatically makes it valid here.
type validatedFamily struct {
	family           string
	endpointFamilies []string
}

// knownMatchKeys returns the per-family valid match keys as a set,
// memoized off facet.KnownKeys.
func knownMatchKeys(family string) map[string]bool {
	out := map[string]bool{}
	for _, k := range facet.KnownKeys(family) {
		out[k] = true
	}
	return out
}

func validate(body any, name string, ctx *config.BuildCtx, fam validatedFamily) hcl.Diagnostics {
	rb := body.(*RuleBody)
	var diags hcl.Diagnostics

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

	// Match keys: detect typos. An absent match block (cty.NilVal)
	// is fine — it matches every request.
	if !rb.Match.IsNull() {
		if !rb.Match.Type().IsObjectType() {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Rule %q match must be an object literal", name),
				Detail:   "Expected `match = { ... }`.",
				Subject:  &ctx.Block.DefRange,
			})
		} else {
			valid := knownMatchKeys(fam.family)
			it := rb.Match.ElementIterator()
			for it.Next() {
				k, _ := it.Element()
				key := k.AsString()
				if !valid[key] {
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  fmt.Sprintf("Unknown match key %q for %s", key, fam.family),
						Detail:   fmt.Sprintf("Valid keys for this rule type: %s.", strings.Join(facet.KnownKeys(fam.family), ", ")),
						Subject:  &ctx.Block.DefRange,
					})
				}
			}
		}
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

	matchMap := ctyObjectToMap(rb.Match)
	if matchMap == nil {
		matchMap = map[string]any{} // explicit empty match-all
	}
	r := &Rule{
		Name:      name,
		Family:    fam.family,
		Endpoints: endpoints,
		Priority:  rb.Priority,
		Disabled:  rb.Disabled,
		Match:     matchMap,
		Verdict:   rb.Verdict,
		Reason:    rb.Reason,
	}

	// Resolve `match = { credential = X }` against the symbol table —
	// this nested ref doesn't fit the standard RefSpec.Path syntax.
	if !rb.Match.IsNull() && rb.Match.Type().IsObjectType() && rb.Match.Type().HasAttribute("credential") {
		credVal := rb.Match.GetAttr("credential")
		if credVal.Type() == cty.String {
			cred := credVal.AsString()
			r.CredentialRef = cred
			if d := requireKind(ctx, cred, config.KindCredential, name, "match.credential"); d != nil {
				diags = append(diags, d)
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

// ctyObjectToMap converts the raw HCL match object to a JSON-friendly
// map. Strings, numbers, and bools become themselves; lists/tuples
// become []any; nested objects recurse. Null returns nil.
func ctyObjectToMap(v cty.Value) map[string]any {
	if v.IsNull() || !v.Type().IsObjectType() {
		return nil
	}
	out := map[string]any{}
	it := v.ElementIterator()
	for it.Next() {
		k, el := it.Element()
		out[k.AsString()] = ctyToGo(el)
	}
	return out
}

func ctyToGo(v cty.Value) any {
	if v.IsNull() {
		return nil
	}
	t := v.Type()
	switch {
	case t == cty.String:
		return v.AsString()
	case t == cty.Number:
		i, _ := v.AsBigFloat().Int64()
		return i
	case t == cty.Bool:
		return v.True()
	case t.IsObjectType() || t.IsMapType():
		return ctyObjectToMap(v)
	case t.IsTupleType() || t.IsListType() || t.IsSetType():
		var out []any
		it := v.ElementIterator()
		for it.Next() {
			_, el := it.Element()
			out = append(out, ctyToGo(el))
		}
		return out
	}
	return v.GoString()
}

// emitRule serializes a built *Rule back to HCL block body. Endpoints
// are emitted as bare-name idents (singular vs list forms preserved
// to round-trip the operator's choice). Match emits as an object
// literal; approve mixes bare-name idents and struct stages depending
// on each entry's shape.
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
	if len(r.Match) > 0 {
		b.SetAttributeRaw("match", matchToTokens(r.Match))
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

// matchToTokens emits a match map as `{ key = value, ... }`. Values
// that are bare-name refs (currently only `credential = X`) get
// emitted as identifiers, not quoted strings.
func matchToTokens(m map[string]any) hclwrite.Tokens {
	tokens := hclwrite.Tokens{
		{Type: hclsyntax.TokenOBrace, Bytes: []byte("{ ")},
	}
	first := true
	// Stable order: sorted keys.
	keys := sortedKeys(m)
	for _, k := range keys {
		if !first {
			tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(", ")})
		}
		first = false
		tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(k + " = ")})
		tokens = append(tokens, valueTokens(k, m[k])...)
	}
	tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenCBrace, Bytes: []byte(" }")})
	return tokens
}

func valueTokens(key string, v any) hclwrite.Tokens {
	// `credential = X` is a bare-name ref.
	if key == "credential" {
		if s, ok := v.(string); ok {
			return hclwrite.Tokens{{Type: hclsyntax.TokenIdent, Bytes: []byte(s)}}
		}
	}
	// Other shapes emit via hclwrite.TokensForValue from the cty form.
	cv, err := goToCty(v)
	if err != nil {
		return hclwrite.Tokens{{Type: hclsyntax.TokenIdent, Bytes: []byte("null")}}
	}
	return hclwrite.TokensForValue(cv)
}

func goToCty(v any) (cty.Value, error) {
	switch x := v.(type) {
	case nil:
		return cty.NullVal(cty.DynamicPseudoType), nil
	case string:
		return cty.StringVal(x), nil
	case bool:
		return cty.BoolVal(x), nil
	case int:
		return cty.NumberIntVal(int64(x)), nil
	case int64:
		return cty.NumberIntVal(x), nil
	case float64:
		return cty.NumberFloatVal(x), nil
	case []any:
		if len(x) == 0 {
			return cty.ListValEmpty(cty.String), nil
		}
		out := make([]cty.Value, len(x))
		for i, e := range x {
			cv, err := goToCty(e)
			if err != nil {
				return cty.NilVal, err
			}
			out[i] = cv
		}
		return cty.TupleVal(out), nil
	case map[string]any:
		out := make(map[string]cty.Value, len(x))
		for k, e := range x {
			cv, err := goToCty(e)
			if err != nil {
				return cty.NilVal, err
			}
			out[k] = cv
		}
		return cty.ObjectVal(out), nil
	}
	return cty.NilVal, fmt.Errorf("unsupported value type %T", v)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// In-place sort. Avoiding sort import here is a wash; small.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
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
// loader's validation, build, and compile paths consult the right
// match-key set and emit the right family stamp on the built Rule.
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
