// Package pools registers the single `token_pool` block kind. A pool
// groups N same-(kind, type) credentials behind one logical handle so
// an endpoint binding `credential = X` can reference the pool by name
// and have the dispatcher spread requests across underlying members
// per the pool's strategy.
//
// Use case: an operator with multiple LLM subscription credentials
// (e.g. one Claude OAuth per teammate) declares them as a pool and
// has the gateway distribute traffic across all of them rather than
// burning through a single credential's monthly quota.
//
// Scope is strictly intra-operator — every pool member is a
// credential the operator controls. There is no marketplace, no
// cross-operator transfer, no money handling. Provider terms-of-
// service may restrict shared subscription use; the gateway flags
// the pattern but does not enforce ToS.
package pools

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/config"
)

// TokenPoolBody is the gohcl-tagged decode target for a `token_pool`
// block body.
type TokenPoolBody struct {
	// Credentials is the bare-name list of credential blocks that
	// make up the pool. All members must share one (kind, type) —
	// the compile pass rejects cross-type pools because the
	// dispatcher cannot meaningfully spread, say, an Anthropic and
	// an OpenAI credential across the same endpoint.
	Credentials []string `hcl:"credentials"`

	// Strategy decides which member services each request:
	// `round_robin` (default) hands out members evenly via an
	// atomic counter; `least_loaded` picks the member with the
	// fewest in-process requests so far.
	Strategy string `hcl:"strategy,optional"`
}

// PoolMembers / PoolStrategy satisfy config.TokenPoolBody so the
// compile pass can lift the lowered values without depending on this
// package.
func (b *TokenPoolBody) PoolMembers() []string { return b.Credentials }
func (b *TokenPoolBody) PoolStrategy() string  { return b.Strategy }

func validate(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
	var diags hcl.Diagnostics
	body := d.(*TokenPoolBody)

	if len(body.Credentials) < 2 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("token_pool %q needs at least 2 members", name),
			Detail:   "A pool of one is just a credential. Reference the credential directly from the endpoint instead.",
			Subject:  &ctx.Block.DefRange,
		})
	}
	seen := map[string]bool{}
	for _, cn := range body.Credentials {
		if cn == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("token_pool %q has empty member", name),
				Subject:  &ctx.Block.DefRange,
			})
			continue
		}
		if seen[cn] {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("token_pool %q lists member %q twice", name, cn),
				Detail:   "Each credential may appear at most once in a pool — duplicate entries skew the strategy.",
				Subject:  &ctx.Block.DefRange,
			})
			continue
		}
		seen[cn] = true
	}

	switch body.Strategy {
	case "", string(config.PoolStrategyRoundRobin), string(config.PoolStrategyLeastLoaded):
		// ok
	case "exhaust_first":
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("token_pool %q: strategy %q not implemented", name, body.Strategy),
			Detail: "exhaust_first requires per-member failure tracking which v1 does not yet wire. " +
				"Use round_robin (default) or least_loaded for now.",
			Subject: &ctx.Block.DefRange,
		})
	default:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("token_pool %q: unknown strategy %q", name, body.Strategy),
			Detail:   fmt.Sprintf("Known strategies: %q, %q.", config.PoolStrategyRoundRobin, config.PoolStrategyLeastLoaded),
			Subject:  &ctx.Block.DefRange,
		})
	}
	return diags
}

func build(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	return d, nil
}

// emit serialises a built *TokenPoolBody back to HCL. Members are
// emitted as bare-name idents so the file round-trips cleanly. Member
// order is preserved from the decoded body — operators rely on it for
// round_robin determinism.
func emit(body any, _ string, b *hclwrite.Body) {
	tb := body.(*TokenPoolBody)
	if len(tb.Credentials) > 0 {
		config.SetIdentList(b, "credentials", tb.Credentials)
	}
	if tb.Strategy != "" {
		b.SetAttributeRaw("strategy", hclwrite.Tokens{
			{Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`)},
			{Type: hclsyntax.TokenQuotedLit, Bytes: []byte(tb.Strategy)},
			{Type: hclsyntax.TokenCQuote, Bytes: []byte(`"`)},
		})
	}
}

// Plugin returns the single config.Plugin that registers `token_pool`
// as a one-label config.KindTokenPool. There is no Type label — the
// dispatch behaviour is driven by the `strategy` attribute, not by a
// kind/type pair.
func Plugin() *config.Plugin {
	return &config.Plugin{
		Kind: config.KindTokenPool,
		Type: "",
		New:  func() any { return &TokenPoolBody{} },
		Refs: []config.RefSpec{
			{Path: "Credentials[*]", Kind: config.KindCredential, Optional: false},
		},
		Validate: validate,
		Build:    build,
		Emit:     emit,
	}
}

func init() {
	config.Register(Plugin())
}
