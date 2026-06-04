package extplugin

import (
	"fmt"

	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
)

// newPluginFacetMatcher compiles condition against a CEL environment
// that exposes the given facet name as a top-level identifier with
// dynamically-typed sub-fields. Plugin facets carry their action
// payload as a JSON object decoded into map[string]any, so a precise
// per-field type system on the gateway side would just shadow what
// the plugin already validates. Dyn typing keeps the env trivially
// generated from the manifest while still giving rule authors the
// usual `<facet>.<field>` selector syntax.
//
// streamFields names the FACET_STREAM fields on the facet. They're
// passed to match.CompileCondition as truncatablePaths so the
// fail-closed-on-truncation contract applies to plugin facets too:
// when the gateway's pullStream had to cap a stream short of EOF,
// the EvaluateAction handler sets Request.Truncated, the matcher
// marks the stream-typed paths as CEL unknowns, and any rule whose
// condition outcome depends on the capped bytes evaluates
// Unevaluable — which runtime.MatchRequest turns into a deny.
//
// The returned matcher additionally implements SubFieldReferencer
// so the gateway adapter can decide, per evaluation, which
// FACET_STREAM fields any rule on the endpoint will actually read.
//
// An empty condition yields a passthrough matcher — the same default
// every built-in facet uses for empty rule conditions.
func newPluginFacetMatcher(facetName, condition string, streamFields []string) (match.Matcher, error) {
	if facetName == "" {
		return nil, fmt.Errorf("plugin facet matcher: empty facet name")
	}
	if condition == "" {
		return match.PassThrough{}, nil
	}
	env, err := cel.NewEnv(
		cel.Variable(facetName, cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("plugin facet %q: cel env: %w", facetName, err)
	}
	buildAct := func(req *match.Request) map[string]any {
		m, ok := req.Meta.(map[string]any)
		if !ok {
			return nil
		}
		return map[string]any{facetName: m}
	}
	truncatable := make([]string, 0, len(streamFields))
	for _, f := range streamFields {
		truncatable = append(truncatable, facetName+"."+f)
	}
	// Plugin facets have no parser stage on the gateway — their action
	// payload is decoded JSON, validated by the plugin itself, not
	// parsed by a grammar that could refuse the bytes. Pass nil for
	// unparseablePaths so the Unparseable gate is a no-op for plugin
	// facet matchers.
	inner, err := match.CompileCondition(env, condition, buildAct, nil, truncatable, nil)
	if err != nil {
		return nil, err
	}
	refs := parseSubFieldRefs(env, condition, facetName)
	return &pluginMatcher{inner: inner, subFieldRefs: refs}, nil
}

// SubFieldReferencer is implemented by plugin-facet matchers to
// surface the set of facet sub-fields the compiled condition reads.
// Used by the adapter's EvaluateAction handler to decide whether to
// pull a stream-typed field in full or just enough for log-prefix.
type SubFieldReferencer interface {
	SubFieldRefs() map[string]bool
}

type pluginMatcher struct {
	inner        match.Matcher
	subFieldRefs map[string]bool
}

func (m *pluginMatcher) Match(req *match.Request) match.Decision { return m.inner.Match(req) }

// InspectsTruncatableFacet forwards the inner CEL matcher's answer —
// the compile-time laziness signal that tells the adapter whether
// any rule needs a stream-typed field pulled in full. Verdicts on
// truncated streams come from the inner matcher's Unevaluable result
// (the stream fields are marked CEL-unknown on a Truncated request).
func (m *pluginMatcher) InspectsTruncatableFacet() bool {
	return m.inner.InspectsTruncatableFacet()
}

// References preserves whatever the inner matcher reports so the
// gateway's existing body-buffering check (top-level identifier
// reachability) keeps working.
func (m *pluginMatcher) References() map[string]bool {
	if r, ok := m.inner.(interface{ References() map[string]bool }); ok {
		return r.References()
	}
	return nil
}

func (m *pluginMatcher) SubFieldRefs() map[string]bool { return m.subFieldRefs }

// parseSubFieldRefs walks condition's AST and returns the set of
// `<facet>.<field>` selector chains. Used to decide which stream
// fields a rule will read at evaluation time. Best-effort — when
// the parse fails (it shouldn't, since the condition already
// type-checked once) we return nil and the caller treats every
// stream field as referenced.
func parseSubFieldRefs(env *cel.Env, condition, facet string) map[string]bool {
	ast, iss := env.Parse(condition)
	if iss != nil && iss.Err() != nil {
		return nil
	}
	out := map[string]bool{}
	walkSelectorPaths(ast.NativeRep().Expr(), facet, out)
	return out
}

func walkSelectorPaths(e celast.Expr, facet string, out map[string]bool) {
	if e == nil {
		return
	}
	switch e.Kind() {
	case celast.SelectKind:
		sel := e.AsSelect()
		// Only single-level <facet>.<field> chains contribute. Deeper
		// chains (`smtp.headers.foo`) still record `headers` because
		// that's the field we'd need to materialize from the action
		// map; the deeper key access works on the already-decoded map.
		if op := sel.Operand(); op != nil && op.Kind() == celast.IdentKind && op.AsIdent() == facet {
			out[sel.FieldName()] = true
		}
		walkSelectorPaths(sel.Operand(), facet, out)
	case celast.CallKind:
		c := e.AsCall()
		if c.Target() != nil {
			walkSelectorPaths(c.Target(), facet, out)
		}
		for _, a := range c.Args() {
			walkSelectorPaths(a, facet, out)
		}
	case celast.ListKind:
		for _, el := range e.AsList().Elements() {
			walkSelectorPaths(el, facet, out)
		}
	case celast.MapKind:
		for _, en := range e.AsMap().Entries() {
			me := en.AsMapEntry()
			walkSelectorPaths(me.Key(), facet, out)
			walkSelectorPaths(me.Value(), facet, out)
		}
	case celast.StructKind:
		for _, f := range e.AsStruct().Fields() {
			walkSelectorPaths(f.AsStructField().Value(), facet, out)
		}
	case celast.ComprehensionKind:
		c := e.AsComprehension()
		walkSelectorPaths(c.IterRange(), facet, out)
		walkSelectorPaths(c.AccuInit(), facet, out)
		walkSelectorPaths(c.LoopCondition(), facet, out)
		walkSelectorPaths(c.LoopStep(), facet, out)
		walkSelectorPaths(c.Result(), facet, out)
	}
}
