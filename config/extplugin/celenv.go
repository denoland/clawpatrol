package extplugin

import (
	"fmt"

	"github.com/denoland/clawpatrol/config/match"
	"github.com/google/cel-go/cel"
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
// The returned Matcher's activation builder pulls the action map out
// of req.Meta (set by the EvaluateAction handler in the adapter)
// and binds it under facetName so conditions like
// `smtp.verb in ['MAIL','RCPT']` evaluate correctly.
//
// An empty condition yields a passthrough matcher — the same default
// every built-in facet uses for empty rule conditions.
func newPluginFacetMatcher(facetName, condition string) (match.Matcher, error) {
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
	return match.CompileCondition(env, condition, buildAct, nil)
}
