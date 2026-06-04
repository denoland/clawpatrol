package facet

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/denoland/clawpatrol/internal/config/match"
)

// CELContrib is the CEL fragment a facet contributes to a compiled
// matcher: env options that declare its variable(s) and the Go types
// behind them, an activation builder that populates its bindings on
// the request's activation map, and the path lists CompileCondition
// needs for case-normalization and the unevaluable-fail-close
// contract (truncated / unparseable values become CEL unknowns).
//
// Built-in facets return their own contribution via CELContributor.
// Composition (a k8s_rule referencing http.method) is performed in
// Compose by unioning the contribs of every facet the rule's family
// declares in the family→facets registry.
//
// EnvOptions must NOT include shared libraries that every CEL env in
// the gateway uses (e.g. ext.Sets): Compose installs those once at
// the composition layer. Contribute only the facet-specific
// variable + native-type declarations.
//
// AddActivation writes the facet's bindings into act. It returns
// false to refuse the match (e.g. wrong Meta type for the family);
// when any contributor refuses, the composed matcher's Match reports
// Unevaluable (fail closed) without evaluating the CEL program.
type CELContrib struct {
	EnvOptions       []cel.EnvOption
	AddActivation    func(req *match.Request, act map[string]any) bool
	LowercasedPaths  []string
	TruncatablePaths []string
	// UnparseablePaths lists the fields a wire frontend's parser
	// derives from the request bytes — when the parser refuses the
	// input, the frontend sets req.Unparseable=true and the matcher
	// marks these paths as CEL unknowns: any rule whose condition
	// outcome depends on one evaluates Unevaluable and is denied.
	// Empty for facets with no parser-failure mode (http, k8s).
	UnparseablePaths []string
}

// CELContributor is the optional interface a Runtime implements when
// it can be composed into another family's CEL env via the
// family→facets registry. Built-in facets (http, sql, k8s) all
// implement it; plugin facets (config/extplugin) don't — they fall
// back to their own NewMatcher.
type CELContributor interface {
	CELContrib() CELContrib
}

// families declares which facets each action family composes onto an
// action. An action of family X carries the bindings of every facet
// X lists, in order; a rule of family X can reference any of those
// facets in its CEL condition.
//
// There is no parent relationship — k8s does not "inherit from" http.
// Both the http and k8s families happen to add the http facet to
// their actions, because a kubernetes API call is an HTTPS request
// underneath and carries http.method / http.path / http.headers /
// http.body / http.body_json on the request snapshot. The k8s family
// adds its own k8s facet on top.
//
// Containment is implicit in the asymmetry: an http_rule can't read
// k8s.* because the http family doesn't compose the k8s facet, not
// because of a directional inheritance rule. SQL families don't
// compose http for the same reason — postgres / clickhouse_native
// wire is binary, not HTTPS.
//
// Adding a new family that wraps HTTPS (e.g. llm, future
// clickhouse_https sql-over-http) is a single edit here: list the
// facets it adds to its actions in the order they activate.
var families = map[string][]string{
	"http": {"http"},
	"sql":  {"sql"},
	"k8s":  {"http", "k8s"},
	"ssh":  {"ssh"},
}

// Facets returns the facets family composes onto an action, in
// activation order. For a family with no explicit entry the result
// falls back to [family] — a family adds at least its own eponymous
// facet — so callers (extplugin facets that ship a Runtime but no
// composition entry) still resolve cleanly.
func Facets(family string) []string {
	fs := families[family]
	if len(fs) == 0 {
		return []string{family}
	}
	out := make([]string, len(fs))
	copy(out, fs)
	return out
}

// Compose builds a Matcher for family + condition by unioning the
// CEL contributions of every facet the family composes. Returns
// ok=false when any of those facets doesn't implement CELContributor
// — the caller (NewMatcher) then falls back to Runtime.NewMatcher,
// which is how plugin facets keep working (their env is declared
// dynamically, not via CELContrib).
//
// When ok=true and err=nil the returned Matcher is ready for use.
// An empty condition short-circuits to PassThrough; the env is still
// composed so the cost shape is uniform across the empty / non-empty
// branches, but the empty-condition matcher has no CEL program to
// evaluate.
func Compose(family, condition string) (m match.Matcher, ok bool, err error) {
	contribs, ok := contributors(family)
	if !ok {
		return nil, false, nil
	}
	if condition == "" {
		return match.PassThrough{}, true, nil
	}
	opts := make([]cel.EnvOption, 0, 1+len(contribs)*2)
	// ext.Sets is shared by every built-in facet's idioms
	// (`sets.intersects(sql.tables, [...])`, `http.method in [...]`).
	// Installed once at the composition layer so individual contribs
	// don't double-register and trip cel.NewEnv's duplicate-function
	// check.
	opts = append(opts, ext.Sets())
	var lower []string
	var trunc []string
	var unparse []string
	builders := make([]func(*match.Request, map[string]any) bool, 0, len(contribs))
	for _, c := range contribs {
		opts = append(opts, c.EnvOptions...)
		lower = append(lower, c.LowercasedPaths...)
		trunc = append(trunc, c.TruncatablePaths...)
		unparse = append(unparse, c.UnparseablePaths...)
		builders = append(builders, c.AddActivation)
	}
	env, envErr := cel.NewEnv(opts...)
	if envErr != nil {
		return nil, true, fmt.Errorf("cel env: %w", envErr)
	}
	build := func(req *match.Request) map[string]any {
		act := make(map[string]any, len(builders))
		for _, b := range builders {
			if !b(req, act) {
				return nil
			}
		}
		return act
	}
	cm, err := match.CompileCondition(env, condition, build, lower, trunc, unparse)
	if err != nil {
		return nil, true, err
	}
	return cm, true, nil
}

// contributors collects the CELContrib for every facet family
// composes, in activation order. Returns ok=false when any required
// facet isn't registered or doesn't implement CELContributor.
func contributors(family string) ([]CELContrib, bool) {
	names := Facets(family)
	out := make([]CELContrib, 0, len(names))
	for _, n := range names {
		r := Lookup(n)
		if r == nil {
			return nil, false
		}
		c, ok := r.(CELContributor)
		if !ok {
			return nil, false
		}
		out = append(out, c.CELContrib())
	}
	return out, true
}
