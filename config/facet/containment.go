package facet

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/denoland/clawpatrol/config/match"
)

// CELContrib is the CEL fragment a facet contributes to a compiled
// matcher: env options that declare its variable(s) and the Go types
// behind them, an activation builder that populates its bindings on
// the request's activation map, and the path lists CompileCondition
// needs for case-normalization and truncation-fail-close.
//
// Built-in facets return their own contribution via CELContributor.
// Family-containment composition (a k8s_rule referencing http.method)
// is performed in Compose by unioning the contribs of the rule's
// family and every ancestor declared in the containment registry.
//
// EnvOptions must NOT include shared libraries that every CEL env in
// the gateway uses (e.g. ext.Sets): Compose installs those once at
// the composition layer. Contribute only the facet-specific
// variable + native-type declarations.
//
// AddActivation writes the facet's bindings into act. It returns
// false to refuse the match (e.g. wrong Meta type for the family);
// when any contributor refuses, the composed matcher's Match returns
// false without evaluating the CEL program.
type CELContrib struct {
	EnvOptions       []cel.EnvOption
	AddActivation    func(req *match.Request, act map[string]any) bool
	LowercasedPaths  []string
	TruncatablePaths []string
}

// CELContributor is the optional interface a Runtime implements when
// it can be composed into another facet's CEL env via the
// family-containment registry. Built-in facets (http, sql, k8s) all
// implement it; plugin facets (config/extplugin) don't — they fall
// back to their own NewMatcher.
type CELContributor interface {
	CELContrib() CELContrib
}

// parents declares family-containment: each entry maps a family to
// the families whose facets it inherits. A rule of the inheriting
// family can reference any facet field its ancestors define, because
// actions of the inheriting family carry the ancestor's bindings too
// (a k8s action is an HTTPS request underneath, so it populates
// http.* as well as k8s.*).
//
// The relation is one-way: http.* fields are visible to k8s rules,
// but k8s.* fields are NOT visible to http rules. Containment is
// declared at the family layer and the matcher composer takes care
// of the rest — no per-rule plumbing.
//
// Adding a new family that wraps HTTPS (e.g. llm, future
// clickhouse_https sql-over-http) is a single edit here.
var parents = map[string][]string{
	"k8s": {"http"},
}

// Parents returns the direct parents declared for family — the
// facets whose CEL bindings a rule of this family inherits. Nil
// when family has no declared parents.
func Parents(family string) []string {
	ps := parents[family]
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, len(ps))
	copy(out, ps)
	return out
}

// Ancestors returns family's transitive parents in dependency-first
// order: each parent's own ancestors precede the parent. The result
// is dedupe'd and excludes family itself. Compose iterates this list
// to layer ancestor contributions in front of the leaf's; with one
// ancestor today the ordering is mostly a style choice, but it gives
// a deterministic shape if multi-parent containment lands later.
func Ancestors(family string) []string {
	var out []string
	seen := map[string]bool{}
	var visit func(string)
	visit = func(f string) {
		for _, p := range parents[f] {
			if seen[p] {
				continue
			}
			visit(p)
			seen[p] = true
			out = append(out, p)
		}
	}
	visit(family)
	return out
}

// Compose builds a Matcher for family + condition by unioning the
// CEL contributions of family and every ancestor in the containment
// registry. Returns ok=false when family or any ancestor doesn't
// implement CELContributor — the caller (NewMatcher) then falls back
// to Runtime.NewMatcher, which is how plugin facets keep working
// (their env is declared dynamically, not via CELContrib).
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
	builders := make([]func(*match.Request, map[string]any) bool, 0, len(contribs))
	for _, c := range contribs {
		opts = append(opts, c.EnvOptions...)
		lower = append(lower, c.LowercasedPaths...)
		trunc = append(trunc, c.TruncatablePaths...)
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
	cm, err := match.CompileCondition(env, condition, build, lower, trunc)
	if err != nil {
		return nil, true, err
	}
	return cm, true, nil
}

// contributors collects the CELContrib for family and every ancestor
// in dependency-first order (ancestors before the leaf). Returns
// ok=false when any required facet isn't registered or doesn't
// implement CELContributor.
func contributors(family string) ([]CELContrib, bool) {
	names := Ancestors(family)
	names = append(names, family)
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
