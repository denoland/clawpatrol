package match

import (
	"fmt"

	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

// ActivationBuilder builds a CEL activation (variable bindings) from
// a request. Each facet owns its own builder so it can pull the
// right fields off Request / Request.Meta. Returning nil means the
// matcher should refuse to match (e.g. wrong-shaped Meta).
type ActivationBuilder func(req *Request) map[string]any

// CompileCondition compiles a CEL condition source against env and
// returns a Matcher that evaluates the program against the activation
// built by buildAct on each call. The returned matcher is safe for
// concurrent use.
//
// The compiled expression must produce a bool — anything else is an
// error at compile time, mirroring the old per-key shape checks.
func CompileCondition(env *cel.Env, condition string, buildAct ActivationBuilder) (Matcher, error) {
	ast, issues := env.Compile(condition)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("cel compile: %w", issues.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("cel condition must yield bool, got %s", ast.OutputType())
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("cel program: %w", err)
	}
	refs := collectReferencedVars(ast.NativeRep().Expr())
	return &celMatcher{
		prog:     prog,
		buildAct: buildAct,
		refs:     refs,
	}, nil
}

// MatcherReferences returns the variable names a Matcher's compiled
// program references. Matchers built by CompileCondition implement
// this; the gateway uses it (via the CelReferences interface in the
// runtime package) to decide whether body buffering is needed.
func (m *celMatcher) References() map[string]bool { return m.refs }

// PassThrough is a Matcher that always returns true. Facets use it
// for empty conditions (catch-all rules).
type PassThrough struct{}

// Match always returns true.
func (PassThrough) Match(*Request) bool { return true }

// References reports no variable use.
func (PassThrough) References() map[string]bool { return nil }

type celMatcher struct {
	prog     cel.Program
	buildAct ActivationBuilder
	refs     map[string]bool
}

func (m *celMatcher) Match(req *Request) bool {
	if m == nil || m.prog == nil {
		return false
	}
	act := m.buildAct(req)
	if act == nil {
		return false
	}
	out, _, err := m.prog.Eval(act)
	if err != nil {
		return false
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false
	}
	return bool(b)
}

// collectReferencedVars walks the CEL AST and returns every top-level
// identifier referenced. We use this to decide whether the gateway
// needs to populate optional fields (e.g. HTTPS body / body_json)
// before evaluation.
func collectReferencedVars(e celast.Expr) map[string]bool {
	refs := map[string]bool{}
	if e == nil {
		return refs
	}
	var walk func(celast.Expr)
	walk = func(n celast.Expr) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case celast.IdentKind:
			refs[n.AsIdent()] = true
		case celast.SelectKind:
			// For x.y we only care about x; selecting fields off a
			// nested identifier doesn't add new top-level vars.
			walk(n.AsSelect().Operand())
		case celast.CallKind:
			c := n.AsCall()
			if c.Target() != nil {
				walk(c.Target())
			}
			for _, a := range c.Args() {
				walk(a)
			}
		case celast.ListKind:
			for _, el := range n.AsList().Elements() {
				walk(el)
			}
		case celast.MapKind:
			for _, en := range n.AsMap().Entries() {
				me := en.AsMapEntry()
				walk(me.Key())
				walk(me.Value())
			}
		case celast.StructKind:
			for _, f := range n.AsStruct().Fields() {
				walk(f.AsStructField().Value())
			}
		case celast.ComprehensionKind:
			c := n.AsComprehension()
			walk(c.IterRange())
			walk(c.AccuInit())
			walk(c.LoopCondition())
			walk(c.LoopStep())
			walk(c.Result())
		}
	}
	walk(e)
	return refs
}

