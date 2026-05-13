package match

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
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
//
// lowercasedPaths names the dotted identifier paths (e.g.
// "http.method", "sql.verb") whose got-values the facet guarantees to
// be lowercase at activation time. CompileCondition walks the AST and
// lowercases every string literal that's compared against one of
// these paths via ==, !=, in, startsWith, endsWith, or contains. The
// normalization happens once at compile time, so case-insensitive
// rule sources like `http.method == "POST"` keep working without any
// per-match cost.
//
// truncatablePaths names the dotted identifier paths whose activation
// values come from bytes a wire frontend may truncate at its
// inspection cap (HTTPS body, SQL statement). CompileCondition walks
// the AST and pre-computes a single bool: does this condition read
// any of those paths? The result is exposed via
// InspectsTruncatableFacet() so the dispatcher can fail-close on a
// truncated request without re-walking the AST per match.
//
// Paths must be of the form "<var>.<field>" — single-level selection
// off a top-level identifier. That's all the facets need today.
func CompileCondition(env *cel.Env, condition string, buildAct ActivationBuilder, lowercasedPaths, truncatablePaths []string) (Matcher, error) {
	ast, issues := env.Compile(condition)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("cel compile: %w", issues.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("cel condition must yield bool, got %s", ast.OutputType())
	}
	if len(lowercasedPaths) > 0 {
		paths, err := parsePaths(lowercasedPaths)
		if err != nil {
			return nil, err
		}
		normalizeWantLiterals(ast.NativeRep().Expr(), paths)
	}
	var inspectsTruncatable bool
	if len(truncatablePaths) > 0 {
		paths, err := parsePaths(truncatablePaths)
		if err != nil {
			return nil, err
		}
		inspectsTruncatable = referencesPath(ast.NativeRep().Expr(), paths)
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("cel program: %w", err)
	}
	refs := collectReferencedVars(ast.NativeRep().Expr())
	return &celMatcher{
		prog:                prog,
		buildAct:            buildAct,
		refs:                refs,
		inspectsTruncatable: inspectsTruncatable,
	}, nil
}

// MatcherReferences returns the variable names a Matcher's compiled
// program references. Matchers built by CompileCondition implement
// this; the gateway uses it (via the CelReferences interface in the
// runtime package) to decide whether body buffering is needed.
func (m *celMatcher) References() map[string]bool { return m.refs }

// InspectsTruncatableFacet reports whether the matcher's CEL
// condition reads any of the truncatablePaths declared when the
// matcher was compiled. Pre-computed at compile time so the
// dispatcher's fail-closed check is O(1) per match.
func (m *celMatcher) InspectsTruncatableFacet() bool { return m.inspectsTruncatable }

// PassThrough is a Matcher that always returns true. Facets use it
// for empty conditions (catch-all rules).
type PassThrough struct{}

// Match always returns true.
func (PassThrough) Match(*Request) bool { return true }

// References reports no variable use.
func (PassThrough) References() map[string]bool { return nil }

// InspectsTruncatableFacet reports false: a catch-all rule has no
// CEL condition, so by definition it reads nothing that could be
// truncated. The dispatcher will fire it normally on a truncated
// request — operators can still attach a default-deny verdict to it.
func (PassThrough) InspectsTruncatableFacet() bool { return false }

type celMatcher struct {
	prog                cel.Program
	buildAct            ActivationBuilder
	refs                map[string]bool
	inspectsTruncatable bool
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

// celPath is the parsed form of a "<var>.<field>" entry shared by
// the lowercasedPaths and truncatablePaths arguments to
// CompileCondition.
type celPath struct {
	ident string
	field string
}

func parsePaths(paths []string) ([]celPath, error) {
	out := make([]celPath, 0, len(paths))
	for _, p := range paths {
		ident, field, ok := strings.Cut(p, ".")
		if !ok || ident == "" || field == "" || strings.Contains(field, ".") {
			return nil, fmt.Errorf("cel path %q must be of the form \"<var>.<field>\"", p)
		}
		out = append(out, celPath{ident: ident, field: field})
	}
	return out, nil
}

// referencesPath walks the AST and returns true when any node is a
// single-level Select expression off a top-level Ident whose
// (ident, field) matches any entry in paths. Used by CompileCondition
// to detect whether a condition reads a truncation-affected field.
func referencesPath(root celast.Expr, paths []celPath) bool {
	if root == nil || len(paths) == 0 {
		return false
	}
	var found bool
	var walk func(celast.Expr)
	walk = func(n celast.Expr) {
		if found || n == nil {
			return
		}
		switch n.Kind() {
		case celast.SelectKind:
			sel := n.AsSelect()
			op := sel.Operand()
			if op != nil && op.Kind() == celast.IdentKind {
				ident := op.AsIdent()
				field := sel.FieldName()
				for _, p := range paths {
					if p.ident == ident && p.field == field {
						found = true
						return
					}
				}
			}
			walk(sel.Operand())
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
	walk(root)
	return found
}

// normalizeWantLiterals walks the AST and lowercases string literals
// compared against any of the declared lowercase paths. The mutation
// happens in place via SetKindCase, which preserves node IDs (and
// therefore the type-check metadata cel.Program relies on).
//
// Recognised shapes — for each, the literal is normalized:
//
//	<path> == "X"           // and the symmetric "X" == <path>
//	<path> != "X"           // and the symmetric "X" != <path>
//	<path> in ["X", "Y"]    // every string literal in the list
//	<path>.startsWith("X")  // member-call args
//	<path>.endsWith("X")
//	<path>.contains("X")
//
// matches() is deliberately not normalized — its argument is a regex,
// where case classes like `[A-Z]` are meaningful and the operator can
// opt into case-insensitivity with `(?i)`.
func normalizeWantLiterals(root celast.Expr, paths []celPath) {
	if root == nil || len(paths) == 0 {
		return
	}
	var walk func(celast.Expr)
	walk = func(n celast.Expr) {
		if n == nil {
			return
		}
		if n.Kind() == celast.CallKind {
			c := n.AsCall()
			switch c.FunctionName() {
			case operators.Equals, operators.NotEquals:
				args := c.Args()
				if len(args) == 2 {
					if matchesPath(args[0], paths) {
						lowercaseStringLiteral(args[1])
					} else if matchesPath(args[1], paths) {
						lowercaseStringLiteral(args[0])
					}
				}
			case operators.In:
				args := c.Args()
				if len(args) == 2 && matchesPath(args[0], paths) && args[1].Kind() == celast.ListKind {
					for _, el := range args[1].AsList().Elements() {
						lowercaseStringLiteral(el)
					}
				}
			case "startsWith", "endsWith", "contains":
				if c.IsMemberFunction() && matchesPath(c.Target(), paths) {
					for _, a := range c.Args() {
						lowercaseStringLiteral(a)
					}
				}
			}
		}
		// Recurse so we hit comparisons composed under && / || / ?: /
		// inside list literals, comprehensions, etc.
		switch n.Kind() {
		case celast.CallKind:
			c := n.AsCall()
			if c.Target() != nil {
				walk(c.Target())
			}
			for _, a := range c.Args() {
				walk(a)
			}
		case celast.SelectKind:
			walk(n.AsSelect().Operand())
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
			cm := n.AsComprehension()
			walk(cm.IterRange())
			walk(cm.AccuInit())
			walk(cm.LoopCondition())
			walk(cm.LoopStep())
			walk(cm.Result())
		}
	}
	walk(root)
}

// matchesPath reports whether e is a single-level Select expression
// off a top-level Ident whose (ident, field) matches any of paths.
func matchesPath(e celast.Expr, paths []celPath) bool {
	if e == nil || e.Kind() != celast.SelectKind {
		return false
	}
	sel := e.AsSelect()
	op := sel.Operand()
	if op == nil || op.Kind() != celast.IdentKind {
		return false
	}
	ident := op.AsIdent()
	field := sel.FieldName()
	for _, p := range paths {
		if p.ident == ident && p.field == field {
			return true
		}
	}
	return false
}

// lowercaseStringLiteral rewrites e in place into a lowercased string
// literal when it currently is a string literal. Non-string literals
// and non-literals are left alone — a rule that compares a lowercase
// field to a dynamic value (e.g. a header lookup) has no static
// want-value to normalize at compile time.
func lowercaseStringLiteral(e celast.Expr) {
	if e == nil || e.Kind() != celast.LiteralKind {
		return
	}
	v := e.AsLiteral()
	s, ok := v.(types.String)
	if !ok {
		return
	}
	lower := strings.ToLower(string(s))
	if lower == string(s) {
		return
	}
	fac := celast.NewExprFactory()
	e.SetKindCase(fac.NewLiteral(e.ID(), types.String(lower)))
}
