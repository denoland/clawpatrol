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
// condition can't be evaluated against this request (e.g.
// wrong-shaped Meta) — the matcher reports Unevaluable.
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
// inspection cap (HTTPS body, SQL statement, SSH stdin). On a request
// with Truncated set, these paths are marked as CEL unknowns via a
// partial activation (only for conditions that reference one — an
// unreferenced path cannot affect the outcome): a condition whose
// outcome depends on one evaluates Unevaluable (the unknown
// propagates virally, NaN-style),
// while a condition that resolves through &&/|| absorption on its
// other predicates still matches or no-matches honestly. The same
// paths also feed a pre-computed bool exposed via
// InspectsTruncatableFacet() — that one is purely the compile-time
// laziness signal (does any rule need the capped bytes buffered at
// all), not a verdict input.
//
// unparseablePaths names the dotted identifier paths whose activation
// values are derived by a frontend's parser and therefore left zero
// when the parser refuses the input (SQL verb / tables / functions).
// On a request with Unparseable set, these are marked unknown the
// same way. The raw statement text is intentionally NOT in this set —
// it's still populated when the parser fails, so rules that key only
// on `<facet>.statement` keep evaluating honestly.
//
// Paths must be of the form "<var>.<field>" — single-level selection
// off a top-level identifier. That's all the facets need today.
func CompileCondition(env *cel.Env, condition string, buildAct ActivationBuilder, lowercasedPaths, truncatablePaths, unparseablePaths []string) (Matcher, error) {
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
	var truncatedUnknowns []*cel.AttributePatternType
	if len(truncatablePaths) > 0 {
		paths, err := parsePaths(truncatablePaths)
		if err != nil {
			return nil, err
		}
		if inspectsTruncatable = referencesPath(ast.NativeRep().Expr(), paths); inspectsTruncatable {
			truncatedUnknowns = unknownPatterns(paths)
		}
	}
	var unparseableUnknowns []*cel.AttributePatternType
	if len(unparseablePaths) > 0 {
		paths, err := parsePaths(unparseablePaths)
		if err != nil {
			return nil, err
		}
		if referencesPath(ast.NativeRep().Expr(), paths) {
			unparseableUnknowns = unknownPatterns(paths)
		}
	}
	// OptPartialEval swaps in the partial-attribute factory so the
	// unknown patterns of a PartialVars activation are honored at
	// attribute-resolution time. The factory adds a per-attribute
	// AsPartialActivation check on every eval, so it is only enabled
	// for conditions that actually reference a truncatable or
	// parser-derived path — anything else never receives a partial
	// activation (Match only wraps when a pattern list is non-empty)
	// and keeps the default factory on the hot path.
	var progOpts []cel.ProgramOption
	if len(truncatedUnknowns)+len(unparseableUnknowns) > 0 {
		progOpts = append(progOpts, cel.EvalOptions(cel.OptPartialEval))
	}
	prog, err := env.Program(ast, progOpts...)
	if err != nil {
		return nil, fmt.Errorf("cel program: %w", err)
	}
	refs := collectReferencedVars(ast.NativeRep().Expr())
	return &celMatcher{
		prog:                prog,
		buildAct:            buildAct,
		refs:                refs,
		inspectsTruncatable: inspectsTruncatable,
		truncatedUnknowns:   truncatedUnknowns,
		unparseableUnknowns: unparseableUnknowns,
	}, nil
}

// unknownPatterns converts parsed "<var>.<field>" paths into the
// attribute patterns a partial activation uses to mark those values
// unknown. Built once at compile time; the patterns are immutable
// afterwards, so sharing them across concurrent Match calls is safe.
func unknownPatterns(paths []celPath) []*cel.AttributePatternType {
	out := make([]*cel.AttributePatternType, 0, len(paths))
	for _, p := range paths {
		out = append(out, cel.AttributePattern(p.ident).QualString(p.field))
	}
	return out
}

// MatcherReferences returns the variable names a Matcher's compiled
// program references. Matchers built by CompileCondition implement
// this; the gateway uses it (via the CelReferences interface in the
// runtime package) to decide whether body buffering is needed.
func (m *celMatcher) References() map[string]bool { return m.refs }

// InspectsTruncatableFacet reports whether the matcher's CEL
// condition reads any of the truncatablePaths declared when the
// matcher was compiled. This is the laziness signal Compile rolls
// up into CompiledEndpoint.InspectsTruncatable — wire frontends use
// it to skip buffering capped bytes no rule reads. Verdicts on
// truncated requests come from Match's Unevaluable result, not from
// this flag.
func (m *celMatcher) InspectsTruncatableFacet() bool { return m.inspectsTruncatable }

// PassThrough is a Matcher that always matches. Facets use it for
// empty conditions (catch-all rules).
type PassThrough struct{}

// Match always reports Matched.
func (PassThrough) Match(*Request) Decision { return Decision{Result: Matched} }

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
	truncatedUnknowns   []*cel.AttributePatternType
	unparseableUnknowns []*cel.AttributePatternType
}

// Match evaluates the compiled condition against req. Anything that
// prevents an honest true/false — a CEL runtime error, a result that
// depends on a facet marked unknown (truncated / unparseable), a
// wrong-shaped activation — comes back Unevaluable so the dispatcher
// fails closed instead of treating the rule as silently non-matching
// (which would let a deny rule fail open).
func (m *celMatcher) Match(req *Request) Decision {
	if m == nil || m.prog == nil {
		return unevaluable("matcher has no compiled program")
	}
	act := m.buildAct(req)
	if act == nil {
		return unevaluable("facet activation could not be built for this request")
	}
	// On a truncated / unparseable request, mark the affected facet
	// paths unknown via a partial activation. The unknowns propagate
	// virally through evaluation; &&/|| absorption still lets the
	// condition resolve when its outcome provably doesn't depend on
	// the unavailable value (false && unknown == false).
	var vars any = act
	if req != nil {
		var patterns []*cel.AttributePatternType
		if req.Truncated {
			patterns = append(patterns, m.truncatedUnknowns...)
		}
		if req.Unparseable {
			patterns = append(patterns, m.unparseableUnknowns...)
		}
		if len(patterns) > 0 {
			pv, err := cel.PartialVars(act, patterns...)
			if err != nil {
				return unevaluable("partial activation: " + err.Error())
			}
			vars = pv
		}
	}
	out, _, err := m.prog.Eval(vars)
	if types.IsUnknown(out) {
		return unevaluable("condition depends on " + unknownDetail(out.(*types.Unknown), req))
	}
	if err != nil {
		return unevaluable("evaluation error: " + err.Error())
	}
	b, ok := out.(types.Bool)
	if !ok {
		return unevaluable(fmt.Sprintf("condition yielded non-bool %v", out))
	}
	if bool(b) {
		return Decision{Result: Matched}
	}
	return Decision{Result: NoMatch}
}

// unevaluable builds the fail-closed Decision with its detail line.
func unevaluable(detail string) Decision {
	return Decision{Result: Unevaluable, Detail: detail}
}

// unknownDetail renders a CEL unknown as an operator-readable line:
// the facet paths the condition's outcome depends on, deduplicated
// and without cel-go's expression-id noise, plus why they were
// unavailable (truncated / unparseable, taken from the request
// flags that caused the partial activation).
func unknownDetail(unk *types.Unknown, req *Request) string {
	var paths []string
	seen := map[string]bool{}
	for _, id := range unk.IDs() {
		trails, _ := unk.GetAttributeTrails(id)
		for _, tr := range trails {
			// NOTE: this leans on cel-go's AttributeTrail.String()
			// ("var.field" / "var[key]" shapes) — an undocumented
			// format that a cel-go upgrade could change. The output
			// feeds the operator log only (never agent-visible
			// reasons, never test assertions), so drift is cosmetic.
			s := fmt.Sprintf("%v", tr)
			if !seen[s] {
				seen[s] = true
				paths = append(paths, s)
			}
		}
	}
	var causes []string
	if req != nil && req.Truncated {
		causes = append(causes, "bytes truncated at the inspection buffer")
	}
	if req != nil && req.Unparseable {
		causes = append(causes, "statement unparseable")
	}
	cause := strings.Join(causes, "; ")
	if cause == "" {
		cause = "unavailable"
	}
	return "facet value(s) the gateway does not have (" + cause + "): " + strings.Join(paths, ", ")
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
