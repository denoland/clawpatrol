package match

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// Op is the operator suffix on a match-block key.
//
// The grammar is `<key>_<op>` where <op> is one of `any`, `all`,
// `none`. A bare `<key>` (no suffix) is sugar for `<key>_any` so the
// shortest form (`method = "POST"`) keeps the most common semantics.
type Op int

// Operator suffixes.
const (
	// OpAny — at least one value-pattern pair matches.
	OpAny Op = iota
	// OpAll — every pattern is satisfied. For unary blobs (`statement`,
	// `name`) every pattern must match the single blob; for multi-valued
	// keys (`tables`) every pattern must hit at least one element.
	// Forbidden on unary-enum keys (`method`, `verb`).
	OpAll
	// OpNone — no value-pattern pair matches. The negation idiom.
	OpNone
)

// Suffix returns the suffix string for an op (e.g. "_any").
func (o Op) Suffix() string {
	switch o {
	case OpAny:
		return "_any"
	case OpAll:
		return "_all"
	case OpNone:
		return "_none"
	}
	return ""
}

// Arity describes how many values a request snapshot exposes for a
// given match key. Drives suffix-validity and CEL emission.
type Arity int

// Arity values.
const (
	// UnaryEnum is a single discrete value (http.method, sql.verb).
	// `_all` is rejected — a single value cannot equal multiple
	// distinct globs.
	UnaryEnum Arity = iota
	// UnaryBlob is a single string blob (sql.statement, k8s.name).
	// `_all` is allowed: every pattern must independently match the
	// blob — useful for substring stacking.
	UnaryBlob
	// MultiValued is a list of strings (sql.tables, sql.function).
	// `_all` is allowed: every pattern must hit at least one element.
	MultiValued
)

// KeySpec declares one key allowed in a `match = { ... }` block. The
// owning facet returns the per-family list via an optional MatchKeys
// method on its Runtime — facets without one disable the match block
// for their rules and operators must use the CEL `condition` form.
//
// CELRef is the dotted CEL expression that yields the value(s) for
// the key (e.g. "http.method", "sql.tables"). The grammar compiler
// emits these refs verbatim, so they must reference variables the
// facet's own *cel.Env already declares.
type KeySpec struct {
	Name   string
	CELRef string
	Arity  Arity
}

// Block is a parsed `match = { ... }` body — an ordered list of
// predicates the operator wrote. Ordering is sorted-by-key for stable
// CEL emission and deterministic golden tests; the operator's own
// declaration order isn't preserved (HCL object expressions don't
// expose it).
type Block struct {
	Predicates []Predicate
	Range      hcl.Range
}

// Predicate is one (key, op, values) triple from a match block.
type Predicate struct {
	Key    string   // e.g. "tables" — already split off the suffix
	Op     Op       // any | all | none
	Values []string // glob patterns (filepath.Match-style)
}

// DecodeAttribute decodes the cty.Value attached to `match = {...}`
// against the facet's allowed key list. Returns the parsed Block plus
// any diagnostics. A nil/empty value yields a nil Block (catch-all).
//
// The function validates each key against allowed (rejecting unknown
// names and ill-formed suffixes) and validates each value list as
// strings of syntactically valid filepath.Match globs.
func DecodeAttribute(val cty.Value, allowed []KeySpec, ruleName string, subject hcl.Range) (*Block, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	if val.IsNull() {
		return nil, nil
	}
	t := val.Type()
	if !t.IsObjectType() && !t.IsMapType() {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Rule %q match must be an object", ruleName),
			Detail:   "Use match = { method_any = [...], path_none = [...], ... }.",
			Subject:  &subject,
		})
		return nil, diags
	}

	specByName := make(map[string]KeySpec, len(allowed))
	allowedNames := make([]string, 0, len(allowed))
	for _, s := range allowed {
		specByName[s.Name] = s
		allowedNames = append(allowedNames, s.Name)
	}
	sort.Strings(allowedNames)

	attrs := val.AsValueMap()
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	block := &Block{Range: subject}
	for _, k := range keys {
		v := attrs[k]
		name, op := splitKey(k)
		spec, specOK := specByName[name]
		if !specOK {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Rule %q match: unknown key %q", ruleName, k),
				Detail:   fmt.Sprintf("Allowed keys (with optional _any/_all/_none suffix): %s.", strings.Join(allowedNames, ", ")),
				Subject:  &subject,
			})
			continue
		}
		if op == OpAll && spec.Arity == UnaryEnum {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Rule %q match.%s: _all not valid on unary-enum key %q", ruleName, k, name),
				Detail:   fmt.Sprintf("`%s` is a single discrete value; _all requires multiple distinct values. Use `%s_any` or `%s_none`.", name, name, name),
				Subject:  &subject,
			})
			continue
		}
		values, vDiags := coerceStringList(v, ruleName, k, subject)
		diags = append(diags, vDiags...)
		if len(values) == 0 {
			continue
		}
		bad := false
		for _, g := range values {
			if _, err := filepath.Match(g, ""); err != nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Rule %q match.%s: invalid glob %q", ruleName, k, g),
					Detail:   err.Error(),
					Subject:  &subject,
				})
				bad = true
			}
		}
		if bad {
			continue
		}
		block.Predicates = append(block.Predicates, Predicate{
			Key:    name,
			Op:     op,
			Values: values,
		})
	}
	if len(block.Predicates) == 0 {
		return nil, diags
	}
	return block, diags
}

// splitKey peels the operator suffix off a match-block key. A bare
// key (no recognized suffix) is treated as `_any`.
func splitKey(k string) (string, Op) {
	switch {
	case strings.HasSuffix(k, "_any"):
		return strings.TrimSuffix(k, "_any"), OpAny
	case strings.HasSuffix(k, "_all"):
		return strings.TrimSuffix(k, "_all"), OpAll
	case strings.HasSuffix(k, "_none"):
		return strings.TrimSuffix(k, "_none"), OpNone
	default:
		return k, OpAny
	}
}

func coerceStringList(v cty.Value, ruleName, key string, subject hcl.Range) ([]string, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	if v.IsNull() {
		return nil, nil
	}
	t := v.Type()
	if t == cty.String {
		return []string{v.AsString()}, nil
	}
	if t.IsListType() || t.IsTupleType() || t.IsSetType() {
		var out []string
		it := v.ElementIterator()
		for it.Next() {
			_, el := it.Element()
			if el.Type() != cty.String {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Rule %q match.%s element must be a string", ruleName, key),
					Subject:  &subject,
				})
				continue
			}
			out = append(out, el.AsString())
		}
		return out, diags
	}
	diags = append(diags, &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  fmt.Sprintf("Rule %q match.%s must be a string or list of strings", ruleName, key),
		Subject:  &subject,
	})
	return nil, diags
}

// Compile lowers the parsed Block into a CEL expression string. The
// compiled expression is suitable for the family's facet env and
// references only KeySpec.CELRef paths plus the `glob` builtin
// (registered via GlobOption).
//
// Predicates AND together. Within a predicate the suffix combines
// per-pattern globs over the request's value(s):
//
//   - UnaryEnum / UnaryBlob, _any  → glob(p1, ref) || glob(p2, ref) ...
//   - UnaryBlob,             _all  → glob(p1, ref) && glob(p2, ref) ...
//   - UnaryEnum / UnaryBlob, _none → !glob(p1, ref) && !glob(p2, ref) ...
//   - MultiValued,           _any  → ref.exists(v, glob(p1, v) || ...)
//   - MultiValued,           _all  → ref.exists(v, glob(p1, v)) && ...
//   - MultiValued,           _none → ref.all(v, !glob(p1, v) && ...)
//
// Returns "" when the block is nil/empty (catch-all).
func (b *Block) Compile(specs []KeySpec) (string, error) {
	if b == nil || len(b.Predicates) == 0 {
		return "", nil
	}
	specByName := make(map[string]KeySpec, len(specs))
	for _, s := range specs {
		specByName[s.Name] = s
	}
	parts := make([]string, 0, len(b.Predicates))
	for _, p := range b.Predicates {
		spec, ok := specByName[p.Key]
		if !ok {
			return "", fmt.Errorf("internal: unknown key %q (already validated)", p.Key)
		}
		parts = append(parts, compileOne(spec, p))
	}
	return strings.Join(parts, " && "), nil
}

func compileOne(spec KeySpec, p Predicate) string {
	ref := spec.CELRef
	quoted := make([]string, len(p.Values))
	for i, v := range p.Values {
		quoted[i] = celQuote(v)
	}
	switch spec.Arity {
	case UnaryEnum, UnaryBlob:
		switch p.Op {
		case OpAny:
			terms := make([]string, len(quoted))
			for i, q := range quoted {
				terms[i] = "glob(" + q + ", " + ref + ")"
			}
			return parenJoin(terms, " || ")
		case OpAll:
			terms := make([]string, len(quoted))
			for i, q := range quoted {
				terms[i] = "glob(" + q + ", " + ref + ")"
			}
			return parenJoin(terms, " && ")
		case OpNone:
			terms := make([]string, len(quoted))
			for i, q := range quoted {
				terms[i] = "!glob(" + q + ", " + ref + ")"
			}
			return parenJoin(terms, " && ")
		}
	case MultiValued:
		switch p.Op {
		case OpAny:
			inner := make([]string, len(quoted))
			for i, q := range quoted {
				inner[i] = "glob(" + q + ", v)"
			}
			return ref + ".exists(v, " + strings.Join(inner, " || ") + ")"
		case OpAll:
			terms := make([]string, len(quoted))
			for i, q := range quoted {
				terms[i] = ref + ".exists(v, glob(" + q + ", v))"
			}
			return parenJoin(terms, " && ")
		case OpNone:
			inner := make([]string, len(quoted))
			for i, q := range quoted {
				inner[i] = "!glob(" + q + ", v)"
			}
			return ref + ".all(v, " + strings.Join(inner, " && ") + ")"
		}
	}
	return "false"
}

func parenJoin(terms []string, sep string) string {
	if len(terms) == 1 {
		return terms[0]
	}
	return "(" + strings.Join(terms, sep) + ")"
}

// celQuote wraps s into a CEL string literal with backslash / quote /
// control-char escaping. Globs use filepath.Match — they don't carry
// CEL metacharacters — but quoting still has to escape `"` and `\`
// so the emitted CEL parses cleanly.
func celQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// MatchKeyer is the optional interface a facet implements to enable
// the declarative match-block grammar for rules of its family. The
// keys it returns are the operator-visible names (without suffix);
// the suffix machinery is shared.
type MatchKeyer interface {
	MatchKeys() []KeySpec
}
