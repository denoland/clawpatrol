package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// EnvVar is one shell variable `clawpatrol env` exports for the
// operator to source into their agent CLI's process environment.
// The Value is what actually gets set in the env: for credential
// plugins it's a placeholder that LOOKS like a real token (so the
// agent CLI's startup validation passes) — the gateway swaps in the
// real secret at MITM time via the credential plugin's InjectHTTP.
//
// For operator-declared env_pushdown { } entries, Value is either
// the literal value (for `value = "..."` form) or a unique
// placeholder substituted at MITM time (for `secret = "..."` form).
// Sensitive is true when Value is a redactable secret — used by
// `clawpatrol env`'s default human-readable output to hide bytes
// the operator chose to keep out of logs / shell history.
type EnvVar struct {
	Name        string
	Value       string
	Description string // shown as a `# comment` line above the export
	Sensitive   bool   // mask Value in `clawpatrol env --list` output
}

// EnvPushdownProvider is the optional interface a credential plugin
// implements when an agent CLI expects to read its credential out of
// a process environment variable. `clawpatrol env` walks every
// registered credential plugin's EnvVars() and prints the union as
// shell `export ...` lines.
//
// Plugins that don't have a CLI integration story (mtls / generic
// bearer / generic header) leave this unimplemented; they show up
// only in the dashboard.
type EnvPushdownProvider interface {
	EnvVars() []EnvVar
}

// EnvPushdownEntry is one operator-declared env var to inject into
// agent processes, parsed from the top-level `env_pushdown { }`
// block in the HCL config.
//
// Exactly one of SecretRef and HasLiteral is set after parse —
// declaring both or neither at the HCL level is a load-time error.
// Description is optional documentation; it shows up as a `# ...`
// comment in the `clawpatrol env` shell output and as the
// description field in the dashboard API response.
//
// SecretRef-form entries resolve their value via the secret store
// at request time; the placeholder put into the agent's process
// environment is substituted with the real secret bytes by the
// MITM HTTPS path before the request leaves the gateway. This is
// the same shape the existing telegram credential uses for its
// placeholder swap, generalized to arbitrary env-named secrets.
//
// Value-form entries (`value = "..."`) inject the literal string
// directly. Operators choose this form when the value isn't
// sensitive (`AWS_REGION = "us-east-1"`) or when the agent's SDK
// needs the real bytes in the env and request-body substitution
// isn't viable (AWS request signing computes HMACs over the secret;
// swapping placeholder bytes at MITM time can't recover the signed
// body).
type EnvPushdownEntry struct {
	Name        string
	SecretRef   string
	Literal     string
	HasLiteral  bool
	Description string

	// DeclRange points at the HCL block / attribute the entry was
	// decoded from, surfaced in error diagnostics from later passes
	// (e.g. when SecretRef points at a credential that isn't
	// declared).
	DeclRange hcl.Range
}

// IsSecret reports whether this entry's value should be resolved via
// the secret store at request time. Inverse of HasLiteral.
func (e *EnvPushdownEntry) IsSecret() bool { return e != nil && e.SecretRef != "" }

// Placeholder is the env-var value the gateway hands the agent for a
// SecretRef-form entry. The MITM HTTPS path substitutes occurrences
// of this byte sequence on outbound requests with the real secret
// bytes resolved from the secret store. The string is deterministic
// per env-var NAME so test fixtures and dashboard inspectors don't
// see drift across reloads.
//
// Format mirrors the existing credential placeholders
// (`clawpatrol-placeholder-do-not-use`) so a grep for that substring
// catches both the legacy per-credential placeholders and the
// generalized env_pushdown ones in one pass.
func (e *EnvPushdownEntry) Placeholder() string {
	if e == nil || e.Name == "" {
		return ""
	}
	return "clawpatrol-env-pushdown-" + e.Name + "-placeholder-do-not-use"
}

// envPushdownAttrSchema is the schema each `NAME = { ... }` entry in
// the env_pushdown block must satisfy. Exactly one of secret/value
// is required; description is optional documentation.
var envPushdownAttrSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "secret"},
		{Name: "value"},
		{Name: "description"},
	},
}

// decodeEnvPushdownBlock walks the body of an env_pushdown block and
// returns one EnvPushdownEntry per declared NAME. Validation:
//
//   - Each NAME must be a valid POSIX-ish env identifier
//     ([A-Za-z_][A-Za-z0-9_]*). Operators occasionally type
//     `OPENAI-KEY` instead of `OPENAI_KEY`; rejecting at load time
//     avoids the agent silently never receiving the var.
//   - Each entry must have exactly one of `secret` or `value`. Both
//     set or neither set is a load error pointing at the entry.
//   - Bare-name references (`secret = openai_key`) are rejected;
//     env_pushdown lives outside the policy symbol table, so the
//     value must be a string literal naming the credential.
func decodeEnvPushdownBlock(block *hcl.Block) ([]*EnvPushdownEntry, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	body, ok := block.Body.(*hclsyntax.Body)
	if !ok {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "env_pushdown body unsupported",
			Detail:   "env_pushdown { } must use literal HCL syntax (the loader cannot evaluate JSON-encoded variants here).",
			Subject:  &block.DefRange,
		})
		return nil, diags
	}
	if len(body.Blocks) > 0 {
		r := body.Blocks[0].DefRange()
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "env_pushdown does not accept nested blocks",
			Detail:   "Declare each env var as `NAME = { secret = \"...\" | value = \"...\" }`.",
			Subject:  &r,
		})
	}

	// Sort attribute names so emit / dump output is deterministic.
	names := make([]string, 0, len(body.Attributes))
	for name := range body.Attributes {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]*EnvPushdownEntry, 0, len(names))
	for _, name := range names {
		attr := body.Attributes[name]
		if !validEnvName(name) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid env var name in env_pushdown",
				Detail:   fmt.Sprintf("%q is not a valid POSIX env var identifier (expected [A-Za-z_][A-Za-z0-9_]*).", name),
				Subject:  attr.NameRange.Ptr(),
			})
			continue
		}
		entry, entryDiags := decodeEnvPushdownAttr(name, attr)
		diags = append(diags, entryDiags...)
		if entry != nil {
			out = append(out, entry)
		}
	}
	return out, diags
}

// decodeEnvPushdownAttr decodes one `NAME = { ... }` attribute into an
// EnvPushdownEntry. The RHS must be an object-cons expression with
// literal-string attributes; bare-name refs are explicitly rejected
// so a typo doesn't silently bind to an unrelated symbol.
func decodeEnvPushdownAttr(name string, attr *hclsyntax.Attribute) (*EnvPushdownEntry, hcl.Diagnostics) {
	var diags hcl.Diagnostics

	objExpr, ok := attr.Expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "env_pushdown entry must be an object literal",
			Detail:   fmt.Sprintf("%s must be assigned a `{ secret = \"...\" }` or `{ value = \"...\" }` object.", name),
			Subject:  attr.Expr.Range().Ptr(),
		})
		return nil, diags
	}

	synBody := &hclsyntax.Body{
		Attributes: hclsyntax.Attributes{},
		SrcRange:   attr.Expr.Range(),
		EndRange:   attr.Expr.Range(),
	}
	for _, item := range objExpr.Items {
		k, kDiags := objectKey(name, item.KeyExpr)
		diags = append(diags, kDiags...)
		if k == "" {
			continue
		}
		synBody.Attributes[k] = &hclsyntax.Attribute{
			Name:        k,
			Expr:        item.ValueExpr,
			SrcRange:    item.ValueExpr.Range(),
			NameRange:   item.KeyExpr.Range(),
			EqualsRange: item.KeyExpr.Range(),
		}
	}

	content, cDiags := synBody.Content(envPushdownAttrSchema)
	diags = append(diags, cDiags...)

	entry := &EnvPushdownEntry{Name: name, DeclRange: attr.Range()}
	gotSecret := false
	gotValue := false

	if a, ok := content.Attributes["secret"]; ok {
		s, sDiags := stringAttrValue(a, name+".secret")
		diags = append(diags, sDiags...)
		if s != "" {
			entry.SecretRef = s
			gotSecret = true
		}
	}
	if a, ok := content.Attributes["value"]; ok {
		s, sDiags := stringAttrValue(a, name+".value")
		diags = append(diags, sDiags...)
		entry.Literal = s
		entry.HasLiteral = true
		gotValue = true
	}
	if a, ok := content.Attributes["description"]; ok {
		s, sDiags := stringAttrValue(a, name+".description")
		diags = append(diags, sDiags...)
		entry.Description = s
	}

	switch {
	case gotSecret && gotValue:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "env_pushdown entry sets both `secret` and `value`",
			Detail:   fmt.Sprintf("%s must use exactly one of `secret = \"<credential>\"` or `value = \"<literal>\"`.", name),
			Subject:  attr.Expr.Range().Ptr(),
		})
		return nil, diags
	case !gotSecret && !gotValue:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "env_pushdown entry missing `secret` or `value`",
			Detail:   fmt.Sprintf("%s must declare exactly one of `secret = \"<credential>\"` or `value = \"<literal>\"`.", name),
			Subject:  attr.Expr.Range().Ptr(),
		})
		return nil, diags
	}
	return entry, diags
}

// objectKey extracts the literal attribute name from an object-cons
// key expression. Keys must be bare identifiers or quoted strings —
// dynamic keys are forbidden here because env_pushdown attribute
// names are the env-var names the agent actually sees.
func objectKey(parent string, expr hcl.Expression) (string, hcl.Diagnostics) {
	switch e := expr.(type) {
	case *hclsyntax.ObjectConsKeyExpr:
		if trav, ok := e.Wrapped.(*hclsyntax.ScopeTraversalExpr); ok {
			if len(trav.Traversal) == 1 {
				if root, ok := trav.Traversal[0].(hcl.TraverseRoot); ok {
					return root.Name, nil
				}
			}
		}
		return objectKey(parent, e.Wrapped)
	case *hclsyntax.LiteralValueExpr:
		if e.Val.Type() == cty.String {
			return e.Val.AsString(), nil
		}
	case *hclsyntax.TemplateExpr:
		if e.IsStringLiteral() {
			v, _ := e.Value(nil)
			return v.AsString(), nil
		}
	}
	return "", hcl.Diagnostics{{
		Severity: hcl.DiagError,
		Summary:  "Dynamic key in env_pushdown entry",
		Detail:   fmt.Sprintf("%s entry keys must be literal identifiers (`secret`, `value`, `description`).", parent),
		Subject:  expr.Range().Ptr(),
	}}
}

// stringAttrValue evaluates a value expression and asserts it's a
// string literal. nil EvalContext rejects any variable / function
// reference, which is what we want — env_pushdown values must be
// inert strings, not policy-symbol bare names.
func stringAttrValue(attr *hcl.Attribute, label string) (string, hcl.Diagnostics) {
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() {
		return "", diags
	}
	if val.Type() != cty.String || val.IsNull() {
		return "", hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("%s must be a string", label),
			Detail:   "Expected a literal string value.",
			Subject:  attr.Expr.Range().Ptr(),
		}}
	}
	return val.AsString(), nil
}

// validEnvName reports whether s is a syntactically valid POSIX
// environment variable name. Rejects empty / leading-digit / non-
// alphanumeric — the kernel passes envp through unchanged, but
// /bin/sh and the agent's libc startup will silently ignore names
// outside this charset, so it's better to fail at load time.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

// EnvPushdownEntriesSorted returns the entries sorted by Name.
// Callers that need declaration order should walk the slice
// directly. Sorted output is for dashboard / `clawpatrol env`
// rendering where stable, locale-independent ordering matters more
// than HCL source ordering.
func EnvPushdownEntriesSorted(entries []*EnvPushdownEntry) []*EnvPushdownEntry {
	out := make([]*EnvPushdownEntry, len(entries))
	copy(out, entries)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.Compare(out[i].Name, out[j].Name) < 0
	})
	return out
}
