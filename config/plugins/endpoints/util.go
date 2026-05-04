// Package endpoints registers every built-in endpoint plugin.
//
// An endpoint is a typed upstream binding: hosts (or RDS host /
// kubernetes server) plus the credential(s) the agent may use against
// it. The two credential-binding shapes are:
//
//   - singular  → `credential = X`
//   - dispatch  → `credentials = [{ placeholder = "...", credential = X }, ...]`
//
// validateBinding enforces "exactly one of" — both forms are accepted,
// but not at the same time.
//
// Per-endpoint plugins live in their own file (https.go, postgres.go,
// kubernetes.go, clickhouse_https.go, clickhouse_native.go); this
// file is the cross-cutting helpers they share.
package endpoints

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
)

// CredentialEntry is one row inside an endpoint's credentials list.
// Placeholder is empty for the no-placeholder fallback entry — see
// the v14 mixing rule (a trailing entry without `placeholder` is the
// fallback when no agent-provided placeholder matches).
type CredentialEntry struct {
	Placeholder string `json:"placeholder,omitempty"`
	Credential  string `json:"credential"`
}

// bindings flattens (singular, list) into the runtime's CredBinding
// form. Singular collapses to one entry with empty placeholder.
func bindings(single string, list []CredentialEntry) []config.CredBinding {
	if single != "" && len(list) == 0 {
		return []config.CredBinding{{Credential: single}}
	}
	out := make([]config.CredBinding, 0, len(list))
	for _, e := range list {
		out = append(out, config.CredBinding{Placeholder: e.Placeholder, Credential: e.Credential})
	}
	return out
}

func singleBinding(name string) []config.CredBinding {
	if name == "" {
		return nil
	}
	return []config.CredBinding{{Credential: name}}
}

// hasCredentialsRaw is the interface the multi-credential validator
// uses to read both binding fields off any endpoint type that
// supports the dispatch shape (HTTPS, postgres). Other endpoint types
// don't satisfy this and skip multiCredValidate.
type hasCredentialsRaw interface {
	credentialAndRaw() (string, cty.Value)
	setCredentialEntries([]CredentialEntry)
}

// validateBinding enforces the credential-binding invariants. The
// loader has already resolved `credential` and `credentials[*].credential`
// into the symbol table; here we only need the structural check.
func validateBinding(decoded any, kind string, name string, blockRange hcl.Range) hcl.Diagnostics {
	var diags hcl.Diagnostics
	hcr, ok := decoded.(hasCredentialsRaw)
	if !ok {
		return nil
	}
	cred, raw := hcr.credentialAndRaw()
	hasList := !raw.IsNull() && (raw.Type().IsTupleType() || raw.Type().IsListType()) && raw.LengthInt() > 0
	if cred != "" && hasList {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Both credential and credentials set on %s %q", kind, name),
			Detail:   "Use exactly one of `credential = X` (singular) or `credentials = [...]` (multi-credential dispatch).",
			Subject:  &blockRange,
		})
	}
	return diags
}

// parseCredentialList walks a raw cty.Value list of objects into
// typed CredentialEntry values. Each object must have a "credential"
// attribute; "placeholder" is optional.
func parseCredentialList(raw cty.Value, blockRange hcl.Range) ([]CredentialEntry, hcl.Diagnostics) {
	if raw.IsNull() {
		return nil, nil
	}
	if !raw.Type().IsTupleType() && !raw.Type().IsListType() {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "credentials must be a list",
			Detail:   fmt.Sprintf("Got %s.", raw.Type().FriendlyName()),
			Subject:  &blockRange,
		}}
	}
	var out []CredentialEntry
	var diags hcl.Diagnostics
	it := raw.ElementIterator()
	for it.Next() {
		_, el := it.Element()
		t := el.Type()
		if !t.IsObjectType() {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "credentials list element must be an object",
				Detail:   fmt.Sprintf("Got %s; expected `{ placeholder = ..., credential = ... }`.", t.FriendlyName()),
				Subject:  &blockRange,
			})
			continue
		}
		entry := CredentialEntry{}
		if t.HasAttribute("credential") {
			cv := el.GetAttr("credential")
			if cv.Type() == cty.String {
				entry.Credential = cv.AsString()
			}
		}
		if entry.Credential == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "credentials list element missing credential",
				Subject:  &blockRange,
			})
			continue
		}
		if t.HasAttribute("placeholder") {
			pv := el.GetAttr("placeholder")
			if !pv.IsNull() && pv.Type() == cty.String {
				entry.Placeholder = pv.AsString()
			}
		}
		out = append(out, entry)
	}
	return out, diags
}

// multiCredValidate is the shared Validate hook for endpoint plugins
// that accept both binding shapes. Validates the exclusivity invariant,
// parses the list, cross-checks each entry's credential against the
// symbol table, then stashes the parsed entries on the typed struct
// via setCredentialEntries.
func multiCredValidate(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
	var diags hcl.Diagnostics
	diags = append(diags, validateBinding(d, "endpoint", name, ctx.Block.DefRange)...)
	hcr, ok := d.(hasCredentialsRaw)
	if !ok {
		return diags
	}
	_, raw := hcr.credentialAndRaw()
	entries, parseDiags := parseCredentialList(raw, ctx.Block.DefRange)
	diags = append(diags, parseDiags...)
	for _, e := range entries {
		if ctx.Symbols.Get(config.KindCredential, e.Credential) != nil {
			continue
		}
		if alt := ctx.Symbols.GetAny(e.Credential); alt != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Wrong reference kind for %q", e.Credential),
				Detail:   fmt.Sprintf("endpoint %q credentials list expects a credential but %q is a %s.", name, e.Credential, alt.Kind),
				Subject:  &ctx.Block.DefRange,
			})
		} else {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Unknown credential %q", e.Credential),
				Detail:   fmt.Sprintf("endpoint %q credentials list references undeclared credential %q.", name, e.Credential),
				Subject:  &ctx.Block.DefRange,
			})
		}
	}
	hcr.setCredentialEntries(entries)
	return diags
}

// passthroughBuild is the Build hook for endpoint plugins that don't
// derive any record beyond their decoded body.
func passthroughBuild(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	return d, nil
}

// singularRef is the standard `credential = X` ref-spec used by every
// endpoint plugin. Kind=KindCredential, Optional so deny-only
// passthrough endpoints can omit it.
var singularRef = []config.RefSpec{
	{Path: "Credential", Kind: config.KindCredential, Optional: true},
}

// emitCredentialBinding writes either `credential = X` (singular) or
// `credentials = [{...}, {...}]` (multi-credential dispatch). The
// list form needs raw tokens because each entry's `credential` value
// is a bare identifier ref, not a quoted string.
func emitCredentialBinding(b *hclwrite.Body, single string, list []CredentialEntry) {
	if len(list) == 0 {
		if single != "" {
			config.SetIdent(b, "credential", single)
		}
		return
	}
	tokens := hclwrite.Tokens{
		{Type: hclsyntax.TokenOBrack, Bytes: []byte("[")},
		{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")},
	}
	for _, e := range list {
		tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte("    {")})
		if e.Placeholder != "" {
			tokens = append(tokens,
				&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(" placeholder = ")},
				&hclwrite.Token{Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`)},
				&hclwrite.Token{Type: hclsyntax.TokenQuotedLit, Bytes: []byte(e.Placeholder)},
				&hclwrite.Token{Type: hclsyntax.TokenCQuote, Bytes: []byte(`"`)},
				&hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(",")},
			)
		}
		tokens = append(tokens,
			&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(" credential = ")},
			&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(e.Credential)},
			&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(" }")},
			&hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(",")},
			&hclwrite.Token{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")},
		)
	}
	tokens = append(tokens,
		&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte("  ")},
		&hclwrite.Token{Type: hclsyntax.TokenCBrack, Bytes: []byte("]")},
	)
	b.SetAttributeRaw("credentials", tokens)
}
