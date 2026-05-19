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
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/hostmatch"
)

// CredentialEntry is one row inside an endpoint's credentials list.
// Each entry carries up to two dispatch constraints — `Placeholder`
// (matched against the agent's wire-level discriminator string by a
// PlaceholderDetector) and `Databases` (matched against the
// agent-declared target database). Empty Placeholder = no
// placeholder constraint; empty Databases = no database constraint;
// an entry with both empty is the catch-all that matches whatever
// no other entry claimed.
type CredentialEntry struct {
	Placeholder string   `json:"placeholder,omitempty"`
	Databases   []string `json:"databases,omitempty"`
	Credential  string   `json:"credential"`
}

// bindings flattens (singular, list) into the runtime's CredBinding
// form. Singular collapses to one entry with no constraints.
func bindings(single string, list []CredentialEntry) []config.CredBinding {
	if single != "" && len(list) == 0 {
		return []config.CredBinding{{Credential: single}}
	}
	out := make([]config.CredBinding, 0, len(list))
	for _, e := range list {
		out = append(out, config.CredBinding{
			Placeholder: e.Placeholder,
			Databases:   e.Databases,
			Credential:  e.Credential,
		})
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
// attribute; dispatch constraints are optional and may be any
// combination of:
//
//   - placeholder (string): the agent's wire-level discriminator
//     string. Spelled "placeholder" (postgres / https / clickhouse) or
//     "user" (ssh) — both compile to the same CredentialEntry.Placeholder
//     field. Specifying both on one entry is an error.
//   - database (string) or databases (list of strings): the
//     agent-declared target database the entry claims. Both spellings
//     compile to CredentialEntry.Databases; specifying both on one
//     entry is an error.
//
// An entry with NO constraints is the catchall (matches whatever
// no other entry claimed). The constraint signature
// `(placeholder, sorted-databases)` must be unique within a list, and
// only one catchall is allowed.
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
				Detail:   fmt.Sprintf("Got %s; expected `{ placeholder|user|database|databases = ..., credential = ... }`.", t.FriendlyName()),
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
		hasPlaceholder := false
		if t.HasAttribute("placeholder") {
			pv := el.GetAttr("placeholder")
			if !pv.IsNull() && pv.Type() == cty.String && pv.AsString() != "" {
				entry.Placeholder = pv.AsString()
				hasPlaceholder = true
			}
		}
		if t.HasAttribute("user") {
			uv := el.GetAttr("user")
			if !uv.IsNull() && uv.Type() == cty.String && uv.AsString() != "" {
				if hasPlaceholder {
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  "credentials entry has both `placeholder` and `user`",
						Detail:   "Pick one — they're aliases for the same dispatch key.",
						Subject:  &blockRange,
					})
					continue
				}
				entry.Placeholder = uv.AsString()
			}
		}
		hasDatabase := false
		if t.HasAttribute("database") {
			dv := el.GetAttr("database")
			if !dv.IsNull() && dv.Type() == cty.String && dv.AsString() != "" {
				entry.Databases = []string{dv.AsString()}
				hasDatabase = true
			}
		}
		if t.HasAttribute("databases") {
			dsv := el.GetAttr("databases")
			if !dsv.IsNull() && (dsv.Type().IsTupleType() || dsv.Type().IsListType()) && dsv.LengthInt() > 0 {
				if hasDatabase {
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  "credentials entry has both `database` and `databases`",
						Detail:   "Pick one — `database` is the single-value form, `databases` the list form.",
						Subject:  &blockRange,
					})
					continue
				}
				dbs := make([]string, 0, dsv.LengthInt())
				dit := dsv.ElementIterator()
				for dit.Next() {
					_, dv := dit.Element()
					if dv.Type() == cty.String && dv.AsString() != "" {
						dbs = append(dbs, dv.AsString())
					}
				}
				entry.Databases = dbs
			}
		}
		out = append(out, entry)
	}
	// Enforce: each entry's constraint signature must be unique, and
	// at most one catchall (entry with no constraints) is allowed.
	// Signature combines placeholder + sorted-databases so two entries
	// scoped identically can't quietly mask each other; runtime
	// dispatch then has a unique most-specific match for any input.
	seen := map[string]bool{}
	for _, e := range out {
		sig := credentialEntrySignature(e)
		if seen[sig] {
			if e.Placeholder == "" && len(e.Databases) == 0 {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "credentials list has more than one catchall entry",
					Detail:   "An entry with no `placeholder`/`user`/`database`/`databases` is the catchall; only one is allowed.",
					Subject:  &blockRange,
				})
			} else {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("duplicate credentials dispatch constraint: %s", credentialEntryHumanSig(e)),
					Detail:   "Two entries with the same (placeholder, databases) constraint claim the same requests.",
					Subject:  &blockRange,
				})
			}
		}
		seen[sig] = true
	}
	return out, diags
}

// credentialEntryHumanSig formats a credential entry's constraint
// set for diagnostics. Mirrors the HCL the operator would have
// typed: e.g. `placeholder = "PH_ro", database = "prod"` for a
// two-constraint entry, or `databases = ["dev","qa"]` for a list.
func credentialEntryHumanSig(e CredentialEntry) string {
	var parts []string
	if e.Placeholder != "" {
		parts = append(parts, fmt.Sprintf("placeholder = %q", e.Placeholder))
	}
	switch len(e.Databases) {
	case 0:
		// nothing
	case 1:
		parts = append(parts, fmt.Sprintf("database = %q", e.Databases[0]))
	default:
		quoted := make([]string, len(e.Databases))
		for i, d := range e.Databases {
			quoted[i] = fmt.Sprintf("%q", d)
		}
		parts = append(parts, fmt.Sprintf("databases = [%s]", strings.Join(quoted, ", ")))
	}
	return strings.Join(parts, ", ")
}

// credentialEntrySignature is the constraint key used to detect
// duplicates. Sort the database list so order doesn't change the
// signature; placeholder + databases are joined with a NUL so a
// hypothetical placeholder like "x,y" can't collide with a
// databases=["x","y"] entry.
func credentialEntrySignature(e CredentialEntry) string {
	dbs := append([]string(nil), e.Databases...)
	sort.Strings(dbs)
	return e.Placeholder + "\x00" + strings.Join(dbs, "\x00")
}

// validateHosts checks the host strings the plugin body exposes via
// EndpointHosts(). It rejects malformed entries (bad ports,
// malformed wildcards) and within-endpoint duplicates. Endpoint
// plugins whose hosts come from a single field (postgres' Host,
// kubernetes' Server) also pass through here — EndpointHosts
// returns a one-element slice for them, so the same validation
// applies.
func validateHosts(d any, name string, defRange hcl.Range) hcl.Diagnostics {
	hosts := extractHostsAny(d)
	if len(hosts) == 0 {
		return nil
	}
	var diags hcl.Diagnostics
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		if err := hostmatch.ValidateHost(h); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Malformed host on endpoint %q", name),
				Detail:   fmt.Sprintf("hosts entry %q: %v", h, err),
				Subject:  &defRange,
			})
			continue
		}
		key := strings.ToLower(h)
		if _, dup := seen[key]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Duplicate host on endpoint %q", name),
				Detail:   fmt.Sprintf("hosts entry %q appears more than once", h),
				Subject:  &defRange,
			})
			continue
		}
		seen[key] = struct{}{}
	}
	return diags
}

// extractHostsAny mirrors compile.extractHosts but lives in this
// package so the Validate hooks can call it without dragging the
// internal compile pass in.
func extractHostsAny(body any) []string {
	if h, ok := body.(interface{ EndpointHosts() []string }); ok {
		return h.EndpointHosts()
	}
	return nil
}

// multiCredValidate is the shared Validate hook for endpoint plugins
// that accept both binding shapes. Validates the exclusivity invariant,
// parses the list, cross-checks each entry's credential against the
// symbol table, then stashes the parsed entries on the typed struct
// via setCredentialEntries. Also validates the endpoint's hosts list.
func multiCredValidate(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
	var diags hcl.Diagnostics
	diags = append(diags, validateHosts(d, name, ctx.Block.DefRange)...)
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
//
// `tunnel = X` is NOT here — that attribute is hoisted to the
// framework level (see config.frameworkAttrsByKind) so plugins
// don't have to declare it. The loader peels it off before gohcl
// runs and stashes the resolved name on Entity.Framework.
var singularRef = []config.RefSpec{
	{Path: "Credential", Kind: config.KindCredential, Optional: true},
}

// emitCredentialBinding writes either `credential = X` (singular) or
// `credentials = [{...}, {...}]` (multi-credential dispatch). The
// list form needs raw tokens because each entry's `credential` value
// is a bare identifier ref, not a quoted string.
//
// dispatchKey is the HCL keyword the protocol uses for the dispatch
// value — "placeholder" for postgres / https / openai_codex (where
// the agent embeds an arbitrary discriminator string in the wire
// protocol), or "user" for ssh (where the agent's username is the
// natural label). Both compile to the same CredentialEntry.Placeholder.
func emitCredentialBinding(b *hclwrite.Body, single string, list []CredentialEntry, dispatchKey string) {
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
				&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(" " + dispatchKey + " = ")},
				&hclwrite.Token{Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`)},
				&hclwrite.Token{Type: hclsyntax.TokenQuotedLit, Bytes: []byte(e.Placeholder)},
				&hclwrite.Token{Type: hclsyntax.TokenCQuote, Bytes: []byte(`"`)},
				&hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(",")},
			)
		}
		switch len(e.Databases) {
		case 0:
			// no database constraint
		case 1:
			tokens = append(tokens,
				&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(" database = ")},
				&hclwrite.Token{Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`)},
				&hclwrite.Token{Type: hclsyntax.TokenQuotedLit, Bytes: []byte(e.Databases[0])},
				&hclwrite.Token{Type: hclsyntax.TokenCQuote, Bytes: []byte(`"`)},
				&hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(",")},
			)
		default:
			tokens = append(tokens,
				&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(" databases = [")},
			)
			for i, db := range e.Databases {
				if i > 0 {
					tokens = append(tokens, &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(", ")})
				}
				tokens = append(tokens,
					&hclwrite.Token{Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`)},
					&hclwrite.Token{Type: hclsyntax.TokenQuotedLit, Bytes: []byte(db)},
					&hclwrite.Token{Type: hclsyntax.TokenCQuote, Bytes: []byte(`"`)},
				)
			}
			tokens = append(tokens,
				&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte("]")},
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
