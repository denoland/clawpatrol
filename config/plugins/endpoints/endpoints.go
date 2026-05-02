// Package endpoints registers every built-in endpoint plugin.
//
// An endpoint is a typed upstream binding: hosts (or RDS host /
// kubernetes server) plus the credential(s) the agent may use against
// it. The two credential-binding shapes are:
//
//   - singular  → `credential = X`
//   - dispatch  → `credentials = [{ placeholder = "...", credential = X }, ...]`
//
// Validate enforces "exactly one of" — both forms are accepted, but
// not at the same time, and a list with a single trailing
// no-placeholder entry collapses to the singular form.
package endpoints

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol-go/config"
	"github.com/denoland/clawpatrol-go/config/runtime"
)

// CredentialEntry is one row inside an endpoint's credentials list.
// Placeholder is empty for the no-placeholder fallback entry — see
// the v14 mixing rule (a trailing entry without `placeholder` is the
// fallback when no agent-provided placeholder matches). The list is
// decoded from a raw cty.Value so Placeholder can legitimately be
// absent without gocty rejecting the row.
type CredentialEntry struct {
	Placeholder string `json:"placeholder,omitempty"`
	Credential  string `json:"credential"`
}

// HTTPSEndpoint covers anything that speaks TLS-wrapped HTTP, including
// the kubernetes endpoint (which is HTTPS underneath) — but k8s has
// extra metadata (server / ca_cert / description) so it's a distinct
// endpoint type below.
type HTTPSEndpoint struct {
	Hosts          []string  `hcl:"hosts"`
	Credential     string    `hcl:"credential,optional"`
	CredentialsRaw cty.Value `hcl:"credentials,optional" json:"-"`

	// Credentials is populated by Build from CredentialsRaw. Stable
	// JSON shape for goldens.
	Credentials []CredentialEntry `json:"Credentials,omitempty"`
}

// PostgresEndpoint addresses a single RDS-or-equivalent server.
// Tunnel topologies (kubectl-portforward-ssh and friends) aren't
// supported in this iteration — operators run the gateway with
// network reachability already arranged. That field returns when
// the postgres runtime hooks land.
type PostgresEndpoint struct {
	Host           string    `hcl:"host"`
	Database       string    `hcl:"database"`
	Credential     string    `hcl:"credential,optional"`
	CredentialsRaw cty.Value `hcl:"credentials,optional" json:"-"`

	Credentials []CredentialEntry `json:"Credentials,omitempty"`
}

// KubernetesEndpoint covers self-hosted clusters (server + ca_cert)
// and managed clusters (hosts + EKS-style credential resolved at
// request time).
type KubernetesEndpoint struct {
	Hosts       []string `hcl:"hosts,optional"`
	Server      string   `hcl:"server,optional"`
	CACert      string   `hcl:"ca_cert,optional"`
	Description string   `hcl:"description,optional"`
	Credential  string   `hcl:"credential,optional"`
}

// ClickhouseHTTPSEndpoint and ClickhouseNativeEndpoint share an
// upstream cluster; rules typically attach to both via
// `endpoints = [ch-o11y-https, ch-o11y-native]`.
type ClickhouseHTTPSEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Credential string   `hcl:"credential,optional"`
}

type ClickhouseNativeEndpoint struct {
	Hosts      []string `hcl:"hosts"`
	Credential string   `hcl:"credential,optional"`
}

// Cross-cut accessors used by config.Compile. Each endpoint type
// exposes its hosts and the (placeholder, credential) bindings as a
// flat list — the singular `credential = X` form collapses to one
// entry with empty placeholder.

type credBinding struct {
	Placeholder string
	Credential  string
}

func bindings(single string, list []CredentialEntry) []credBinding {
	if single != "" && len(list) == 0 {
		return []credBinding{{Credential: single}}
	}
	out := make([]credBinding, 0, len(list))
	for _, e := range list {
		out = append(out, credBinding{Placeholder: e.Placeholder, Credential: e.Credential})
	}
	return out
}

func (e *HTTPSEndpoint) EndpointHosts() []string { return e.Hosts }
func (e *HTTPSEndpoint) EndpointCredentials() []struct {
	Placeholder string
	Credential  string
} {
	out := bindings(e.Credential, e.Credentials)
	r := make([]struct {
		Placeholder string
		Credential  string
	}, len(out))
	for i, b := range out {
		r[i] = struct {
			Placeholder string
			Credential  string
		}{b.Placeholder, b.Credential}
	}
	return r
}

func (e *PostgresEndpoint) EndpointHosts() []string { return []string{e.Host} }
func (e *PostgresEndpoint) EndpointCredentials() []struct {
	Placeholder string
	Credential  string
} {
	out := bindings(e.Credential, e.Credentials)
	r := make([]struct {
		Placeholder string
		Credential  string
	}, len(out))
	for i, b := range out {
		r[i] = struct {
			Placeholder string
			Credential  string
		}{b.Placeholder, b.Credential}
	}
	return r
}

func (e *KubernetesEndpoint) EndpointHosts() []string {
	if len(e.Hosts) > 0 {
		return e.Hosts
	}
	if e.Server != "" {
		return []string{e.Server}
	}
	return nil
}
func (e *KubernetesEndpoint) EndpointCredentials() []struct {
	Placeholder string
	Credential  string
} {
	if e.Credential == "" {
		return nil
	}
	return []struct {
		Placeholder string
		Credential  string
	}{{Credential: e.Credential}}
}

func (e *ClickhouseHTTPSEndpoint) EndpointHosts() []string { return e.Hosts }
func (e *ClickhouseHTTPSEndpoint) EndpointCredentials() []struct {
	Placeholder string
	Credential  string
} {
	if e.Credential == "" {
		return nil
	}
	return []struct {
		Placeholder string
		Credential  string
	}{{Credential: e.Credential}}
}

func (e *ClickhouseNativeEndpoint) EndpointHosts() []string { return e.Hosts }
func (e *ClickhouseNativeEndpoint) EndpointCredentials() []struct {
	Placeholder string
	Credential  string
} {
	if e.Credential == "" {
		return nil
	}
	return []struct {
		Placeholder string
		Credential  string
	}{{Credential: e.Credential}}
}

// ── Endpoint runtimes ────────────────────────────────────────────────
//
// HTTPSEndpointRuntime / PostgresEndpointRuntime are the per-protocol
// runtime types. For now they only implement PlaceholderDetector —
// the request-handling loop (HandleHTTP / HandleConn) lands in a
// follow-up commit. Wiring PlaceholderDetector early lets the
// dispatcher resolve multi-credential endpoints correctly when the
// handler swap arrives.

// HTTPSEndpointRuntime detects placeholders in an HTTP request's
// Authorization header. Postgres does the same via the StartupMessage
// password (PostgresEndpointRuntime, below).
type HTTPSEndpointRuntime struct{}

// DetectPlaceholder scans the Authorization header (and the optional
// Cookie header — some agents embed the placeholder there) for any
// of the configured candidates. Returns the first match or "".
//
// Plain-substring scan rather than a strict equality check because
// agents send placeholders embedded in `Bearer <PH>` or
// `Basic <base64(<PH>:)>` shapes; we only need to recognize that the
// agent picked one of our placeholders, not parse the auth scheme.
func (HTTPSEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil || req.Headers == nil {
		return ""
	}
	hay := req.Headers.Get("Authorization") + "\x00" + req.Headers.Get("Cookie")
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

// PostgresEndpointRuntime detects placeholders in a postgres
// StartupMessage. The wire-protocol front-end (lands in a follow-up
// commit) populates Request with a SQL meta whose Statement field
// carries the agent's submitted password verbatim before injection.
type PostgresEndpointRuntime struct{}

func (PostgresEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil || req.SQL == nil {
		return ""
	}
	hay := req.SQL.Statement
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

// Compile-time interface checks — keeps the registered Runtime field
// honest at build time so a signature drift fails the build instead
// of panicking on first request.
var (
	_ runtime.PlaceholderDetector = HTTPSEndpointRuntime{}
	_ runtime.PlaceholderDetector = PostgresEndpointRuntime{}
)

// validateBinding enforces the credential-binding invariants. The
// loader has already resolved `credential` and `credentials[*].credential`
// into the symbol table; here we only need the structural check.
func validateBinding(decoded any, kind string, name string, blockRange hcl.Range) hcl.Diagnostics {
	var diags hcl.Diagnostics
	cred, raw := readBinding(decoded)
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

func readBinding(decoded any) (string, cty.Value) {
	switch v := decoded.(type) {
	case *HTTPSEndpoint:
		return v.Credential, v.CredentialsRaw
	case *PostgresEndpoint:
		return v.Credential, v.CredentialsRaw
	}
	return "", cty.NilVal
}

// parseCredentialList walks a raw cty.Value list of objects into
// typed CredentialEntry values. Each object must have a "credential"
// attribute; "placeholder" is optional. Diagnostics surface malformed
// entries pinned to the block range — gohcl already validated the
// list shape so most errors here are about missing required fields.
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

func init() {
	// Singular `credential = X` ref via the standard RefSpec path.
	// The list-form `credentials = [...]` is a cty.Value that
	// validateMultiCred parses + validates manually below.
	singularRef := []config.RefSpec{
		{Path: "Credential", Kind: config.KindCredential, Optional: true},
	}

	multiCredValidate := func(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
		var diags hcl.Diagnostics
		diags = append(diags, validateBinding(d, "endpoint", name, ctx.Block.DefRange)...)
		_, raw := readBinding(d)
		entries, parseDiags := parseCredentialList(raw, ctx.Block.DefRange)
		diags = append(diags, parseDiags...)
		// Validate each entry's credential reference against the
		// symbol table — the standard RefSpec walker can't reach
		// into the cty list.
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
		// Stash the parsed entries on the typed struct so Build (and
		// the JSON dump path used by tests) can read them without
		// re-parsing.
		switch v := d.(type) {
		case *HTTPSEndpoint:
			v.Credentials = entries
		case *PostgresEndpoint:
			v.Credentials = entries
		}
		return diags
	}

	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "https",
		Family:   "https",
		New:      func() any { return &HTTPSEndpoint{} },
		Refs:     singularRef,
		Validate: multiCredValidate,
		Runtime:  HTTPSEndpointRuntime{},
		Build:    func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*HTTPSEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			emitCredentialBinding(b, e.Credential, e.Credentials)
		},
	})

	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "postgres",
		Family:   "sql",
		New:      func() any { return &PostgresEndpoint{} },
		Refs:     singularRef,
		Validate: multiCredValidate,
		Runtime:  PostgresEndpointRuntime{},
		Build:    func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*PostgresEndpoint)
			b.SetAttributeValue("host", cty.StringVal(e.Host))
			b.SetAttributeValue("database", cty.StringVal(e.Database))
			emitCredentialBinding(b, e.Credential, e.Credentials)
		},
	})

	config.Register(&config.Plugin{
		Kind:   config.KindEndpoint,
		Type:   "kubernetes",
		Family: "k8s",
		New:    func() any { return &KubernetesEndpoint{} },
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential, Optional: true},
		},
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*KubernetesEndpoint)
			if len(e.Hosts) > 0 {
				b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			}
			if e.Server != "" {
				b.SetAttributeValue("server", cty.StringVal(e.Server))
			}
			if e.CACert != "" {
				b.SetAttributeValue("ca_cert", cty.StringVal(e.CACert))
			}
			if e.Description != "" {
				b.SetAttributeValue("description", cty.StringVal(e.Description))
			}
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})

	config.Register(&config.Plugin{
		Kind:   config.KindEndpoint,
		Type:   "clickhouse_https",
		Family: "sql",
		New:    func() any { return &ClickhouseHTTPSEndpoint{} },
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential, Optional: true},
		},
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*ClickhouseHTTPSEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})

	config.Register(&config.Plugin{
		Kind:   config.KindEndpoint,
		Type:   "clickhouse_native",
		Family: "sql",
		New:    func() any { return &ClickhouseNativeEndpoint{} },
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential, Optional: true},
		},
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*ClickhouseNativeEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			if e.Credential != "" {
				config.SetIdent(b, "credential", e.Credential)
			}
		},
	})
}

// emitCredentialBinding writes either `credential = X` (singular) or
// `credentials = [{...}, {...}]` (multi-credential dispatch). The
// list form needs raw tokens because each entry's `credential` value
// is a bare identifier ref, not a quoted string — gocty can't emit
// the right shape via cty.ObjectVal alone.
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
		// Don't emit `placeholder = ""` — only when set.
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
