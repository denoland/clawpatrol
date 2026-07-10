// Package config loads and validates clawpatrol's HCL gateway config.
//
// The config has two layers. Operational fields (listen /
// state_dir / tailscale {} / ...) live at the top of the file and
// decode via
// gohcl into the Gateway struct. Policy blocks (defaults / approver /
// credential / endpoint / rule / profile) are dispatched to
// plugins by their first label; each plugin owns its body schema, the
// in-memory record it builds, and (later) the runtime that handles
// requests for it.
package config

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

// Kind names a class of policy block. The plugin-dispatched two-label
// kinds — KindEndpoint, KindCredential, KindApprover, KindTunnel —
// read their type from the block's first label (e.g. `endpoint "https"
// "github-dev"` → Type="https").
//
// KindRule and KindProfile are one-label blocks. KindRule has a single
// registered plugin (Type="") and infers its protocol family from the
// endpoints it targets at validate/build time. KindProfile has a
// fixed schema.
type Kind string

// Plugin kind constants enumerate supported config block kinds.
const (
	KindEndpoint   Kind = "endpoint"
	KindCredential Kind = "credential"
	KindRule       Kind = "rule"
	KindApprover   Kind = "approver"
	KindProfile    Kind = "profile"
	KindTunnel     Kind = "tunnel"
)

// LabelCount returns how many labels a block of this kind carries
// (excluding the kind keyword itself).
func (k Kind) LabelCount() int {
	switch k {
	case KindEndpoint, KindCredential, KindApprover, KindTunnel:
		return 2 // first = type, second = name
	case KindRule, KindProfile:
		return 1 // name
	}
	return 0
}

// Plugin describes one (Kind, Type) pair — e.g. (endpoint, https) or
// (credential, bearer_token). Built-in plugins call Register at init
// time; the loader looks them up by (Kind, Type) when decoding blocks.
type Plugin struct {
	Kind Kind
	Type string

	// New returns a fresh pointer to the plugin's gohcl-tagged config
	// struct. The loader passes the result to gohcl.DecodeBody, unless
	// DecodeBody is set (see below).
	New func() any

	// DecodeBody, when set, replaces the loader's default
	// gohcl.DecodeBody call. External plugins (config/extplugin) use
	// this hook because their schema is only known at runtime — gohcl
	// requires a statically-tagged Go struct, but an external plugin
	// declares its attributes via a Manifest at startup. The hook
	// receives the body that remains after framework-attr extraction
	// and is responsible for populating target with the decoded
	// attributes (typically by stashing a cty.Value). Built-in
	// plugins leave this nil and rely on gohcl.
	DecodeBody func(body hcl.Body, ctx *hcl.EvalContext, target any) hcl.Diagnostics

	// Refs declares which fields on the decoded struct hold bare-name
	// references that must be resolved against the symbol table.
	Refs []RefSpec

	// Family classifies an endpoint's protocol so rule plugins can
	// constrain which endpoints they target. Set on KindEndpoint
	// plugins ("http" | "sql" | "k8s"). KindRule, with a single
	// unified plugin, leaves these empty — family is inferred from
	// the rule's resolved endpoints at validate/build time.
	Family   string
	Families []string

	// Validate runs after gohcl decode and after Refs are resolved.
	// It catches plugin-local invariants gohcl can't express
	// (e.g. exactly-one-of credential / credentials) and may use the
	// symbol table to resolve refs that the standard RefSpec path
	// syntax can't reach (e.g. fields inside a cty.Value attribute).
	Validate func(decoded any, name string, ctx *BuildCtx) hcl.Diagnostics

	// Build returns the canonical in-memory record stored in
	// Policy.Endpoints / .Credentials / etc. The runtime reads from
	// these, never from the raw decoded struct.
	Build func(decoded any, name string, ctx *BuildCtx) (any, hcl.Diagnostics)

	// CompileRule lowers a rule plugin's Build output into a
	// *CompiledRule + the list of endpoint names it attaches to.
	// Only set on rule plugins; nil for other kinds. Defined as a
	// callback so the lowering logic lives next to the rule plugin's
	// schema (rather than in a generic compile pass that needs an
	// interface escape hatch).
	CompileRule func(body any, name string) (*CompiledRule, []string, error)

	// Runtime is type-asserted by callers based on Kind:
	//   KindEndpoint   → runtime.EndpointRuntime
	//   KindCredential → runtime.CredentialRuntime
	//   KindApprover   → runtime.ApproverRuntime
	//   KindRule       → runtime.RuleMatcherFactory
	//   KindTunnel     → runtime.TunnelRuntime
	// nil means "schema-only; runtime not implemented" — request-time
	// dispatch reports a clear diagnostic when it tries to use one.
	Runtime any

	// Emit serializes a built entity back to HCL by populating an
	// hclwrite block body. Required for every plugin — the framework
	// has no generic reverse path that handles bare-name refs,
	// heterogeneous list shapes (credentials with optional
	// placeholders), or per-family match maps. Plugins that decode
	// nothing (zero-attribute credentials) provide a no-op Emit.
	Emit func(body any, name string, hb *hclwrite.Body)

	// Disambiguators names the HCL attrs this credential plugin
	// recognizes as dispatch discriminators when two credentials of
	// the same type bind the same endpoint within a profile. Only
	// meaningful for KindCredential plugins; left empty elsewhere.
	//
	// Each name corresponds to a string-valued attr the operator may
	// set on either the credential block itself or inline in a
	// profile's credentials list (`{ credential = X, <name> = "..." }`);
	// profile-inline values override block-side values for the same
	// `(credential, endpoint)` tuple.
	//
	// Conventional names per protocol family:
	//   - HTTP-auth (bearer_token, header_token, anthropic_*, …): "placeholder"
	//   - postgres_credential:   "user" (postgres routes by user)
	//   - clickhouse_credential: "database", "user" (either or both)
	//   - ssh_credential:        "user"
	//
	// The loader rejects any disambiguator attr (block-side or
	// profile-side) whose name is not in this list — that catches
	// e.g. `placeholder = "..."` set on a postgres credential.
	Disambiguators []string
}

// BuildCtx is what the loader hands to Validate and Build. It bundles
// the standard pre-resolved Refs (from RefSpec entries) with the
// symbol table, so plugins can resolve names embedded in shapes that
// don't fit the RefSpec.Path mini-DSL — most notably bare-name fields
// inside `match = { credential = X }` cty.Value attributes.
type BuildCtx struct {
	Refs    *Refs
	Symbols *SymbolTable
	Block   *hcl.Block // for diagnostic ranges when nothing more precise is available
}

// FrameworkAttrSpec declares an HCL attribute that the loader peels
// off a block body BEFORE the plugin's gohcl decode runs. The plugin
// never sees these attrs in its struct or schema — the framework
// owns them. Mirrors Terraform's `lifecycle {}` shape: every
// resource accepts `lifecycle` without each provider having to
// implement it.
//
// Three shapes:
//   - Kind != "" && !List : singular bare-name ref → FrameworkAttrs.Refs
//   - Kind != "" && List  : list of bare-name refs → FrameworkAttrs.RefLists
//   - Kind == ""          : primitive string       → FrameworkAttrs.Strings
type FrameworkAttrSpec struct {
	Name     string
	Kind     Kind // ref kind; "" for primitive string attrs
	Optional bool
	List     bool // when true (and Kind != ""), value is a list of bare names
}

// frameworkAttrsByKind is the per-kind table of framework-level
// attrs the loader extracts before invoking each plugin. New
// cross-cutting endpoint attributes (a `timeout`, a future
// `retry_policy`, …) land as one-line additions here, with no
// plugin churn.
var frameworkAttrsByKind = map[Kind][]FrameworkAttrSpec{
	KindEndpoint: {
		{Name: "tunnel", Kind: KindTunnel, Optional: true},
		// Free-text, human/LLM-readable note describing what this
		// endpoint is for. Surfaced in the discovery manifest.
		{Name: "description", Optional: true},
		// Per-endpoint action-log retention. Overrides the global
		// gateway.actions_keep default for this endpoint's rows.
		// time.ParseDuration format ("168h"); "0" / "off" (or any
		// zero-valued duration like "0s") keeps this endpoint's rows
		// forever. Negative values are rejected at compile.
		{Name: "retention", Optional: true},
	},
	// credential→endpoint binding lives on the credential block. A
	// credential names either a single endpoint or a list of them
	// (the singleton-or-list shape preserves the case where one
	// credential authenticates against multiple protocol endpoints
	// of the same upstream — clickhouse_https + clickhouse_native).
	//
	// `placeholder` is the HTTP-auth-family dispatch discriminator
	// peeled off as a framework attr because no HTTP credential
	// plugin's struct stores it (vs. SQL-family `user`/`database`
	// which double as auth fields on their plugin's struct).
	// Loader stashes the value in Entity.Framework.Strings;
	// per-plugin validation (Plugin.Disambiguators) rejects it on
	// types that don't list "placeholder".
	KindCredential: {
		{Name: "endpoint", Kind: KindEndpoint, Optional: true},
		{Name: "endpoints", Kind: KindEndpoint, Optional: true, List: true},
		{Name: "placeholder", Optional: true},
		// Free-text, human/LLM-readable note describing what this
		// credential is for. Surfaced in the discovery manifest.
		{Name: "description", Optional: true},
	},
}

// RefSpec declares a field on a decoded plugin struct that holds a
// bare-name reference (or a list of them) into the symbol table.
type RefSpec struct {
	// Path traverses the decoded struct. Slice elements use [*];
	// nested struct fields use dot. Examples:
	//   "Endpoint"
	//   "Endpoints[*]"
	//   "Credentials[*].Credential"
	Path string

	// Kind the resolved name must belong to.
	Kind Kind

	// FamilyConstraint, when non-empty, requires the resolved entity's
	// Family to be in this set. Used by rule plugins to require
	// endpoints of a matching protocol family. Empty = any family.
	FamilyConstraint []string

	// Optional means an empty/zero value at Path is fine. Required
	// references that resolve to "" emit a diagnostic.
	Optional bool
}
