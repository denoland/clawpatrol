// Package config loads and validates clawpatrol's HCL gateway config.
//
// The config has two layers. Operational fields (listen / ca_dir /
// tailscale {} / ...) live at the top of the file and decode via
// gohcl into the Gateway struct. Policy blocks (defaults / approver /
// policy / credential / endpoint / rule / profile) are dispatched to
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
// "github-avocet"` → Type="https").
//
// KindRule, KindPolicy and KindProfile are one-label blocks. KindRule
// has a single registered plugin (Type="") and infers its protocol
// family from the endpoints it targets at validate/build time. The
// other two have fixed schemas.
type Kind string

// Plugin kind constants enumerate supported config block kinds.
const (
	KindEndpoint   Kind = "endpoint"
	KindCredential Kind = "credential"
	KindRule       Kind = "rule"
	KindApprover   Kind = "approver"
	KindPolicy     Kind = "policy"
	KindProfile    Kind = "profile"
	KindTunnel     Kind = "tunnel"
)

// LabelCount returns how many labels a block of this kind carries
// (excluding the kind keyword itself).
func (k Kind) LabelCount() int {
	switch k {
	case KindEndpoint, KindCredential, KindApprover, KindTunnel:
		return 2 // first = type, second = name
	case KindRule, KindPolicy, KindProfile:
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
// For Kind != "", the attr is a bare-name reference into the symbol
// table; the loader resolves and kind-checks against the table and
// stashes the resolved name on Entity.Framework. Primitive
// (non-ref) framework attrs are reserved for future use; today
// every framework attr is a ref.
type FrameworkAttrSpec struct {
	Name     string
	Kind     Kind // ref kind; "" reserved for primitives (unused today)
	Optional bool
}

// frameworkAttrsByKind is the per-kind table of framework-level
// attrs the loader extracts before invoking each plugin. New
// cross-cutting endpoint attributes (a `timeout`, a future
// `retry_policy`, …) land as one-line additions here, with no
// plugin churn.
var frameworkAttrsByKind = map[Kind][]FrameworkAttrSpec{
	KindEndpoint: {
		{Name: "tunnel", Kind: KindTunnel, Optional: true},
	},
}

// FrameworkAttrsFor returns the framework attr specs declared for
// kind, or nil if none.
func FrameworkAttrsFor(kind Kind) []FrameworkAttrSpec {
	return frameworkAttrsByKind[kind]
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
