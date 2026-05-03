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

// Kind names a class of policy block. The four kinds with plugin-
// dispatched types — KindEndpoint, KindCredential, KindRule,
// KindApprover — read their type from the block's first label
// (e.g. `endpoint "https" "github-avocet"` → Type="https").
//
// KindPolicy and KindProfile are one-label blocks with fixed schemas;
// they're listed so the symbol table can record their names and detect
// collisions across the flat namespace.
type Kind string

const (
	KindEndpoint   Kind = "endpoint"
	KindCredential Kind = "credential"
	KindRule       Kind = "rule"
	KindApprover   Kind = "approver"
	KindPolicy     Kind = "policy"
	KindProfile    Kind = "profile"
	KindDevice     Kind = "device"
)

// LabelCount returns how many labels a block of this kind carries
// (excluding the kind keyword itself).
func (k Kind) LabelCount() int {
	switch k {
	case KindEndpoint, KindCredential, KindRule, KindApprover:
		return 2 // first = type, second = name
	case KindPolicy, KindProfile, KindDevice:
		return 1 // name (device's name = its IP)
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
	// struct. The loader passes the result to gohcl.DecodeBody.
	New func() any

	// Refs declares which fields on the decoded struct hold bare-name
	// references that must be resolved against the symbol table.
	Refs []RefSpec

	// Family classifies an endpoint's protocol so rule plugins can
	// constrain which endpoints they target. Set on KindEndpoint
	// plugins ("https" | "sql" | "k8s"). KindRule plugins set
	// Families to the families they accept.
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
