// Package environments hosts the built-in environment plugin
// implementations. An `environment "<type>" "<name>" { ... }` block
// declares one named push-down contribution; profiles list which
// environments apply via `environments = [type.name, ...]`. See
// internal/config/env_pushdown.go for the EnvironmentRuntime
// interface the plugin's built body implements.
package environments

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/internal/config"
)

// newer returns a New() func that allocates a fresh *T.
func newer[T any]() func() any { return func() any { return new(T) } }

// emptyEmit is the no-op Emit used by environment plugins whose body
// has no HCL attributes beyond the framework-peeled `endpoint` /
// `credential` refs.
func emptyEmit(_ any, _ string, _ *hclwrite.Body) {}

// passthrough is the trivial Build hook for environment plugins that
// don't need to look at the framework refs at build time — typically
// the ones whose body decode already captured everything the runtime
// needs.
func passthrough(decoded any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	return decoded, nil
}

// resolveEndpoint pulls the framework-peeled `endpoint = <ref>` name
// off the build context and looks the target up in the symbol table.
// Returns (nil, "", nil) when the operator didn't set the attr;
// (nil, name, diag) when the ref names something that isn't a
// declared endpoint (shouldn't happen — framework attr resolution
// already validated the kind — but defensive).
func resolveEndpoint(name string, ctx *config.BuildCtx) (*config.Symbol, string, hcl.Diagnostics) {
	if ctx == nil {
		return nil, "", nil
	}
	ref := ctx.Framework.Ref("endpoint")
	if ref == "" {
		return nil, "", nil
	}
	sym := ctx.Symbols.Get(config.KindEndpoint, ref)
	if sym == nil {
		return nil, ref, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("environment %q: unknown endpoint %q", name, ref),
			Subject:  &ctx.Block.DefRange,
		}}
	}
	return sym, ref, nil
}

// readStringAttr extracts a single string-valued attribute off an
// hcl.Body without round-tripping the block through gohcl. This lets
// an environment plugin peek at fields on a *different* plugin's
// body (e.g. postgres_environment reading the `host` attribute off
// the bound postgres endpoint) without an import cycle on the
// endpoint plugin's struct type.
//
// Returns "" when the attribute isn't set or doesn't evaluate to a
// string. Diagnostics on bad expressions are silently swallowed —
// the actual decode of the referenced block will surface them.
func readStringAttr(body hcl.Body, name string) string {
	if body == nil {
		return ""
	}
	content, _, _ := body.PartialContent(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: name}},
	})
	if content == nil {
		return ""
	}
	attr, ok := content.Attributes[name]
	if !ok {
		return ""
	}
	val, diag := attr.Expr.Value(nil)
	if diag.HasErrors() {
		return ""
	}
	if val.IsNull() {
		return ""
	}
	if val.Type().FriendlyName() != "string" {
		return ""
	}
	return val.AsString()
}

// resolveCredential is resolveEndpoint's counterpart for the
// framework-peeled `credential = <ref>` attr.
func resolveCredential(name string, ctx *config.BuildCtx) (*config.Symbol, string, hcl.Diagnostics) {
	if ctx == nil {
		return nil, "", nil
	}
	ref := ctx.Framework.Ref("credential")
	if ref == "" {
		return nil, "", nil
	}
	sym := ctx.Symbols.Get(config.KindCredential, ref)
	if sym == nil {
		return nil, ref, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("environment %q: unknown credential %q", name, ref),
			Subject:  &ctx.Block.DefRange,
		}}
	}
	return sym, ref, nil
}
