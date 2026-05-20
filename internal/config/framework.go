package config

// Framework-level attribute extraction. The loader peels these off
// each block body before invoking the plugin's gohcl decode, so the
// plugin author writes nothing per-attr — the cross-cutting feature
// is just available everywhere the framework declares it. Adding a
// new endpoint-wide knob (`tunnel`, future `timeout`, `retry`, …)
// is a one-line addition to frameworkAttrsByKind.
//
// HCL plumbing: hcl.Body.PartialContent extracts a known set of
// named attrs and returns a `remain` body containing everything
// else. Passing `remain` to gohcl satisfies its strict-attr check
// without the plugin schema having to mention the framework attrs.

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// extractFramework runs the framework-level attr decode pass for
// one block. Returns the populated FrameworkAttrs, the remainder
// body that gohcl should decode (= original body minus the
// framework attrs), and any diagnostics from value-eval / kind-
// validation.
func extractFramework(body hcl.Body, kind Kind, evalCtx *hcl.EvalContext, table *SymbolTable) (FrameworkAttrs, hcl.Body, hcl.Diagnostics) {
	specs := frameworkAttrsByKind[kind]
	if len(specs) == 0 {
		return FrameworkAttrs{}, body, nil
	}
	schema := &hcl.BodySchema{}
	for _, s := range specs {
		schema.Attributes = append(schema.Attributes, hcl.AttributeSchema{
			Name:     s.Name,
			Required: !s.Optional,
		})
	}
	content, remain, diags := body.PartialContent(schema)
	fw := FrameworkAttrs{Refs: map[string]string{}}
	for _, s := range specs {
		attr, ok := content.Attributes[s.Name]
		if !ok {
			continue
		}
		v, evalDiags := attr.Expr.Value(evalCtx)
		diags = append(diags, evalDiags...)
		if evalDiags.HasErrors() {
			continue
		}
		if v.IsNull() {
			continue
		}
		if v.Type() != cty.String {
			rng := attr.Expr.Range()
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Invalid %s attribute", s.Name),
				Detail:   fmt.Sprintf("Expected a bare-name reference; got %s.", v.Type().FriendlyName()),
				Subject:  &rng,
			})
			continue
		}
		name := v.AsString()
		if name == "" {
			continue
		}
		if s.Kind != "" {
			if sym := table.Get(s.Kind, name); sym == nil {
				rng := attr.Expr.Range()
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Unknown %s %q", s.Kind, name),
					Detail:   fmt.Sprintf("Framework attribute %q references undeclared %s %q.", s.Name, s.Kind, name),
					Subject:  &rng,
				})
				continue
			}
		}
		fw.Refs[s.Name] = name
	}
	return fw, remain, diags
}
