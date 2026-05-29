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
	fw := FrameworkAttrs{
		Refs:     map[string]string{},
		RefLists: map[string][]string{},
		Strings:  map[string]string{},
	}
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
		rng := attr.Expr.Range()
		switch {
		case s.Kind == "":
			if v.Type() != cty.String {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Invalid %s attribute", s.Name),
					Detail:   fmt.Sprintf("Expected a string; got %s.", v.Type().FriendlyName()),
					Subject:  &rng,
				})
				continue
			}
			fw.Strings[s.Name] = v.AsString()
		case s.List:
			t := v.Type()
			if !t.IsTupleType() && !t.IsListType() {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Invalid %s attribute", s.Name),
					Detail:   fmt.Sprintf("Expected a list of bare-name references; got %s.", t.FriendlyName()),
					Subject:  &rng,
				})
				continue
			}
			var names []string
			it := v.ElementIterator()
			for it.Next() {
				_, el := it.Element()
				if el.Type() != cty.String {
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  fmt.Sprintf("Invalid %s element", s.Name),
						Detail:   fmt.Sprintf("Each entry must be a bare-name reference; got %s.", el.Type().FriendlyName()),
						Subject:  &rng,
					})
					continue
				}
				name := el.AsString()
				if name == "" {
					continue
				}
				if d := resolveRefName(s.Kind, name, s.Name, table, rng); d != nil {
					diags = append(diags, d)
					continue
				}
				names = append(names, name)
			}
			if len(names) > 0 {
				fw.RefLists[s.Name] = names
			}
		default:
			if v.Type() != cty.String {
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
			if d := resolveRefName(s.Kind, name, s.Name, table, rng); d != nil {
				diags = append(diags, d)
				continue
			}
			fw.Refs[s.Name] = name
		}
	}
	return fw, remain, diags
}

// resolveRefName looks up name in the symbol table under the given
// kind and returns a diagnostic if it doesn't resolve. Returns nil
// on success. With typed traversals, the eval step has already
// constrained which kind the name came from, so a missing entry
// here is an undeclared-name error rather than a wrong-kind one.
func resolveRefName(kind Kind, name, attrName string, table *SymbolTable, rng hcl.Range) *hcl.Diagnostic {
	if table.GetByQName(kind, name) != nil {
		return nil
	}
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  fmt.Sprintf("Unknown %s %q", kind, name),
		Detail:   fmt.Sprintf("Framework attribute %q references undeclared %s %q.", attrName, kind, name),
		Subject:  &rng,
	}
}
