package config

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

// Refs is the result of resolving one block's RefSpec entries. Each
// entry is keyed by the plugin's RefSpec.Path and points back to the
// resolved Symbol (so plugins can read its Family or Kind without
// re-querying the table).
//
// The loader populates this and passes it to plugin.Validate and
// plugin.Build. Plugins read Refs to wire pointers in the canonical
// record they produce.
type Refs struct {
	resolved map[string][]*Symbol
}

// Get returns every symbol resolved at path. For singular references
// this has length 0 or 1; for slice paths it can be longer. Missing
// path → nil (not an error — the loader has already emitted any
// diagnostic during resolution).
func (r *Refs) Get(path string) []*Symbol {
	if r == nil || r.resolved == nil {
		return nil
	}
	return r.resolved[path]
}

// First is a convenience for singular references.
func (r *Refs) First(path string) *Symbol {
	v := r.Get(path)
	if len(v) == 0 {
		return nil
	}
	return v[0]
}

func (r *Refs) put(path string, s *Symbol) {
	if r.resolved == nil {
		r.resolved = make(map[string][]*Symbol)
	}
	r.resolved[path] = append(r.resolved[path], s)
}

// resolveRefs walks the decoded struct, reads each RefSpec.Path,
// validates the resolved name(s) against the symbol table, and
// returns a populated Refs along with diagnostics for any unresolved
// or kind/family-mismatched references.
func resolveRefs(decoded any, name string, plugin *Plugin, table *SymbolTable, blockRange hcl.Range) (*Refs, hcl.Diagnostics) {
	refs := &Refs{}
	var diags hcl.Diagnostics
	for _, spec := range plugin.Refs {
		values, valDiags := readPath(decoded, spec.Path, blockRange)
		diags = append(diags, valDiags...)
		if len(values) == 0 && !spec.Optional {
			// Path with no entries is fine for slice paths; for
			// scalar paths readPath emits its own diagnostic when
			// the field is missing entirely. Required emptiness is
			// caught by gohcl (missing required attr) so we don't
			// double-report here.
			continue
		}
		for _, v := range values {
			if v.value == "" {
				if !spec.Optional {
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  fmt.Sprintf("Empty %s reference", spec.Kind),
						Detail:   fmt.Sprintf("Field %q in %s %q must name a declared %s.", spec.Path, plugin.Kind, name, spec.Kind),
						Subject:  v.rangePtr,
					})
				}
				continue
			}
			sym := table.Get(spec.Kind, v.value)
			if sym == nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Unknown %s %q", spec.Kind, v.value),
					Detail:   fmt.Sprintf("No %s named %q is declared in this file.", spec.Kind, v.value),
					Subject:  v.rangePtr,
				})
				continue
			}
			if len(spec.FamilyConstraint) > 0 {
				ok := false
				for _, f := range spec.FamilyConstraint {
					if sym.Family == f {
						ok = true
						break
					}
				}
				if !ok {
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  fmt.Sprintf("Incompatible endpoint family for %q", v.value),
						Detail:   fmt.Sprintf("Rule %q (%s) accepts endpoint families %v but %q is family %q.", name, plugin.Type, spec.FamilyConstraint, v.value, sym.Family),
						Subject:  v.rangePtr,
					})
					continue
				}
			}
			refs.put(spec.Path, sym)
		}
	}
	return refs, diags
}
