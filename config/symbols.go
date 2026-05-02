package config

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

// Symbol is one entry in the flat namespace shared across all named
// kinds (endpoint, credential, rule, approver, policy, profile).
type Symbol struct {
	Name   string
	Kind   Kind
	Type   string // "" for one-label kinds
	Family string // for endpoints: "https"|"sql"|"k8s"; "" otherwise
	Block  *hcl.Block
}

// Range is the block's declaration range — handy as a diagnostic
// fallback when the loader doesn't have a more precise pointer.
func (s *Symbol) Range() hcl.Range {
	return s.Block.DefRange
}

// SymbolTable is the indexed version of every named block in the
// file, populated in pass 1.
//
// Names are unique WITHIN a kind, not globally — the v14 example
// legitimately reuses names across kinds (e.g. `slack-avocet` is both
// a credential and an endpoint; `notion-archive` is both an approver
// and a rule). The single eval-context variable map is fine even with
// cross-kind collisions because both occurrences evaluate to the same
// string ("slack-avocet"); the RefSpec.Kind on the consuming field is
// what disambiguates which sibling is meant.
type SymbolTable struct {
	byKey    map[symKey]*Symbol
	byKind   map[Kind][]*Symbol
	byName   map[string]*Symbol  // O(1) cross-kind lookup for diagnostics
	allNames map[string]struct{} // for the eval context
}

type symKey struct {
	Kind Kind
	Name string
}

// Get returns the symbol with (kind, name), or nil. Used by ref
// resolution to validate bare-name references against the expected
// kind.
func (t *SymbolTable) Get(kind Kind, name string) *Symbol {
	if t == nil {
		return nil
	}
	return t.byKey[symKey{Kind: kind, Name: name}]
}

// GetAny returns ANY symbol with the given name, regardless of kind.
// O(1) — used by diagnostics that want to disambiguate "unknown name"
// from "name exists, wrong kind."
func (t *SymbolTable) GetAny(name string) *Symbol {
	if t == nil {
		return nil
	}
	return t.byName[name]
}

// All returns every symbol of the given kind, in deterministic
// (declaration) order. Used by the loader's pass-2 walk.
func (t *SymbolTable) All(kind Kind) []*Symbol {
	if t == nil {
		return nil
	}
	return t.byKind[kind]
}

// AllNames returns every declared name (deduplicated across kinds).
// Used to populate the hcl.EvalContext that turns bare identifiers
// into string values.
func (t *SymbolTable) AllNames() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.allNames))
	for n := range t.allNames {
		out = append(out, n)
	}
	return out
}

// blockKinds is the set of block keywords the loader recognizes at
// the top level of a policy file. Anything else flows through to
// gohcl's operational decode.
var blockKinds = map[string]Kind{
	"endpoint":   KindEndpoint,
	"credential": KindCredential,
	"rule":       KindRule,
	"approver":   KindApprover,
	"policy":     KindPolicy,
	"profile":    KindProfile,
}

// buildSymbols is pass 1. It walks the parsed file's policy blocks,
// validates label counts, looks up each block's plugin to attach the
// Family, registers every name in the flat namespace, and reports
// collisions.
//
// Single-block kinds (defaults) are NOT added to the symbol table —
// they don't have names and can't be referenced.
func buildSymbols(blocks hcl.Blocks) (*SymbolTable, hcl.Diagnostics) {
	table := &SymbolTable{
		byKey:    make(map[symKey]*Symbol),
		byKind:   make(map[Kind][]*Symbol),
		byName:   make(map[string]*Symbol),
		allNames: make(map[string]struct{}),
	}
	var diags hcl.Diagnostics

	for _, block := range blocks {
		kind, ok := blockKinds[block.Type]
		if !ok {
			// Unknown top-level block — caller decides whether to
			// emit a diagnostic. Skip in pass 1.
			continue
		}
		want := kind.LabelCount()
		if len(block.Labels) != want {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Wrong label count for %s block", kind),
				Detail:   fmt.Sprintf("%s blocks take %d label(s); got %d.", kind, want, len(block.Labels)),
				Subject:  &block.DefRange,
			})
			continue
		}

		var typ, name, family string
		switch want {
		case 1:
			name = block.Labels[0]
		case 2:
			typ, name = block.Labels[0], block.Labels[1]
			plugin := Lookup(kind, typ)
			if plugin == nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Unknown %s type %q", kind, typ),
					Detail:   fmt.Sprintf("Known %s types: %v.", kind, Types(kind)),
					Subject:  &block.LabelRanges[0],
				})
				// Still register the name so we don't cascade
				// "unknown reference" errors for downstream rules.
			} else {
				family = plugin.Family
			}
		}

		sym := &Symbol{
			Name:   name,
			Kind:   kind,
			Type:   typ,
			Family: family,
			Block:  block,
		}

		// Global uniqueness across all kinds — names share one flat
		// namespace per the v14 design. Same-name-same-kind hits the
		// branch below; same-name-different-kind hits the cross-kind
		// branch. Both are load errors.
		if dup := table.byName[name]; dup != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Duplicate name %q", name),
				Detail:   fmt.Sprintf("Names share a single flat namespace. %q is already declared as %s at %s.", name, dup.Kind, dup.Range()),
				Subject:  &block.DefRange,
			})
			continue
		}
		table.byKey[symKey{Kind: kind, Name: name}] = sym
		table.byKind[kind] = append(table.byKind[kind], sym)
		table.byName[name] = sym
		table.allNames[name] = struct{}{}
	}

	return table, diags
}
