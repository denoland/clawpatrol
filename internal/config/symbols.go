package config

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// Symbol is one entry in the per-(kind,type) namespace.
type Symbol struct {
	Name   string
	Kind   Kind
	Type   string // "" for one-label kinds
	Family string // for endpoints: "http"|"sql"|"k8s"; "" otherwise
	Block  *hcl.Block
}

// Range is the block's declaration range — handy as a diagnostic
// fallback when the loader doesn't have a more precise pointer.
func (s *Symbol) Range() hcl.Range {
	if s == nil || s.Block == nil {
		return hcl.Range{}
	}
	return s.Block.DefRange
}

// QName returns the symbol's addressable name:
//   - one-label kinds: the bare name (e.g. "profile_foo").
//   - two-label kinds: "type.name" (e.g. "https.github").
func (s *Symbol) QName() string {
	if s == nil {
		return ""
	}
	if s.Kind.LabelCount() == 2 && s.Type != "" {
		return s.Type + "." + s.Name
	}
	return s.Name
}

// SymbolTable indexes every named block in the file, populated in
// pass 1. Names are unique within a (kind, type) pair; the same
// name may legally appear under different types of the same kind
// (e.g. `credential "github_api_key" "ops"` and
// `credential "anthropic_subscription" "ops"`) because references
// always carry the type for two-label kinds.
type SymbolTable struct {
	byKey  map[symKey]*Symbol
	byKind map[Kind][]*Symbol
}

type symKey struct {
	Kind Kind
	Type string
	Name string
}

// Get returns the symbol with (kind, type, name), or nil. Use "" for
// type when kind is one-label. For lookups driven by a single qname
// string (e.g. a resolved cty reference) use GetByQName instead.
func (t *SymbolTable) Get(kind Kind, typ, name string) *Symbol {
	if t == nil {
		return nil
	}
	return t.byKey[symKey{Kind: kind, Type: typ, Name: name}]
}

// GetByQName looks up a symbol by its addressable name:
//   - one-label kinds: qname is the bare name.
//   - two-label kinds: qname is "type.name"; a bare name (no ".")
//     is looked up across all types of that kind and returns the
//     symbol only if exactly one type carries that name. This bare-
//     name fallback preserves caller compatibility while the data
//     model still keys storage by bare name (see follow-up beads).
func (t *SymbolTable) GetByQName(kind Kind, qname string) *Symbol {
	if t == nil {
		return nil
	}
	typ, name := SplitQName(kind, qname)
	if kind.LabelCount() == 2 && typ == "" {
		var found *Symbol
		for _, s := range t.byKind[kind] {
			if s.Name == name {
				if found != nil {
					return nil
				}
				found = s
			}
		}
		return found
	}
	return t.byKey[symKey{Kind: kind, Type: typ, Name: name}]
}

// SplitQName decomposes a qname into (type, name) per the kind's
// label shape:
//   - one-label kinds: always returns ("", qname).
//   - two-label kinds: splits on the first "." into ("type", "name").
//     If qname has no ".", returns ("", qname) — a bare name to be
//     resolved by the bare-name fallback in GetByQName.
func SplitQName(kind Kind, qname string) (typ, name string) {
	if kind.LabelCount() == 2 {
		if i := strings.IndexByte(qname, '.'); i >= 0 {
			return qname[:i], qname[i+1:]
		}
	}
	return "", qname
}

// All returns every symbol of the given kind, in deterministic
// (declaration) order. Used by the loader's pass-2 walk.
func (t *SymbolTable) All(kind Kind) []*Symbol {
	if t == nil {
		return nil
	}
	return t.byKind[kind]
}

// blockKinds is the set of block keywords the loader recognizes at
// the top level of a policy file. Anything else flows through to
// gohcl's operational decode.
var blockKinds = map[string]Kind{
	"endpoint":   KindEndpoint,
	"credential": KindCredential,
	"rule":       KindRule,
	"approver":   KindApprover,
	"profile":    KindProfile,
	"tunnel":     KindTunnel,
}

// buildSymbols is pass 1. It walks the parsed file's policy blocks,
// validates label counts, looks up each block's plugin to attach the
// Family, and registers every (kind, type, name) in the symbol table.
func buildSymbols(blocks hcl.Blocks) (*SymbolTable, hcl.Diagnostics) {
	table := &SymbolTable{
		byKey:  make(map[symKey]*Symbol),
		byKind: make(map[Kind][]*Symbol),
	}
	// Pre-register built-in approvers (e.g. dashboard) so refs like
	// `approve = [builtin.dashboard]` resolve at load time without an
	// explicit `approver "..." "dashboard" {}` block.
	for _, name := range builtinApproverNames {
		sym := &Symbol{Name: name, Kind: KindApprover, Type: "builtin"}
		table.byKey[symKey{Kind: KindApprover, Type: "builtin", Name: name}] = sym
		table.byKind[KindApprover] = append(table.byKind[KindApprover], sym)
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

		key := symKey{Kind: kind, Type: typ, Name: name}
		if dup := table.byKey[key]; dup != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Duplicate %s name %q", kind, name),
				Detail:   fmt.Sprintf("%s %q is already declared at %s. Names must be unique within a type.", kind, name, dup.Range()),
				Subject:  &block.DefRange,
			})
			continue
		}
		table.byKey[key] = sym
		table.byKind[kind] = append(table.byKind[kind], sym)
	}

	return table, diags
}
