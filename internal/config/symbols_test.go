package config

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// parseBlocks parses src and pulls out every recognized top-level
// policy block. Test helper for exercising buildSymbols directly.
func parseBlocks(t *testing.T, src string) hcl.Blocks {
	t.Helper()
	p := hclparse.NewParser()
	file, diags := p.ParseHCL([]byte(src), "test.hcl")
	if diags.HasErrors() {
		t.Fatalf("parse: %s", diags.Error())
	}
	blocks, diags := extractPolicyBlocks(file.Body)
	if diags.HasErrors() {
		t.Fatalf("extract: %s", diags.Error())
	}
	return blocks
}

// TestBuildSymbolsAllowsCrossTypeSameName: the symbol table must
// register two credentials of different types that share a name
// without emitting a duplicate-name diagnostic. The two symbols are
// addressable via GetByQName("type.name") and as a pair via All().
//
// Plugins are intentionally not registered in this test; buildSymbols
// reports "Unknown credential type" for unknown types but still
// registers the symbol (see the comment in buildSymbols). Those
// diagnostics are ignored — the test asserts only on the
// duplicate-name signal.
func TestBuildSymbolsAllowsCrossTypeSameName(t *testing.T) {
	src := `
credential "github_api_key" "ops" {}
credential "anthropic_subscription" "ops" {}
`
	blocks := parseBlocks(t, src)
	tab, diags := buildSymbols(blocks)
	for _, d := range diags {
		if strings.HasPrefix(d.Summary, "Duplicate") {
			t.Fatalf("unexpected duplicate diagnostic: %s — %s", d.Summary, d.Detail)
		}
	}

	got := tab.All(KindCredential)
	if len(got) != 2 {
		t.Fatalf("All(KindCredential) length = %d, want 2", len(got))
	}

	if sym := tab.GetByQName(KindCredential, "github_api_key.ops"); sym == nil || sym.Type != "github_api_key" {
		t.Errorf(`GetByQName(credential, "github_api_key.ops") = %v, want type=github_api_key`, sym)
	}
	if sym := tab.GetByQName(KindCredential, "anthropic_subscription.ops"); sym == nil || sym.Type != "anthropic_subscription" {
		t.Errorf(`GetByQName(credential, "anthropic_subscription.ops") = %v, want type=anthropic_subscription`, sym)
	}

	// Bare-name fallback is ambiguous when two types share a name.
	if sym := tab.GetByQName(KindCredential, "ops"); sym != nil {
		t.Errorf(`GetByQName(credential, "ops") = %v, want nil (ambiguous)`, sym)
	}
}

// TestBuildSymbolsRejectsSameTypeSameName: two blocks with the same
// (kind, type, name) must still fail with a duplicate-name diagnostic.
func TestBuildSymbolsRejectsSameTypeSameName(t *testing.T) {
	src := `
credential "github_api_key" "ops" {}
credential "github_api_key" "ops" {}
`
	blocks := parseBlocks(t, src)
	_, diags := buildSymbols(blocks)
	var dup *hcl.Diagnostic
	for _, d := range diags {
		if strings.HasPrefix(d.Summary, "Duplicate") {
			dup = d
			break
		}
	}
	if dup == nil {
		t.Fatalf("expected a duplicate-name diagnostic, got: %s", diags.Error())
	}
	if !strings.Contains(dup.Detail, "unique within a type") {
		t.Errorf("diagnostic detail = %q, want it to mention 'unique within a type'", dup.Detail)
	}
}

// TestSymbolQName covers the addressable-name shape for both label
// counts (and the nil receiver, which callers in diagnostic paths
// rely on returning "").
func TestSymbolQName(t *testing.T) {
	cases := []struct {
		name string
		sym  *Symbol
		want string
	}{
		{"nil receiver", nil, ""},
		{"two-label", &Symbol{Kind: KindCredential, Type: "github_api_key", Name: "ops"}, "github_api_key.ops"},
		{"one-label", &Symbol{Kind: KindProfile, Name: "default"}, "default"},
		{"two-label with empty type falls back to bare name", &Symbol{Kind: KindCredential, Name: "ops"}, "ops"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sym.QName(); got != tc.want {
				t.Errorf("QName() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSplitQName covers the parser used by GetByQName.
func TestSplitQName(t *testing.T) {
	cases := []struct {
		name     string
		kind     Kind
		qname    string
		wantTyp  string
		wantName string
	}{
		{"one-label kind ignores dots", KindProfile, "default", "", "default"},
		{"one-label kind keeps dots in name", KindProfile, "a.b.c", "", "a.b.c"},
		{"two-label kind splits on first dot", KindCredential, "github_api_key.ops", "github_api_key", "ops"},
		{"two-label kind keeps later dots in name", KindCredential, "github_api_key.my.ops", "github_api_key", "my.ops"},
		{"two-label kind without dot returns bare name", KindCredential, "ops", "", "ops"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			typ, name := SplitQName(tc.kind, tc.qname)
			if typ != tc.wantTyp || name != tc.wantName {
				t.Errorf("SplitQName(%s, %q) = (%q, %q), want (%q, %q)",
					tc.kind, tc.qname, typ, name, tc.wantTyp, tc.wantName)
			}
		})
	}
}
