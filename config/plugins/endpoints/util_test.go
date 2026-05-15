package endpoints

import (
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// credentialEntriesFromHCLValues builds the cty.Value the parser
// expects (tuple of objects). Each entry is built from a small
// pseudo-HCL map; nil values are skipped so each test can express
// "this attribute isn't set" by leaving it out of the map.
func credentialEntryValue(t *testing.T, attrs map[string]cty.Value) cty.Value {
	t.Helper()
	if len(attrs) == 0 {
		return cty.EmptyObjectVal
	}
	return cty.ObjectVal(attrs)
}

func credentialListValue(t *testing.T, entries ...cty.Value) cty.Value {
	t.Helper()
	if len(entries) == 0 {
		return cty.EmptyTupleVal
	}
	return cty.TupleVal(entries)
}

func TestParseCredentialListSingleDatabase(t *testing.T) {
	raw := credentialListValue(t,
		credentialEntryValue(t, map[string]cty.Value{
			"database":   cty.StringVal("prod"),
			"credential": cty.StringVal("ch-prod"),
		}),
	)
	got, diags := parseCredentialList(raw, hcl.Range{})
	if diags.HasErrors() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	want := []CredentialEntry{{Databases: []string{"prod"}, Credential: "ch-prod"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseCredentialListDatabasesList(t *testing.T) {
	raw := credentialListValue(t,
		credentialEntryValue(t, map[string]cty.Value{
			"databases": cty.TupleVal([]cty.Value{
				cty.StringVal("dev"),
				cty.StringVal("qa"),
			}),
			"credential": cty.StringVal("ch-nonprod"),
		}),
	)
	got, diags := parseCredentialList(raw, hcl.Range{})
	if diags.HasErrors() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	want := []CredentialEntry{{Databases: []string{"dev", "qa"}, Credential: "ch-nonprod"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseCredentialListPlaceholderAndDatabase(t *testing.T) {
	raw := credentialListValue(t,
		credentialEntryValue(t, map[string]cty.Value{
			"placeholder": cty.StringVal("PH_ro"),
			"database":    cty.StringVal("prod"),
			"credential":  cty.StringVal("ch-ro"),
		}),
	)
	got, diags := parseCredentialList(raw, hcl.Range{})
	if diags.HasErrors() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	want := []CredentialEntry{{Placeholder: "PH_ro", Databases: []string{"prod"}, Credential: "ch-ro"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseCredentialListRejectsDatabaseAndDatabases(t *testing.T) {
	raw := credentialListValue(t,
		credentialEntryValue(t, map[string]cty.Value{
			"database":   cty.StringVal("prod"),
			"databases":  cty.TupleVal([]cty.Value{cty.StringVal("dev")}),
			"credential": cty.StringVal("c"),
		}),
	)
	_, diags := parseCredentialList(raw, hcl.Range{})
	if !diags.HasErrors() {
		t.Fatalf("expected diags, got none")
	}
	if !strings.Contains(diags.Error(), "both `database` and `databases`") {
		t.Errorf("unexpected diag: %v", diags)
	}
}

func TestParseCredentialListRejectsDuplicateConstraint(t *testing.T) {
	raw := credentialListValue(t,
		credentialEntryValue(t, map[string]cty.Value{
			"database":   cty.StringVal("prod"),
			"credential": cty.StringVal("a"),
		}),
		credentialEntryValue(t, map[string]cty.Value{
			"database":   cty.StringVal("prod"),
			"credential": cty.StringVal("b"),
		}),
	)
	_, diags := parseCredentialList(raw, hcl.Range{})
	if !diags.HasErrors() {
		t.Fatalf("expected diags, got none")
	}
	if !strings.Contains(diags.Error(), "duplicate credentials dispatch constraint") {
		t.Errorf("unexpected diag: %v", diags)
	}
}

func TestParseCredentialListRejectsTwoCatchalls(t *testing.T) {
	raw := credentialListValue(t,
		credentialEntryValue(t, map[string]cty.Value{"credential": cty.StringVal("a")}),
		credentialEntryValue(t, map[string]cty.Value{"credential": cty.StringVal("b")}),
	)
	_, diags := parseCredentialList(raw, hcl.Range{})
	if !diags.HasErrors() {
		t.Fatalf("expected diags, got none")
	}
	if !strings.Contains(diags.Error(), "more than one catchall") {
		t.Errorf("unexpected diag: %v", diags)
	}
}

func TestParseCredentialListAllowsCatchallAlongsideSpecific(t *testing.T) {
	// An entry with no constraints alongside an entry with `database`
	// is the canonical mixed shape — specific claims its database, the
	// catchall takes everything else.
	raw := credentialListValue(t,
		credentialEntryValue(t, map[string]cty.Value{
			"database":   cty.StringVal("prod"),
			"credential": cty.StringVal("a"),
		}),
		credentialEntryValue(t, map[string]cty.Value{"credential": cty.StringVal("b")}),
	)
	got, diags := parseCredentialList(raw, hcl.Range{})
	if diags.HasErrors() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if len(got) != 2 {
		t.Errorf("got %d entries, want 2", len(got))
	}
}

// TestCredentialEntrySignatureStableAcrossOrder confirms that two
// `databases = [...]` entries with the same elements in different
// order are flagged as duplicates — the signature sorts the database
// list.
func TestCredentialEntrySignatureStableAcrossOrder(t *testing.T) {
	a := CredentialEntry{Databases: []string{"dev", "qa"}}
	b := CredentialEntry{Databases: []string{"qa", "dev"}}
	if credentialEntrySignature(a) != credentialEntrySignature(b) {
		t.Errorf("signatures differ across element order: %q vs %q",
			credentialEntrySignature(a), credentialEntrySignature(b))
	}
}
