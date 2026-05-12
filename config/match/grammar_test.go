package match_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config/match"
)

var sqlSpecs = []match.KeySpec{
	{Name: "verb", CELRef: "sql.verb", Arity: match.UnaryEnum},
	{Name: "tables", CELRef: "sql.tables", Arity: match.MultiValued},
	{Name: "function", CELRef: "sql.function", Arity: match.MultiValued},
	{Name: "statement", CELRef: "sql.statement", Arity: match.UnaryBlob},
}

var k8sSpecs = []match.KeySpec{
	{Name: "verb", CELRef: "k8s.verb", Arity: match.UnaryEnum},
	{Name: "resource", CELRef: "k8s.resource", Arity: match.UnaryBlob},
	{Name: "name", CELRef: "k8s.name", Arity: match.UnaryBlob},
}

func mustDecode(t *testing.T, val cty.Value, specs []match.KeySpec) *match.Block {
	t.Helper()
	b, diags := match.DecodeAttribute(val, specs, "test", hcl.Range{})
	if diags.HasErrors() {
		t.Fatalf("decode: %v", diags.Errs())
	}
	return b
}

func TestSplitSugarBecomesAny(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"verb": cty.StringVal("select"),
	})
	block := mustDecode(t, val, sqlSpecs)
	got, err := block.Compile(sqlSpecs)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	want := `glob("select", sql.verb)`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestUnaryAnyMultipleValues(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"verb_any": cty.TupleVal([]cty.Value{cty.StringVal("select"), cty.StringVal("show")}),
	})
	block := mustDecode(t, val, sqlSpecs)
	got, _ := block.Compile(sqlSpecs)
	want := `(glob("select", sql.verb) || glob("show", sql.verb))`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestUnaryNone(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"verb_none": cty.TupleVal([]cty.Value{cty.StringVal("drop"), cty.StringVal("truncate")}),
	})
	block := mustDecode(t, val, sqlSpecs)
	got, _ := block.Compile(sqlSpecs)
	want := `(!glob("drop", sql.verb) && !glob("truncate", sql.verb))`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestUnaryAllRejectedOnEnum(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"verb_all": cty.TupleVal([]cty.Value{cty.StringVal("select"), cty.StringVal("show")}),
	})
	_, diags := match.DecodeAttribute(val, sqlSpecs, "test", hcl.Range{})
	if !diags.HasErrors() {
		t.Fatalf("expected error on _all over UnaryEnum")
	}
	got := diags.Errs()[0].Error()
	if !strings.Contains(got, "_all not valid") {
		t.Errorf("expected _all rejection diagnostic, got: %s", got)
	}
}

func TestUnaryAllOnBlob(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"name_all": cty.TupleVal([]cty.Value{cty.StringVal("api-*"), cty.StringVal("*-svc")}),
	})
	block := mustDecode(t, val, k8sSpecs)
	got, _ := block.Compile(k8sSpecs)
	want := `(glob("api-*", k8s.name) && glob("*-svc", k8s.name))`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestMultiValuedAny(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"tables_any": cty.TupleVal([]cty.Value{cty.StringVal("users"), cty.StringVal("audit_*")}),
	})
	block := mustDecode(t, val, sqlSpecs)
	got, _ := block.Compile(sqlSpecs)
	want := `sql.tables.exists(v, glob("users", v) || glob("audit_*", v))`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestMultiValuedAllCoOccurrence(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"tables_all": cty.TupleVal([]cty.Value{cty.StringVal("users"), cty.StringVal("audit_log")}),
	})
	block := mustDecode(t, val, sqlSpecs)
	got, _ := block.Compile(sqlSpecs)
	want := `(sql.tables.exists(v, glob("users", v)) && sql.tables.exists(v, glob("audit_log", v)))`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestMultiValuedNone(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"function_none": cty.TupleVal([]cty.Value{cty.StringVal("pg_read_file")}),
	})
	block := mustDecode(t, val, sqlSpecs)
	got, _ := block.Compile(sqlSpecs)
	want := `sql.function.all(v, !glob("pg_read_file", v))`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestCompoundAnyAndNoneOnSameKey(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"verb_any":  cty.TupleVal([]cty.Value{cty.StringVal("select")}),
		"verb_none": cty.TupleVal([]cty.Value{cty.StringVal("show")}),
	})
	block := mustDecode(t, val, sqlSpecs)
	got, _ := block.Compile(sqlSpecs)
	// Predicates emit in sorted-key order: verb_any then verb_none.
	want := `glob("select", sql.verb) && !glob("show", sql.verb)`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"feerb_any": cty.TupleVal([]cty.Value{cty.StringVal("select")}),
	})
	_, diags := match.DecodeAttribute(val, sqlSpecs, "test", hcl.Range{})
	if !diags.HasErrors() {
		t.Fatalf("expected unknown-key diagnostic")
	}
}

func TestNullValueIsCatchAll(t *testing.T) {
	block, diags := match.DecodeAttribute(cty.NullVal(cty.EmptyObject), sqlSpecs, "test", hcl.Range{})
	if diags.HasErrors() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errs())
	}
	if block != nil {
		t.Fatalf("expected nil block for null match value, got %+v", block)
	}
}

func TestCelQuoteEscapesQuotesAndBackslashes(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"name": cty.StringVal(`a"b\c`),
	})
	block := mustDecode(t, val, k8sSpecs)
	got, _ := block.Compile(k8sSpecs)
	want := `glob("a\"b\\c", k8s.name)`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestStringValueIsListLifted(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"resource_none": cty.StringVal("*/exec"),
	})
	block := mustDecode(t, val, k8sSpecs)
	got, _ := block.Compile(k8sSpecs)
	want := `!glob("*/exec", k8s.resource)`
	if got != want {
		t.Errorf("compile:\n got  %s\n want %s", got, want)
	}
}

func TestInvalidGlobRejected(t *testing.T) {
	val := cty.ObjectVal(map[string]cty.Value{
		"name": cty.StringVal("[unclosed"),
	})
	_, diags := match.DecodeAttribute(val, k8sSpecs, "test", hcl.Range{})
	if !diags.HasErrors() {
		t.Fatalf("expected diag on malformed glob")
	}
	if !strings.Contains(diags.Errs()[0].Error(), "invalid glob") {
		t.Errorf("expected invalid-glob diagnostic, got: %s", diags.Errs()[0])
	}
}
