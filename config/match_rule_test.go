package config_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
	k8sfacet "github.com/denoland/clawpatrol/config/plugins/facets/k8s"
	sqlfacet "github.com/denoland/clawpatrol/config/plugins/facets/sql"
)

// loadFirstRule loads the source as a one-rule fixture and returns the
// compiled rule plus a t.Fatal escape on any load/compile failure.
func loadFirstRule(t *testing.T, src string) *config.CompiledRule {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(src), "test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, ep := range cp.Endpoints {
		if len(ep.Rules) > 0 {
			return ep.Rules[0]
		}
	}
	t.Fatalf("no rules compiled")
	return nil
}

// TestMatchBlockHttpsAny exercises the simplest sugar — bare key gets
// _any semantics, single-string value lifts to a singleton list.
func TestMatchBlockHttpsAny(t *testing.T) {
	src := `
credential "bearer_token" "pat" {}
endpoint "https" "ep" {
  hosts      = ["api.example.com"]
  credential = pat
}
profile "p" { endpoints = [ep] }

rule "r" {
  endpoint = ep
  match    = { method = ["GET", "HEAD"] }
  verdict  = "allow"
}
`
	rule := loadFirstRule(t, src)
	for _, m := range []string{"GET", "HEAD"} {
		req := &match.Request{Family: "https", Method: m}
		if !rule.Matcher.Match(req) {
			t.Errorf("expected %q to match", m)
		}
	}
	for _, m := range []string{"POST", "DELETE"} {
		req := &match.Request{Family: "https", Method: m}
		if rule.Matcher.Match(req) {
			t.Errorf("expected %q to NOT match", m)
		}
	}
}

// TestMatchBlockGlobOnPath exercises the glob runtime — `*admin*`
// substring globs work because every value is a glob.
func TestMatchBlockGlobOnPath(t *testing.T) {
	src := `
credential "bearer_token" "pat" {}
endpoint "https" "ep" {
  hosts      = ["api.example.com"]
  credential = pat
}
profile "p" { endpoints = [ep] }

rule "r" {
  endpoint = ep
  match    = { path_none = ["/admin/*"] }
  verdict  = "deny"
}
`
	rule := loadFirstRule(t, src)
	mkReq := func(p string) *match.Request {
		u, _ := url.Parse("https://x" + p)
		return &match.Request{Family: "https", Method: "GET", URL: u, Headers: http.Header{}}
	}
	if rule.Matcher.Match(mkReq("/admin/users")) {
		t.Error("expected /admin/users to be excluded by path_none")
	}
	if !rule.Matcher.Match(mkReq("/api/widgets")) {
		t.Error("expected /api/widgets to fall through path_none")
	}
}

// TestMatchBlockK8sCompound exercises compound predicates (multiple
// keys AND together) and the negation idiom (resource_none).
func TestMatchBlockK8sCompound(t *testing.T) {
	src := `
credential "bearer_token" "tok" {}
endpoint "kubernetes" "k" {
  hosts      = ["k8s.example.com:443"]
  credential = tok
}
profile "p" { endpoints = [k] }

rule "r" {
  endpoint = k
  match = {
    verb_any      = ["create", "update", "patch", "delete"]
    name_none     = ["debug-*"]
    resource_none = ["*/exec", "*/attach"]
  }
  verdict = "deny"
}
`
	rule := loadFirstRule(t, src)
	mk := func(verb, resource, name string) *match.Request {
		return &match.Request{
			Family: "k8s",
			Meta: &k8sfacet.Meta{
				Verb:     verb,
				Resource: resource,
				Name:     name,
			},
		}
	}
	if !rule.Matcher.Match(mk("create", "pods", "api-1")) {
		t.Error("expected create pods/api-1 to match the deny rule")
	}
	if rule.Matcher.Match(mk("create", "pods", "debug-1")) {
		t.Error("debug-* pod should not match (name_none)")
	}
	if rule.Matcher.Match(mk("create", "pods/exec", "api-1")) {
		t.Error("pods/exec should not match (resource_none)")
	}
	if rule.Matcher.Match(mk("get", "pods", "api-1")) {
		t.Error("get is not in verb_any")
	}
}

// TestMatchBlockSqlAllOnTables checks the multi-valued `_all`
// semantics: every pattern must hit at least one extracted table.
func TestMatchBlockSqlAllOnTables(t *testing.T) {
	src := `
credential "postgres_credential" "tok" {}
endpoint "postgres" "pg" {
  host       = "10.0.0.1:5432"
  database   = "app"
  credential = tok
}
profile "p" { endpoints = [pg] }

rule "r" {
  endpoint = pg
  match    = {
    verb_any   = ["select"]
    tables_all = ["users", "audit_log"]
  }
  verdict = "deny"
}
`
	rule := loadFirstRule(t, src)
	mk := func(verb string, tables []string) *match.Request {
		return &match.Request{
			Family: "sql",
			Meta:   &sqlfacet.Meta{Verb: verb, Tables: tables},
		}
	}
	if !rule.Matcher.Match(mk("select", []string{"users", "audit_log", "sessions"})) {
		t.Error("expected co-occurrence of users + audit_log to match")
	}
	if rule.Matcher.Match(mk("select", []string{"users"})) {
		t.Error("missing audit_log → should not match _all")
	}
	if rule.Matcher.Match(mk("insert", []string{"users", "audit_log"})) {
		t.Error("verb_any rejects insert")
	}
}

// TestMatchAndConditionMutuallyExclusive — load fails when a rule
// declares both shapes.
func TestMatchAndConditionMutuallyExclusive(t *testing.T) {
	src := `
credential "bearer_token" "tok" {}
endpoint "https" "ep" {
  hosts      = ["x.example.com"]
  credential = tok
}
profile "p" { endpoints = [ep] }

rule "r" {
  endpoint  = ep
  match     = { method = ["GET"] }
  condition = "http.method == 'GET'"
  verdict   = "allow"
}
`
	_, diags := config.LoadBytes([]byte(src), "in.hcl")
	if !diags.HasErrors() {
		t.Fatal("expected load error when both match and condition set")
	}
	if !strings.Contains(diags.Error(), "Both condition and match") {
		t.Errorf("expected mutual-exclusion diagnostic, got: %v", diags)
	}
}

// TestMatchAllRejectedOnEnumKey — `_all` is forbidden on unary-enum
// keys and the diagnostic explains why.
func TestMatchAllRejectedOnEnumKey(t *testing.T) {
	src := `
credential "bearer_token" "tok" {}
endpoint "https" "ep" {
  hosts      = ["x.example.com"]
  credential = tok
}
profile "p" { endpoints = [ep] }

rule "r" {
  endpoint = ep
  match    = { method_all = ["GET", "POST"] }
  verdict  = "allow"
}
`
	_, diags := config.LoadBytes([]byte(src), "in.hcl")
	if !diags.HasErrors() {
		t.Fatal("expected error on method_all")
	}
	if !strings.Contains(diags.Error(), "_all not valid") {
		t.Errorf("expected _all-on-enum diagnostic, got: %v", diags)
	}
}

// TestMatchUnknownKeyRejected — typos in keys surface as errors.
func TestMatchUnknownKeyRejected(t *testing.T) {
	src := `
credential "bearer_token" "tok" {}
endpoint "https" "ep" {
  hosts      = ["x.example.com"]
  credential = tok
}
profile "p" { endpoints = [ep] }

rule "r" {
  endpoint = ep
  match    = { mehtod_any = ["GET"] }
  verdict  = "allow"
}
`
	_, diags := config.LoadBytes([]byte(src), "in.hcl")
	if !diags.HasErrors() {
		t.Fatal("expected error on unknown key")
	}
	if !strings.Contains(diags.Error(), "unknown key") {
		t.Errorf("expected unknown-key diagnostic, got: %v", diags)
	}
}

// TestEmitRoundtripsMatchBlock checks that a rule loaded from a match
// block re-emits as a match block (not as the lowered CEL).
func TestEmitRoundtripsMatchBlock(t *testing.T) {
	src := `
credential "bearer_token" "tok" {}
endpoint "https" "ep" {
  hosts      = ["x.example.com"]
  credential = tok
}
profile "p" { endpoints = [ep] }

rule "r" {
  endpoint = ep
  match    = { method_any = ["GET", "HEAD"], path_none = ["/admin/*"] }
  verdict  = "allow"
}
`
	gw, diags := config.LoadBytes([]byte(src), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	out, err := config.Emit(gw)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "match ") || !strings.Contains(got, "method_any") || !strings.Contains(got, "path_none") {
		t.Errorf("expected emitted source to retain the match block, got:\n%s", got)
	}
	if strings.Contains(got, "condition = ") {
		t.Errorf("expected emit to skip condition= when match block is present, got:\n%s", got)
	}
}
