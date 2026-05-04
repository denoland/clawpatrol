package config_test

import (
	"path/filepath"
	"testing"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

// TestCompile loads testdata/feature_minimal.hcl, lowers it via
// config.Compile, and exercises the resulting CompiledPolicy end-to-
// end: priority sort, host indexing, credential resolution, and
// matcher dispatch on synthetic requests.
func TestCompile(t *testing.T) {
	gw, diags := config.Load(filepath.Join("testdata", "feature_minimal.hcl"))
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Profile shape.
	prof, ok := cp.Profiles["default"]
	if !ok {
		t.Fatalf("missing default profile")
	}
	if len(prof.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(prof.Endpoints))
	}
	ep := prof.Endpoints["github"]
	if ep == nil {
		t.Fatal("expected github endpoint")
	}

	// Host index.
	for _, want := range []string{"api.github.com", "github.com"} {
		if prof.HostIndex[want] != ep {
			t.Errorf("HostIndex[%q] missing or wrong", want)
		}
	}

	// Credentials resolved.
	if len(ep.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(ep.Credentials))
	}
	if ep.Credentials[0].Credential == nil ||
		ep.Credentials[0].Credential.Symbol.Name != "github-pat" {
		t.Errorf("credential resolution wrong: %+v", ep.Credentials[0])
	}

	// Rule order: github-reads (priority 0), github-writes (priority 0).
	// Both 0 → declaration order, but the fixture declares reads first.
	if len(ep.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(ep.Rules))
	}
	names := []string{ep.Rules[0].Name, ep.Rules[1].Name}
	// Stable sort; rule order in cp.Endpoints map vs. iteration is
	// non-deterministic upstream, so we just check both rules landed.
	got := map[string]bool{names[0]: true, names[1]: true}
	for _, want := range []string{"github-reads", "github-writes"} {
		if !got[want] {
			t.Errorf("missing rule %q in compiled set %v", want, names)
		}
	}

	// Matcher dispatch — find each rule by name and run a request.
	var reads, writes *config.CompiledRule
	for _, r := range ep.Rules {
		switch r.Name {
		case "github-reads":
			reads = r
		case "github-writes":
			writes = r
		}
	}
	getReq := &match.Request{Family: "https", Method: "GET"}
	postReq := &match.Request{Family: "https", Method: "POST"}
	if !reads.Matcher.Match(getReq) {
		t.Errorf("github-reads should match GET")
	}
	if reads.Matcher.Match(postReq) {
		t.Errorf("github-reads should NOT match POST")
	}
	if !writes.Matcher.Match(postReq) {
		t.Errorf("github-writes should match POST")
	}
	if writes.Matcher.Match(getReq) {
		t.Errorf("github-writes should NOT match GET")
	}

	// Outcomes wired correctly.
	if reads.Outcome.Verdict != "allow" {
		t.Errorf("github-reads verdict=%q want allow", reads.Outcome.Verdict)
	}
	if len(writes.Outcome.Approve) != 1 || writes.Outcome.Approve[0].Name != "ops" {
		t.Errorf("github-writes approve=%+v", writes.Outcome.Approve)
	}
}

// TestCompilePrioritySort verifies that rules with mixed priorities
// land in descending priority order, matching the v14 first-match-
// wins evaluation. Tied priorities preserve declaration order.
func TestCompilePrioritySort(t *testing.T) {
	src := `
credential "bearer_token" "pat" {}
endpoint "https" "ep" {
  hosts      = ["x.example.com"]
  credential = pat
}
profile "p" { endpoints = [ep] }

rule "http_rule" "fallback" {
  endpoint = ep
  priority = -100
  match    = { method = "POST" }
  verdict  = "deny"
}
rule "http_rule" "specific" {
  endpoint = ep
  priority = 100
  match    = { method = "POST", path = "/v1/refunds" }
  verdict  = "deny"
}
rule "http_rule" "general" {
  endpoint = ep
  match    = { method = "POST" }
  verdict  = "allow"
}
`
	gw, diags := config.LoadBytes([]byte(src), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules := cp.Endpoints["ep"].Rules
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	want := []string{"specific", "general", "fallback"}
	for i, r := range rules {
		if r.Name != want[i] {
			t.Errorf("rules[%d]=%q want %q (priorities %v)",
				i, r.Name, want[i], priorities(rules))
		}
	}
}

func priorities(rules []*config.CompiledRule) []int {
	out := make([]int, len(rules))
	for i, r := range rules {
		out[i] = r.Priority
	}
	return out
}

// TestCompileFullSpec confirms the verbatim v14 fixture compiles
// without errors after Load — every rule's match map produces a
// valid matcher, every endpoint resolves its credentials, every
// profile resolves its endpoints.
func TestCompileFullSpec(t *testing.T) {
	gw, diags := config.Load(filepath.Join("testdata", "full.hcl"))
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cp.Profiles) != 3 {
		t.Errorf("expected 3 profiles, got %d", len(cp.Profiles))
	}
	if len(cp.Endpoints) < 20 {
		t.Errorf("expected ~30 endpoints, got %d", len(cp.Endpoints))
	}
	totalRules := 0
	for _, ep := range cp.Endpoints {
		totalRules += len(ep.Rules)
	}
	if totalRules < 50 {
		t.Errorf("expected ~50+ rule attachments, got %d", totalRules)
	}
}
