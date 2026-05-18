package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

// loadExamplePolicy compiles testdata/example.hcl. A typo there
// surfaces here, not as a downstream fixture-mismatch failure.
func loadExamplePolicy(t *testing.T) *config.CompiledPolicy {
	t.Helper()
	gw, diags := config.Load("testdata/example.hcl")
	if diags.HasErrors() {
		t.Fatalf("load testdata/example.hcl: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile testdata/example.hcl: %v", err)
	}
	return policy
}

// TestExampleConfigCompiles gates the rest: a clean HCL parse +
// compile of the shipped sample.
func TestExampleConfigCompiles(t *testing.T) {
	policy := loadExamplePolicy(t)
	if policy.Endpoints["github"] == nil {
		t.Fatal("expected endpoint 'github' in compiled policy")
	}
}

// TestExampleFixturesPass replays the shipped fixtures end-to-end.
func TestExampleFixturesPass(t *testing.T) {
	policy := loadExamplePolicy(t)
	matches, err := filepath.Glob("testdata/*.json")
	if err != nil || len(matches) == 0 {
		t.Fatalf("glob fixtures: %v len=%d", err, len(matches))
	}
	for _, f := range matches {
		ok, msg, err := runOneFixture(policy, f)
		if err != nil {
			t.Errorf("%s: load error %v", f, err)
			continue
		}
		if !ok {
			t.Errorf("%s: verdict mismatch:\n%s", f, msg)
		}
	}
}

// Mutate a fixture's expected verdict; runner must report mismatch.
func TestExampleFixtureDetectsDrift(t *testing.T) {
	policy := loadExamplePolicy(t)
	body, err := os.ReadFile("testdata/get-user.json")
	if err != nil {
		t.Fatal(err)
	}
	var f Fixture
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatal(err)
	}
	f.Match.Verdict = "deny"
	f.Match.Rule = "github-writes"
	out, _ := json.Marshal(&f)
	tmp := filepath.Join(t.TempDir(), "flipped.json")
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		t.Fatal(err)
	}
	ok, _, err := runOneFixture(policy, tmp)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if ok {
		t.Fatal("expected mismatch, got match")
	}
}

// Host-resolution paths: unique, ambiguous (errors + disambiguated
// via match.endpoint), unknown. Compiles an ad-hoc policy with
// shared hosts since testdata/example.hcl has only one endpoint.
func TestResolveEndpointByHost(t *testing.T) {
	hcl := `
admin_email = "x@example.com"
credential "bearer_token" "a" {}
credential "bearer_token" "b" {}
endpoint "https" "alpha" {
  hosts      = ["api.example.com"]
  credential = a
}
endpoint "https" "beta" {
  hosts      = ["api.example.com"]
  credential = b
}
endpoint "https" "gamma" {
  hosts      = ["solo.example.com"]
  credential = a
}
profile "default" { endpoints = [alpha, beta, gamma] }
`
	gw, diags := config.LoadBytes([]byte(hcl), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	mk := func(t *testing.T, body string) *Fixture {
		t.Helper()
		var f Fixture
		if err := json.Unmarshal([]byte(body), &f); err != nil {
			t.Fatal(err)
		}
		return &f
	}

	t.Run("unique host", func(t *testing.T) {
		f := mk(t, `{"action":{"host":"solo.example.com","http":{"path":"/x"}},"match":{"verdict":"allow"}}`)
		ep, err := f.ResolveEndpoint(policy)
		if err != nil {
			t.Fatal(err)
		}
		if ep.Name != "gamma" {
			t.Fatalf("got %q want gamma", ep.Name)
		}
	})

	t.Run("ambiguous host errors with candidates", func(t *testing.T) {
		f := mk(t, `{"action":{"host":"api.example.com","http":{"path":"/x"}},"match":{"verdict":"allow"}}`)
		_, err := f.ResolveEndpoint(policy)
		if err == nil || !strings.Contains(err.Error(), "claimed by multiple endpoints") {
			t.Fatalf("want ambiguity error, got %v", err)
		}
	})

	t.Run("ambiguous host disambiguated by match.endpoint", func(t *testing.T) {
		f := mk(t, `{"action":{"host":"api.example.com","http":{"path":"/x"}},"match":{"verdict":"allow","endpoint":"beta"}}`)
		ep, err := f.ResolveEndpoint(policy)
		if err != nil {
			t.Fatal(err)
		}
		if ep.Name != "beta" {
			t.Fatalf("got %q want beta", ep.Name)
		}
	})

	t.Run("unknown host", func(t *testing.T) {
		f := mk(t, `{"action":{"host":"nope.example.com","http":{"path":"/x"}},"match":{"verdict":"allow"}}`)
		_, err := f.ResolveEndpoint(policy)
		if err == nil || !strings.Contains(err.Error(), "no endpoint claims") {
			t.Fatalf("want unknown-host error, got %v", err)
		}
	})
}

// File vs directory vs missing argument path resolution.
func TestResolveFixtures(t *testing.T) {
	got, err := resolveFixtures("testdata/")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 {
		t.Fatalf("dir mode: want ≥2 fixtures, got %d (%v)", len(got), got)
	}
	if !strings.HasSuffix(got[0], "delete-issue.json") {
		t.Fatalf("expected sorted order, got %v", got)
	}
	single, err := resolveFixtures("testdata/get-user.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 {
		t.Fatalf("file mode: want 1, got %d", len(single))
	}
	if _, err := resolveFixtures("testdata/does-not-exist"); err == nil {
		t.Fatal("missing path: expected error, got nil")
	}
}
