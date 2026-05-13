package runtime_test

import (
	"net/url"
	"testing"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	llmfacet "github.com/denoland/clawpatrol/config/plugins/facets/llm"
	"github.com/denoland/clawpatrol/config/runtime"
)

// TestMultiFamilyRoutingHTTPAndLLM pins the headline behaviour the
// llm-facet design adds: a multi-family endpoint (`anthropic` carries
// http + llm) lets both http_rule and llm_rule predicates fire on
// the same action.
//
// Two rules on the same anthropic endpoint:
//   - HTTP-shaped: gate POSTs to /v1/messages
//   - LLM-shaped (explicit family = "llm"): deny opus-class models
//
// The request carries http + llm slots; the higher-priority opus
// gate fires regardless of method, and at lower priority the
// method-only rule still fires for non-opus requests.
func TestMultiFamilyRoutingHTTPAndLLM(t *testing.T) {
	cp := compileFixture(t, `
credential "bearer_token" "anthropic-key" {}

endpoint "anthropic" "claude" {
  hosts      = ["api.anthropic.com"]
  credential = anthropic-key
}

profile "default" { endpoints = [claude] }

rule "no-opus" {
  endpoint  = claude
  family    = "llm"
  condition = "llm.model.matches('^claude-opus-')"
  priority  = 100
  verdict   = "deny"
  reason    = "opus-class models gated"
}
rule "allow-posts" {
  endpoint  = claude
  family    = "http"
  condition = "http.method == 'POST'"
  verdict   = "allow"
}
rule "default-deny" {
  endpoint = claude
  priority = -100
  family   = "http"
  verdict  = "deny"
  reason   = "no policy matched"
}
`)
	ep := cp.Endpoints["claude"]
	if ep == nil {
		t.Fatal("expected claude endpoint to compile")
	}
	if got := ep.PrimaryFamily(); got != "http" {
		t.Errorf("primary family = %q, want http", got)
	}
	if !ep.HasFamily("llm") {
		t.Error("expected llm family on anthropic endpoint")
	}

	// Helper to build an in-flight request with both facets populated.
	build := func(method, model string) *match.Request {
		u, _ := url.Parse("https://api.anthropic.com/v1/messages")
		req := &match.Request{
			Families: ep.Families,
			Method:   method,
			URL:      u,
		}
		req.SetMeta("llm", &llmfacet.Meta{Provider: "anthropic", Model: model})
		return req
	}

	// Opus model → llm gate fires first (priority 100), denies.
	r := runtime.MatchRequest(ep, build("POST", "claude-opus-4-7-20251001"))
	if r == nil || r.Name != "no-opus" || r.Outcome.Verdict != "deny" {
		t.Errorf("opus POST: got %+v, want no-opus deny", r)
	}

	// Sonnet POST → llm gate misses; allow-posts fires.
	r = runtime.MatchRequest(ep, build("POST", "claude-3-5-sonnet-20240620"))
	if r == nil || r.Name != "allow-posts" || r.Outcome.Verdict != "allow" {
		t.Errorf("sonnet POST: got %+v, want allow-posts allow", r)
	}

	// Sonnet GET → both rules miss; default-deny fires.
	r = runtime.MatchRequest(ep, build("GET", "claude-3-5-sonnet-20240620"))
	if r == nil || r.Name != "default-deny" {
		t.Errorf("sonnet GET: got %+v, want default-deny", r)
	}
}

// TestRuleFamilyRequiredForAmbiguousEndpoint pins the validation
// half: a rule attached to a multi-family endpoint without an
// explicit `family =` is ambiguous, and the loader must surface a
// diagnostic instead of silently picking one.
func TestRuleFamilyRequiredForAmbiguousEndpoint(t *testing.T) {
	src := `
credential "bearer_token" "anthropic-key" {}
endpoint "anthropic" "claude" {
  hosts      = ["api.anthropic.com"]
  credential = anthropic-key
}
profile "default" { endpoints = [claude] }

rule "ambiguous" {
  endpoint  = claude
  condition = "http.method == 'POST'"
  verdict   = "allow"
}
`
	_, diags := config.LoadBytes([]byte(src), "in.hcl")
	if !diags.HasErrors() {
		t.Fatal("expected ambiguity diagnostic, got none")
	}
	if !containsSubstring(diags.Error(), "ambiguous") {
		t.Errorf("diagnostic missing 'ambiguous' marker: %v", diags)
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
