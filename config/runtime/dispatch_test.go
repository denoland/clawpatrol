package runtime_test

import (
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
	"github.com/denoland/clawpatrol/config/runtime"
)

const fixture = `
credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com", "github.com"]
  credential = pat
}

profile "default" { endpoints = [github] }

rule "http_rule" "reads" {
  endpoint = github
  match    = { method = ["GET", "HEAD"] }
  verdict  = "allow"
}
rule "http_rule" "writes" {
  endpoint = github
  match    = { method = ["POST", "PATCH", "DELETE"] }
  verdict  = "deny"
  reason   = "writes go through PR review"
}
rule "http_rule" "github-default" {
  endpoint = github
  priority = -100
  verdict  = "deny"
  reason   = "no policy matched"
}
`

func compile(t *testing.T) *config.CompiledPolicy {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(fixture), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cp
}

// TestHostEndpoint covers the per-profile lookup and the
// single-tenant fallback path that scans every profile.
func TestHostEndpoint(t *testing.T) {
	cp := compile(t)

	if got := runtime.HostEndpoint(cp, "default", "api.github.com"); got == nil || got.Name != "github" {
		t.Errorf("default profile / api.github.com → %+v", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "unknown.example"); got != nil {
		t.Errorf("unknown host should resolve to nil, got %+v", got)
	}
	// Unknown profile + known host → fallback scan finds it.
	if got := runtime.HostEndpoint(cp, "no-such-profile", "github.com"); got == nil {
		t.Errorf("fallback scan should find github.com")
	}
}

// TestMatchRequest exercises priority-ordered first-match-wins
// dispatch and the default catch-all (priority -100).
func TestMatchRequest(t *testing.T) {
	cp := compile(t)
	ep := cp.Endpoints["github"]

	cases := []struct {
		name   string
		method string
		want   string // expected rule name; "" → no match
	}{
		{"GET hits reads", "GET", "reads"},
		{"POST hits writes", "POST", "writes"},
		{"PATCH hits writes", "PATCH", "writes"},
		{"OPTIONS falls through to default", "OPTIONS", "github-default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &match.Request{Family: "https", Method: tc.method}
			r := runtime.MatchRequest(ep, req)
			if r == nil {
				if tc.want != "" {
					t.Errorf("expected rule %q, got nil", tc.want)
				}
				return
			}
			if r.Name != tc.want {
				t.Errorf("rule=%q want %q", r.Name, tc.want)
			}
		})
	}
}

// TestResolveCredentialSingular: one credential, no placeholder →
// returned without consulting the endpoint plugin's detector.
func TestResolveCredentialSingular(t *testing.T) {
	cp := compile(t)
	ep := cp.Endpoints["github"]
	got := runtime.ResolveCredential(ep, &match.Request{Family: "https", Headers: http.Header{}})
	if got == nil || got.Credential.Symbol.Name != "pat" {
		t.Errorf("singular credential resolution wrong: %+v", got)
	}
}

// TestResolveCredentialPlaceholder: multi-credential dispatch asks
// the endpoint plugin's runtime to detect the agent's placeholder
// from the actual request, then matches against the configured set.
// The trailing no-placeholder entry is the fallback.
func TestResolveCredentialPlaceholder(t *testing.T) {
	src := `
credential "bearer_token" "test"     {}
credential "bearer_token" "prod"     {}
credential "bearer_token" "fallback" {}
endpoint "https" "ep" {
  hosts = ["x.example.com"]
  credentials = [
    { placeholder = "PH_test", credential = test },
    { placeholder = "PH_prod", credential = prod },
    { credential = fallback },
  ]
}
profile "default" { endpoints = [ep] }
`
	gw, diags := config.LoadBytes([]byte(src), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := cp.Endpoints["ep"]

	mkReq := func(authz string) *match.Request {
		h := http.Header{}
		if authz != "" {
			h.Set("Authorization", authz)
		}
		return &match.Request{Family: "https", Headers: h}
	}

	got := runtime.ResolveCredential(ep, mkReq("Bearer PH_prod"))
	if got == nil || got.Credential.Symbol.Name != "prod" {
		t.Errorf("Authorization=Bearer PH_prod should select prod, got %+v", got)
	}
	got = runtime.ResolveCredential(ep, mkReq("Bearer something-else"))
	if got == nil || got.Credential.Symbol.Name != "fallback" {
		t.Errorf("no placeholder match should fall back, got %+v", got)
	}
	got = runtime.ResolveCredential(ep, mkReq(""))
	if got == nil || got.Credential.Symbol.Name != "fallback" {
		t.Errorf("missing Authorization should fall back, got %+v", got)
	}
}
