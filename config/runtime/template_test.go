package runtime_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
	"github.com/denoland/clawpatrol/config/runtime"
)

// TestTemplateRoundTrip loads a policy with a rule template,
// matches against a synthetic request, and asserts the rendered
// approval message reflects the matched request fields.
func TestTemplateRoundTrip(t *testing.T) {
	cp := compileFixture(t, `
credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

approver "human_approver" "ops" { channel = "#ops" }

rule "writes" {
  endpoint = github
  condition = "http.method == 'POST'"
  approve  = [ops]
  template = "'agent wants ' + http.method + ' ' + http.path"
}

profile "default" { endpoints = [github] }
`)

	ep := cp.Endpoints["github"]
	if ep == nil {
		t.Fatal("no github endpoint")
	}
	u, _ := url.Parse("https://api.github.com/v1/repos")
	req := &match.Request{
		Family:  "http",
		Method:  "POST",
		URL:     u,
		Headers: http.Header{},
	}
	cr := runtime.MatchRequest(ep, req)
	if cr == nil {
		t.Fatal("MatchRequest: no rule matched")
	}
	if cr.Template == "" {
		t.Fatal("CompiledRule.Template empty")
	}
	if cr.TemplateRenderer == nil {
		t.Fatal("CompiledRule.TemplateRenderer nil")
	}
	got := runtime.RenderTemplate(cr, req)
	if want := "agent wants post /v1/repos"; got != want {
		t.Fatalf("RenderTemplate = %q, want %q", got, want)
	}
}

// TestTemplateAbsentLeavesRendererNil ensures rules without a
// template field don't carry a renderer, preserving the default
// approval-message format.
func TestTemplateAbsentLeavesRendererNil(t *testing.T) {
	cp := compileFixture(t, `
credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

approver "human_approver" "ops" { channel = "#ops" }

rule "writes" {
  endpoint = github
  condition = "http.method == 'POST'"
  approve  = [ops]
}

profile "default" { endpoints = [github] }
`)
	ep := cp.Endpoints["github"]
	if len(ep.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(ep.Rules))
	}
	r := ep.Rules[0]
	if r.Template != "" {
		t.Errorf("Template = %q, want empty", r.Template)
	}
	if r.TemplateRenderer != nil {
		t.Errorf("TemplateRenderer = %v, want nil", r.TemplateRenderer)
	}
	if got := runtime.RenderTemplate(r, &match.Request{Family: "http"}); got != "" {
		t.Errorf("RenderTemplate with no template = %q, want \"\"", got)
	}
}

// TestRenderTemplateFallsBackOnEvalError exercises the render-time
// failure path: a template that compiles but errors at eval (here:
// indexing into a string-valued field) renders to "" so the caller
// falls back to the approver's default format.
func TestRenderTemplateFallsBackOnEvalError(t *testing.T) {
	cp := compileFixture(t, `
credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

approver "human_approver" "ops" { channel = "#ops" }

rule "writes" {
  endpoint = github
  approve  = [ops]
  template = "http.headers['x-missing'][0]"
}

profile "default" { endpoints = [github] }
`)
	ep := cp.Endpoints["github"]
	r := ep.Rules[0]
	u, _ := url.Parse("https://api.github.com/")
	req := &match.Request{
		Family:  "http",
		Method:  "POST",
		URL:     u,
		Headers: http.Header{},
	}
	if got := runtime.RenderTemplate(r, req); got != "" {
		t.Errorf("RenderTemplate after eval error = %q, want \"\"", got)
	}
}

func TestRenderTemplateNilRuleSafe(t *testing.T) {
	if got := runtime.RenderTemplate(nil, &match.Request{}); got != "" {
		t.Errorf("RenderTemplate(nil, ...) = %q, want \"\"", got)
	}
	if got := runtime.RenderTemplate(&config.CompiledRule{}, nil); got != "" {
		t.Errorf("RenderTemplate(rule, nil) = %q, want \"\"", got)
	}
}

// TestTemplateAcrossFacetsCompiles ensures every registered facet
// exposes a working NewTemplate hook with the same compile-time
// type checks the matcher enforces.
func TestTemplateAcrossFacetsCompiles(t *testing.T) {
	cases := []struct {
		family string
		expr   string
	}{
		{"http", "'method: ' + http.method"},
		{"sql", "'verb: ' + sql.verb"},
		{"k8s", "'verb: ' + k8s.verb"},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			r, err := facet.NewTemplate(tc.family, tc.expr)
			if err != nil {
				t.Fatalf("NewTemplate(%s, %q): %v", tc.family, tc.expr, err)
			}
			if r == nil {
				t.Fatalf("NewTemplate(%s) returned nil renderer", tc.family)
			}
		})
	}
}

func TestNewTemplateRejectsNonStringOnEveryFacet(t *testing.T) {
	cases := []struct {
		family string
		expr   string
	}{
		{"http", "http.method == 'GET'"},
		{"sql", "sql.verb == 'select'"},
		{"k8s", "k8s.verb == 'get'"},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			if _, err := facet.NewTemplate(tc.family, tc.expr); err == nil {
				t.Errorf("NewTemplate(%s, %q): want error, got nil", tc.family, tc.expr)
			} else if !strings.Contains(err.Error(), "string") {
				t.Errorf("NewTemplate(%s): unexpected error %v", tc.family, err)
			}
		})
	}
}
