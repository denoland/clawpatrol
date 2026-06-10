package config_test

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// TestMiddlewareChainResolves loads an endpoint with an ordered
// `middleware = [...]` list and verifies the compiled endpoint carries
// the two middlewares in declared order, and that cp.Middlewares indexes
// both.
func TestMiddlewareChainResolves(t *testing.T) {
	src := `
middleware "anthropic_system_prompt" "first" {
  text = "AAA"
}
middleware "anthropic_system_prompt" "second" {
  text = "BBB"
}
endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  middleware = [anthropic_system_prompt.first, anthropic_system_prompt.second]
}
credential "anthropic_manual_key" "key" {
  endpoint = https.anthropic
}
profile "default" { credentials = [anthropic_manual_key.key] }
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "mw.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cp.Middlewares) != 2 {
		t.Fatalf("cp.Middlewares = %d, want 2", len(cp.Middlewares))
	}
	ep := cp.Endpoints["anthropic"]
	if ep == nil {
		t.Fatal("missing compiled anthropic endpoint")
	}
	if len(ep.Middleware) != 2 {
		t.Fatalf("ep.Middleware = %d, want 2", len(ep.Middleware))
	}
	if ep.Middleware[0].Name != "first" || ep.Middleware[1].Name != "second" {
		t.Errorf("middleware order = [%q, %q], want [first, second]",
			ep.Middleware[0].Name, ep.Middleware[1].Name)
	}
	// Compiled pointers are shared with the policy-level index.
	if ep.Middleware[0] != cp.Middlewares["first"] {
		t.Error("ep.Middleware[0] is not the cp.Middlewares[\"first\"] instance")
	}
}

// TestMiddlewareHostCompatDiagnostic verifies the loader rejects an
// anthropic_system_prompt middleware attached to an endpoint that
// doesn't serve api.anthropic.com.
func TestMiddlewareHostCompatDiagnostic(t *testing.T) {
	src := `
middleware "anthropic_system_prompt" "inj" {
  text = "AAA"
}
endpoint "https" "openai" {
  hosts      = ["api.openai.com"]
  middleware = [anthropic_system_prompt.inj]
}
credential "bearer_token" "k" {
  endpoint = https.openai
}
profile "default" { credentials = [bearer_token.k] }
`
	_, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "mw_bad.hcl")
	if !diags.HasErrors() {
		t.Fatal("expected a host-incompatibility diagnostic, got none")
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Summary, "incompatible with endpoint") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing incompatibility diagnostic; got %v", diags)
	}
}

// TestMiddlewareUnknownReference verifies an endpoint referencing a
// middleware that wasn't declared is rejected at load.
func TestMiddlewareUnknownReference(t *testing.T) {
	src := `
endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  middleware = [anthropic_system_prompt.missing]
}
credential "anthropic_manual_key" "key" {
  endpoint = https.anthropic
}
profile "default" { credentials = [anthropic_manual_key.key] }
`
	_, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "mw_unknown.hcl")
	if !diags.HasErrors() {
		t.Fatal("expected an unknown-middleware diagnostic, got none")
	}
}

// TestMiddlewareEmitRoundTrip verifies a loaded middleware block plus its
// endpoint attachment survive Emit → Load with the chain intact.
func TestMiddlewareEmitRoundTrip(t *testing.T) {
	src := `
middleware "anthropic_system_prompt" "first" {
  text = "AAA"
}
middleware "anthropic_system_prompt" "second" {
  text = "BBB"
}
endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  middleware = [anthropic_system_prompt.first, anthropic_system_prompt.second]
}
credential "anthropic_manual_key" "key" {
  endpoint = https.anthropic
}
profile "default" { credentials = [anthropic_manual_key.key] }
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "mw.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	out, err := config.Emit(gw)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !strings.Contains(string(out), `middleware "anthropic_system_prompt" "first"`) {
		t.Errorf("emit missing middleware block:\n%s", out)
	}
	if !strings.Contains(string(out), "anthropic_system_prompt.first") {
		t.Errorf("emit missing endpoint middleware ref:\n%s", out)
	}

	gw2, diags := config.LoadBytes(out, "mw_round.hcl")
	if diags.HasErrors() {
		t.Fatalf("reload emitted: %v\n%s", diags, out)
	}
	cp2, err := config.Compile(gw2)
	if err != nil {
		t.Fatalf("recompile: %v", err)
	}
	ep := cp2.Endpoints["anthropic"]
	if ep == nil || len(ep.Middleware) != 2 {
		t.Fatalf("round-trip lost middleware chain: %+v", ep)
	}
	if ep.Middleware[0].Name != "first" || ep.Middleware[1].Name != "second" {
		t.Errorf("round-trip order = [%q, %q]", ep.Middleware[0].Name, ep.Middleware[1].Name)
	}
}
