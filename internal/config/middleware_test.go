package config_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// middlewareSrc declares an Anthropic endpoint with two ordered
// system-prompt middlewares attached. Reused across the resolve /
// ordering tests.
const middlewareSrc = `
middleware "anthropic_system_prompt" "first" {
  text = "FIRST"
}
middleware "anthropic_system_prompt" "second" {
  text = "SECOND"
}
endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  middleware = [anthropic_system_prompt.first, anthropic_system_prompt.second]
}
credential "bearer_token" "key" {
  endpoint = https.anthropic
}
profile "p" { credentials = [bearer_token.key] }
`

// TestMiddlewareResolveAndOrder verifies the new `middleware` block
// parses, the endpoint's `middleware = [...]` reflist resolves to
// shared CompiledMiddleware pointers, and declaration order is
// preserved on the compiled endpoint.
func TestMiddlewareResolveAndOrder(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+middlewareSrc), "mw.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if len(gw.Policy.Middlewares) != 2 {
		t.Fatalf("expected 2 middlewares, got %d", len(gw.Policy.Middlewares))
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ce := cp.Endpoints["anthropic"]
	if ce == nil {
		t.Fatal("missing anthropic endpoint")
	}
	if len(ce.Middleware) != 2 {
		t.Fatalf("endpoint has %d middlewares, want 2", len(ce.Middleware))
	}
	if ce.Middleware[0].Name != "first" || ce.Middleware[1].Name != "second" {
		t.Errorf("middleware order = [%s, %s], want [first, second]",
			ce.Middleware[0].Name, ce.Middleware[1].Name)
	}
	// Pointers are shared with cp.Middlewares.
	if ce.Middleware[0] != cp.Middlewares["first"] {
		t.Error("endpoint middleware is not the same instance as cp.Middlewares")
	}
}

// TestMiddlewareOrderedExecution runs the compiled middleware chain
// against a Messages body and asserts both transforms applied in
// declared order (FIRST appended before SECOND).
func TestMiddlewareOrderedExecution(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+middlewareSrc), "mw.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ce := cp.Endpoints["anthropic"]

	body := []byte(`{"system":"BASE","messages":[]}`)
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(string(body)))
	for _, mw := range ce.Middleware {
		r, ok := mw.Body.(runtime.HTTPMiddleware)
		if !ok {
			t.Fatalf("middleware %q body does not satisfy HTTPMiddleware", mw.Name)
		}
		body, err = r.RewriteHTTPRequest(context.Background(), req, body)
		if err != nil {
			t.Fatalf("middleware %q: %v", mw.Name, err)
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("result not JSON: %v", err)
	}
	want := "BASE\n\nFIRST\n\nSECOND"
	if obj["system"] != want {
		t.Errorf("system = %q, want %q (ordered application)", obj["system"], want)
	}
}

// TestMiddlewareHostCompatDiagnostic verifies the load-time
// compatibility check: attaching anthropic_system_prompt to an
// endpoint that doesn't intercept api.anthropic.com is a clear error.
func TestMiddlewareHostCompatDiagnostic(t *testing.T) {
	src := `
middleware "anthropic_system_prompt" "inject" {
  text = "x"
}
endpoint "https" "openai" {
  hosts      = ["api.openai.com"]
  middleware = [anthropic_system_prompt.inject]
}
credential "bearer_token" "key" {
  endpoint = https.openai
}
profile "p" { credentials = [bearer_token.key] }
`
	_, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "mw.hcl")
	if !diags.HasErrors() {
		t.Fatal("expected a host-compatibility diagnostic, got none")
	}
	var found bool
	for _, d := range diags {
		if strings.Contains(d.Summary, "incompatible with endpoint") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected incompatibility diagnostic, got: %v", diags)
	}
}

// TestMiddlewareRoundTrip verifies a config with middleware blocks
// survives Emit → Load unchanged in structure (block parses back and
// the endpoint re-resolves its middleware list).
func TestMiddlewareRoundTrip(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+middlewareSrc), "mw.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	out, err := config.Emit(gw)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	gw2, diags := config.LoadBytes(out, "mw-roundtrip.hcl")
	if diags.HasErrors() {
		t.Fatalf("reload emitted config: %v\n--- emitted ---\n%s", diags, out)
	}
	cp, err := config.Compile(gw2)
	if err != nil {
		t.Fatalf("compile reloaded: %v", err)
	}
	ce := cp.Endpoints["anthropic"]
	if ce == nil || len(ce.Middleware) != 2 {
		t.Fatalf("round-trip lost middleware wiring: %+v", ce)
	}
	if mw := gw2.Policy.Middlewares["first"]; mw == nil {
		t.Error("round-trip lost middleware block 'first'")
	} else if asp, ok := mw.Body.(interface {
		FileIncludeFields() []config.FileIncludeField
	}); ok {
		if got := asp.FileIncludeFields()[0].Get(); got != "FIRST" {
			t.Errorf("round-trip text = %q, want FIRST", got)
		}
	}
}
