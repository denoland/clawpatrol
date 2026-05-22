package runtime_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// benchPolicy: representative HTTPS endpoint with several rules that
// touch different facets (method, headers, body, body_json). The
// HTTPS facet's addActivation is the per-rule allocation that
// dominates the dispatch hot path for HTTPS traffic.
const benchPolicy = `
endpoint "https" "api" {
  hosts = ["api.example.com"]
}
credential "bearer_token" "tok" { endpoint = https.api }
profile "default" { credentials = [bearer_token.tok] }

rule "writes-deny" {
  endpoint  = https.api
  condition = "http.method in ['POST', 'PUT', 'PATCH']"
  verdict   = "deny"
  reason    = "writes denied"
}
rule "secret-deny" {
  endpoint  = https.api
  condition = "http.body.contains('drop table')"
  verdict   = "deny"
  reason    = "destructive verb"
}
rule "json-deny" {
  endpoint  = https.api
  condition = "http.body_json.danger == true"
  verdict   = "deny"
  reason    = "danger flag"
}
rule "header-deny" {
  endpoint  = https.api
  condition = "'evil' in http.headers['x-foo']"
  verdict   = "deny"
}
rule "default-allow" {
  endpoint = https.api
  priority = -100
  verdict  = "allow"
}
`

func benchHTTPSRequest(body []byte) *match.Request {
	u, _ := url.Parse("https://api.example.com/v1/things?q=1")
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Authorization", "Bearer xxxxx")
	h.Set("User-Agent", "agent/1.0")
	h.Set("X-Foo", "harmless")
	return &match.Request{
		Family:  "http",
		Method:  "GET",
		URL:     u,
		Headers: h,
		Body:    body,
	}
}

func compileBenchFixture(b *testing.B, src string) *config.CompiledPolicy {
	b.Helper()
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "in.hcl")
	if diags.HasErrors() {
		b.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		b.Fatalf("compile: %v", err)
	}
	return cp
}

// BenchmarkMatchRequestHTTPSSmallBody covers the dominant gateway hot
// path: per-request dispatch against an endpoint with several rules
// over a small JSON body.
func BenchmarkMatchRequestHTTPSSmallBody(b *testing.B) {
	cp := compileBenchFixture(b, benchPolicy)
	ep := cp.Endpoints["api"]
	body := []byte(`{"hello":"world","danger":false,"nested":{"k":"v"}}`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Fresh Request per iteration mirrors the gateway path —
		// every wire request builds its own match.Request snapshot.
		req := benchHTTPSRequest(body)
		if r := runtime.MatchRequest(ep, req); r == nil {
			b.Fatal("nil rule")
		}
	}
}

// BenchmarkMatchRequestHTTPSLargeJSONBody stresses the body_json
// parse cost. Same request shape, larger JSON body (~32 KiB of
// nested objects). With per-rule body parsing this scales linearly
// with rule count; with caching it stays flat.
func BenchmarkMatchRequestHTTPSLargeJSONBody(b *testing.B) {
	cp := compileBenchFixture(b, benchPolicy)
	ep := cp.Endpoints["api"]
	body := []byte(`{"items":[` + strings.Repeat(`{"name":"x","weight":1.5,"tags":["a","b","c"],"meta":{"k":"v"}},`, 300) + `null]}`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := benchHTTPSRequest(body)
		if r := runtime.MatchRequest(ep, req); r == nil {
			b.Fatal("nil rule")
		}
	}
}

// BenchmarkMatchRequestHTTPSNoBody covers the empty-body case (GET
// requests). Body JSON parse short-circuits but we still want the
// facet activation path to be lean.
func BenchmarkMatchRequestHTTPSNoBody(b *testing.B) {
	cp := compileBenchFixture(b, benchPolicy)
	ep := cp.Endpoints["api"]

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := benchHTTPSRequest(nil)
		if r := runtime.MatchRequest(ep, req); r == nil {
			b.Fatal("nil rule")
		}
	}
}
