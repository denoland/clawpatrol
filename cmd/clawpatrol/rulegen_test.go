package main

import (
	"strings"
	"testing"

	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestGenerateRuleHTTPExact(t *testing.T) {
	g := gatewayWithPolicy(t, fixtureHCL)
	rule, err := GenerateRuleFromEvent(g.Policy(), &Event{
		ID:       "018f0000-0000-7000-8000-000000000001",
		Endpoint: "github",
		Method:   "DELETE",
		Path:     "/repos/me/sandbox/issues/1?force=true",
	}, RuleGenOptions{Verdict: "deny", Scope: "exact"})
	if err != nil {
		t.Fatalf("GenerateRuleFromEvent: %v", err)
	}
	if !strings.Contains(rule.HCL, `endpoint  = https.github`) {
		t.Fatalf("hcl missing typed endpoint:\n%s", rule.HCL)
	}
	wantHTTP := "condition = <<-CEL\n    http.method == 'DELETE'\n    && http.path == '/repos/me/sandbox/issues/1'\n  CEL"
	if !strings.Contains(rule.HCL, wantHTTP) {
		t.Fatalf("hcl missing exact HTTP condition:\n%s", rule.HCL)
	}
	if !strings.Contains(rule.HCL, `verdict   = "deny"`) {
		t.Fatalf("hcl missing deny verdict:\n%s", rule.HCL)
	}
}

func TestGenerateRuleSQLStructuredFacets(t *testing.T) {
	g := gatewayWithPolicy(t, `
endpoint "postgres" "pg" { host = "pg.example.com:5432" }
credential "postgres_credential" "pg-user" { endpoint = postgres.pg }
profile "default" { credentials = [postgres_credential.pg-user] }
`)
	rule, err := GenerateRuleFromEvent(g.Policy(), &Event{
		ID:       "018f0000-0000-7000-8000-000000000002",
		Endpoint: "pg",
		Facets: map[string]any{
			"verb":   "drop",
			"tables": []any{"users"},
		},
	}, RuleGenOptions{Verdict: "deny", Scope: "exact"})
	if err != nil {
		t.Fatalf("GenerateRuleFromEvent: %v", err)
	}
	wantSQL := "condition = <<-CEL\n    sql.verb == 'drop'\n    && 'users' in sql.tables\n  CEL"
	if !strings.Contains(rule.HCL, wantSQL) {
		t.Fatalf("hcl missing SQL condition:\n%s", rule.HCL)
	}
}

func TestGenerateRuleK8sStructuredFacets(t *testing.T) {
	g := gatewayWithPolicy(t, `
endpoint "kubernetes" "prod" { hosts = ["k8s.example.com"] }
credential "bearer_token" "k8s-token" { endpoint = kubernetes.prod }
profile "default" { credentials = [bearer_token.k8s-token] }
`)
	rule, err := GenerateRuleFromEvent(g.Policy(), &Event{
		ID:       "018f0000-0000-7000-8000-000000000003",
		Endpoint: "prod",
		Facets: map[string]any{
			"verb":      "delete",
			"resource":  "secrets",
			"namespace": "prod",
			"name":      "api-token",
		},
	}, RuleGenOptions{Verdict: "deny", Scope: "exact"})
	if err != nil {
		t.Fatalf("GenerateRuleFromEvent: %v", err)
	}
	want := "condition = <<-CEL\n    k8s.verb == 'delete'\n    && k8s.resource == 'secrets'\n    && k8s.namespace == 'prod'\n    && k8s.name == 'api-token'\n  CEL"
	if !strings.Contains(rule.HCL, want) {
		t.Fatalf("hcl missing K8s condition:\n%s", rule.HCL)
	}
}

func TestGenerateRuleRejectsMissingEndpoint(t *testing.T) {
	g := gatewayWithPolicy(t, fixtureHCL)
	_, err := GenerateRuleFromEvent(g.Policy(), &Event{}, RuleGenOptions{Verdict: "deny", Scope: "exact"})
	if err == nil || !strings.Contains(err.Error(), "no endpoint or host") {
		t.Fatalf("err=%v, want no endpoint or host", err)
	}
}

func TestGenerateRuleSpliceHostCreatesEndpointAndDenyRule(t *testing.T) {
	g := gatewayWithPolicy(t, fixtureHCL)
	rule, err := GenerateRuleFromEvent(g.Policy(), &Event{
		ID:     "018f0000-0000-7000-8000-000000000004",
		Mode:   "splice",
		Host:   "TinyClouds.org",
		Action: "allow",
	}, RuleGenOptions{Verdict: "deny", Scope: "exact"})
	if err != nil {
		t.Fatalf("GenerateRuleFromEvent: %v", err)
	}
	if !strings.Contains(rule.HCL, `endpoint "https" "tinyclouds_org"`) {
		t.Fatalf("hcl missing generated endpoint:\n%s", rule.HCL)
	}
	if !strings.Contains(rule.HCL, `hosts = ["tinyclouds.org"]`) {
		t.Fatalf("hcl missing observed host:\n%s", rule.HCL)
	}
	if !strings.Contains(rule.HCL, `endpoint = https.tinyclouds_org`) {
		t.Fatalf("hcl missing generated endpoint reference:\n%s", rule.HCL)
	}
	if !strings.Contains(rule.HCL, `credential "passthrough" "tinyclouds_org_passthrough"`) {
		t.Fatalf("hcl missing generated passthrough credential:\n%s", rule.HCL)
	}
	if !strings.Contains(rule.HCL, `credentials = [passthrough.tinyclouds_org_passthrough]`) {
		t.Fatalf("hcl missing profile credential claim:\n%s", rule.HCL)
	}
	if strings.Contains(rule.HCL, `condition`) {
		t.Fatalf("host block rule should be catch-all:\n%s", rule.HCL)
	}
	if len(rule.Warnings) == 0 {
		t.Fatalf("expected warning for generated endpoint")
	}
}

func TestGeneratedSpliceHostBlockRoutesInDefaultProfile(t *testing.T) {
	g := gatewayWithPolicy(t, `
endpoint "https" "github" {
  hosts = ["api.github.com"]
}
credential "bearer_token" "tok" { endpoint = https.github }

endpoint "https" "tinyclouds_org" {
  hosts = ["tinyclouds.org"]
}

credential "passthrough" "tinyclouds_org_passthrough" {
  endpoint = https.tinyclouds_org
}

rule "block_tinyclouds_org" {
  endpoint = https.tinyclouds_org
  verdict  = "deny"
}

profile "default" {
  credentials = [bearer_token.tok, passthrough.tinyclouds_org_passthrough]
}
`)
	ep := runtime.HostEndpoint(g.Policy(), "default", "tinyclouds.org")
	if ep == nil || ep.Name != "tinyclouds_org" {
		t.Fatalf("HostEndpoint = %#v, want generated endpoint", ep)
	}
}
