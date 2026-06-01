package main

import (
	"strings"
	"testing"

	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
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
	if !strings.Contains(rule.HCL, `condition = "http.method == \"DELETE\" && http.path == \"/repos/me/sandbox/issues/1\""`) {
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
	if !strings.Contains(rule.HCL, `condition = "sql.verb == \"drop\" && \"users\" in sql.tables"`) {
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
	want := `condition = "k8s.verb == \"delete\" && k8s.resource == \"secrets\" && k8s.namespace == \"prod\" && k8s.name == \"api-token\""`
	if !strings.Contains(rule.HCL, want) {
		t.Fatalf("hcl missing K8s condition:\n%s", rule.HCL)
	}
}

func TestGenerateRuleRejectsMissingEndpoint(t *testing.T) {
	g := gatewayWithPolicy(t, fixtureHCL)
	_, err := GenerateRuleFromEvent(g.Policy(), &Event{}, RuleGenOptions{Verdict: "deny", Scope: "exact"})
	if err == nil || !strings.Contains(err.Error(), "no endpoint") {
		t.Fatalf("err=%v, want no endpoint", err)
	}
}
