package main

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// TestProfileDetailFlowGraph covers the four endpoint shapes the
// dashboard's flow map renders: direct (endpoint → rules → cred),
// tunneled (endpoint → tunnel → rules → cred), single-credential
// (rules converge to one credential), and multi-credential with
// disambiguators (each binding carries the operator-set discriminator
// keys/values the dispatcher uses to pick between credentials on the
// same endpoint).
func TestProfileDetailFlowGraph(t *testing.T) {
	src := `
endpoint "https" "github" {
  hosts = ["api.github.com"]
}
endpoint "https" "alpha" {
  hosts = ["alpha.example"]
}
endpoint "postgres" "pg" {
  host = "pg.internal:5432"
}

credential "bearer_token" "gh"        { endpoint = https.github }
credential "bearer_token" "alpha_tok" { endpoint = https.alpha }
credential "postgres_credential" "pg_ro" {
  user      = "ro_app"
  endpoints = [postgres.pg]
}
credential "postgres_credential" "pg_rw" {
  user      = "rw_app"
  endpoints = [postgres.pg]
}

profile "default" {
  credentials = [
    bearer_token.gh,
    bearer_token.alpha_tok,
    { credential = postgres_credential.pg_ro, user = "ro_app" },
    { credential = postgres_credential.pg_rw, user = "rw_app" },
  ]
}

rule "gh-allow" {
  verdict  = "allow"
  endpoint = https.github
}
rule "alpha-allow" {
  verdict  = "allow"
  endpoint = https.alpha
}
rule "pg-allow" {
  verdict  = "allow"
  endpoint = postgres.pg
}
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "profiles-v2-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	prof := policy.Profiles["default"]
	if prof == nil {
		t.Fatalf("compile lost profile 'default'")
	}

	detail := buildProfileDetail("default", prof, policy, 3)
	if detail.Devices != 3 {
		t.Errorf("Devices = %d want 3", detail.Devices)
	}
	if detail.Endpoints == nil || len(detail.Endpoints) != 3 {
		t.Fatalf("endpoints = %d want 3 (%+v)", len(detail.Endpoints), detail.Endpoints)
	}

	byName := map[string]ProfileEndpoint{}
	for _, ep := range detail.Endpoints {
		byName[ep.Name] = ep
	}

	// direct endpoint, single rule converging to one credential
	gh, ok := byName["github"]
	if !ok {
		t.Fatalf("missing endpoint 'github'")
	}
	if len(gh.TunnelChain) != 0 {
		t.Errorf("github tunnel chain = %v want empty", gh.TunnelChain)
	}
	if len(gh.Rules) != 1 || gh.Rules[0].Name != "gh-allow" {
		t.Errorf("github rules = %+v want [gh-allow]", gh.Rules)
	}
	if len(gh.Credentials) != 1 || gh.Credentials[0].Credential != "gh" {
		t.Errorf("github credentials = %+v want [gh]", gh.Credentials)
	}
	if len(gh.Credentials[0].Disambiguators) != 0 {
		t.Errorf("github disambiguators = %v want empty (single-cred endpoint)", gh.Credentials[0].Disambiguators)
	}

	// alpha — also single-credential, distinct from github so we
	// confirm credential scoping is per-endpoint not per-profile.
	alpha, ok := byName["alpha"]
	if !ok {
		t.Fatalf("missing endpoint 'alpha'")
	}
	if len(alpha.Credentials) != 1 || alpha.Credentials[0].Credential != "alpha_tok" {
		t.Errorf("alpha credentials = %+v want [alpha_tok] (regression guard for cl-lgwg)", alpha.Credentials)
	}

	// multi-credential endpoint with disambiguators
	pg, ok := byName["pg"]
	if !ok {
		t.Fatalf("missing endpoint 'pg'")
	}
	if len(pg.Credentials) != 2 {
		t.Fatalf("pg credentials = %d want 2 (%+v)", len(pg.Credentials), pg.Credentials)
	}
	for _, b := range pg.Credentials {
		if len(b.Disambiguators) == 0 {
			t.Errorf("pg binding %q missing disambiguators", b.Credential)
			continue
		}
		want := map[string]string{"pg_ro": "ro_app", "pg_rw": "rw_app"}[b.Credential]
		if want == "" {
			t.Errorf("pg binding for unexpected credential %q", b.Credential)
			continue
		}
		if got := b.Disambiguators["user"]; got != `"`+want+`"` && got != want {
			t.Errorf("pg binding %q user disambiguator = %q want %q", b.Credential, got, want)
		}
	}
}

// TestProfileEndpointTunnelChain covers the tunneled endpoint case
// — the dashboard must render a tunnel node between the endpoint
// and its rules. CompiledEndpoint.Tunnel is the source of truth;
// the test asserts the chain shows up in the JSON shape the flow
// map walks.
func TestProfileEndpointTunnelChain(t *testing.T) {
	src := `
credential "bearer_token" "tok" {}
tunnel "local_command" "bastion" {
  command    = ["ssh", "bastion"]
  listen     = "127.0.0.1:7001"
  keepalive  = "always"
  credential = bearer_token.tok
}
endpoint "https" "internal" {
  hosts  = ["api.internal"]
  tunnel = local_command.bastion
}
credential "bearer_token" "api" { endpoint = https.internal }
profile "tunneled" {
  credentials = [bearer_token.api]
}
rule "ok" {
  verdict  = "allow"
  endpoint = https.internal
}
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "tunnel.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	prof := policy.Profiles["tunneled"]
	detail := buildProfileDetail("tunneled", prof, policy, 0)
	if len(detail.Endpoints) != 1 {
		t.Fatalf("endpoints = %d want 1", len(detail.Endpoints))
	}
	ep := detail.Endpoints[0]
	if len(ep.TunnelChain) != 1 {
		t.Fatalf("tunnel chain = %d want 1 (%+v)", len(ep.TunnelChain), ep.TunnelChain)
	}
	if ep.TunnelChain[0].Name != "bastion" {
		t.Errorf("tunnel chain[0].Name = %q want bastion", ep.TunnelChain[0].Name)
	}
	if ep.TunnelChain[0].Credential != "tok" {
		t.Errorf("tunnel chain[0].Credential = %q want tok", ep.TunnelChain[0].Credential)
	}
	// Summary count: the tunnel's credential ("tok") is reachable via
	// the profile, so the credentials count must include both
	// profile-declared ("api") and tunnel-attached ("tok") creds.
	if detail.Credentials != 2 {
		t.Errorf("credentials count = %d want 2 (profile + tunnel-attached)", detail.Credentials)
	}
	if detail.Tunnels != 1 {
		t.Errorf("tunnels = %d want 1", detail.Tunnels)
	}
}

// TestProfileSummaryCounts checks each card field counts the right
// entity: devices comes from the agent snapshot, endpoints/tunnels/
// rules dedup correctly across the endpoint set, credentials covers
// both direct + tunnel-attached entries.
func TestProfileSummaryCounts(t *testing.T) {
	src := `
endpoint "https" "github" { hosts = ["api.github.com"] }
endpoint "https" "alpha"  { hosts = ["alpha.example"] }
credential "bearer_token" "gh"    { endpoint = https.github }
credential "bearer_token" "alpha" { endpoint = https.alpha }
profile "prod"    { credentials = [bearer_token.gh, bearer_token.alpha] }
profile "staging" { credentials = [bearer_token.gh] }
rule "ok" {
  verdict   = "allow"
  endpoints = [https.github, https.alpha]
}
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "summary.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	sums := buildProfileSummaries(policy, map[string]int{"prod": 7}, gw.Policy)
	if len(sums) != 2 {
		t.Fatalf("summaries = %d want 2 (%+v)", len(sums), sums)
	}
	byName := map[string]ProfileSummary{}
	for _, s := range sums {
		byName[s.Name] = s
	}
	prod := byName["prod"]
	if prod.Devices != 7 {
		t.Errorf("prod.Devices = %d want 7", prod.Devices)
	}
	if prod.Endpoints != 2 {
		t.Errorf("prod.Endpoints = %d want 2", prod.Endpoints)
	}
	if prod.Credentials != 2 {
		t.Errorf("prod.Credentials = %d want 2", prod.Credentials)
	}
	if prod.Rules != 1 {
		t.Errorf("prod.Rules = %d want 1 (rule attached twice but declared once)", prod.Rules)
	}
	if prod.Tunnels != 0 {
		t.Errorf("prod.Tunnels = %d want 0", prod.Tunnels)
	}
	staging := byName["staging"]
	if staging.Endpoints != 1 || staging.Credentials != 1 {
		t.Errorf("staging counts = %+v want {Endpoints:1 Credentials:1}", staging)
	}
	if staging.Devices != 0 {
		t.Errorf("staging.Devices = %d want 0 (no agents pinned)", staging.Devices)
	}
}
