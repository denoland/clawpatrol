package main

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all" // register builtin plugins
)

// TestCredentialBindings verifies the IntegrationRow Profiles +
// Endpoints fan-out: each declared credential gathers the endpoint
// names it's bound to (directly or via a tunnel) and the profiles
// whose endpoint set references any of those endpoints.
func TestCredentialBindings(t *testing.T) {
	src := `
endpoint "https" "alpha_api" {
  hosts = ["alpha.example"]
}
endpoint "https" "beta_api" {
  hosts = ["beta.example"]
}
endpoint "https" "beta_api_2" {
  hosts = ["beta2.example"]
}

credential "bearer_token" "alpha"  { endpoint = https.alpha_api }
credential "bearer_token" "beta"   { endpoints = [https.beta_api, https.beta_api_2] }
credential "bearer_token" "orphan" {}

profile "prod" {
  credentials = [bearer_token.alpha, bearer_token.beta]
}
profile "staging" {
  credentials = [bearer_token.beta]
}

rule "default-allow" {
  verdict   = "allow"
  endpoints = [https.alpha_api, https.beta_api, https.beta_api_2]
}
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "bindings-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	cases := []struct {
		name      string
		profiles  []string
		endpoints []string
	}{
		{"alpha", []string{"prod"}, []string{"alpha_api"}},
		{"beta", []string{"prod", "staging"}, []string{"beta_api", "beta_api_2"}},
		{"orphan", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			profs, eps := credentialBindings(policy, c.name)
			if !sliceEq(profs, c.profiles) {
				t.Errorf("profiles got %v want %v", profs, c.profiles)
			}
			if !sliceEq(eps, c.endpoints) {
				t.Errorf("endpoints got %v want %v", eps, c.endpoints)
			}
		})
	}
}

// Settings-page Profiles column must NOT leak sibling profiles onto
// a credential's row. Regression for cl-c38g (inverse of cl-lgwg):
// credentialBindings previously walked the global endpoint→credentials
// list to populate profiles, so any profile routing through a shared
// endpoint claimed every credential bound to that endpoint. The
// postgres "pg" endpoint binds both pg-readonly and pg-writer; profile
// "data" declares only pg-readonly and must appear under pg-readonly
// only, not pg-writer.
func TestCredentialBindingsDoesNotLeakSiblingProfiles(t *testing.T) {
	pgTargets := config.FrameworkAttrs{
		RefLists: map[string][]string{"endpoints": {"pg"}},
	}
	readonly := &config.Entity{Symbol: &config.Symbol{Name: "pg-readonly"}, Framework: pgTargets}
	writer := &config.Entity{Symbol: &config.Symbol{Name: "pg-writer"}, Framework: pgTargets}
	ep := &config.CompiledEndpoint{
		Name:        "pg",
		Credentials: []*config.Entity{readonly, writer},
	}
	policy := &config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{"pg": ep},
		Credentials: map[string]*config.Entity{
			"pg-readonly": readonly,
			"pg-writer":   writer,
		},
		Profiles: map[string]*config.CompiledProfile{
			"data": {
				Credentials: []*config.Entity{readonly},
				Endpoints:   map[string]*config.CompiledEndpoint{"pg": ep},
			},
			"platform": {
				Credentials: []*config.Entity{writer},
				Endpoints:   map[string]*config.CompiledEndpoint{"pg": ep},
			},
		},
	}
	roProfs, roEps := credentialBindings(policy, "pg-readonly")
	if !sliceEq(roProfs, []string{"data"}) {
		t.Errorf("pg-readonly profiles got %v want [data] (must not include platform)", roProfs)
	}
	if !sliceEq(roEps, []string{"pg"}) {
		t.Errorf("pg-readonly endpoints got %v want [pg]", roEps)
	}
	wrProfs, wrEps := credentialBindings(policy, "pg-writer")
	if !sliceEq(wrProfs, []string{"platform"}) {
		t.Errorf("pg-writer profiles got %v want [platform] (must not include data)", wrProfs)
	}
	if !sliceEq(wrEps, []string{"pg"}) {
		t.Errorf("pg-writer endpoints got %v want [pg]", wrEps)
	}
}

// Tunnel-attached credentials must still surface on every profile
// whose endpoint set reaches the tunnel — mirrors the tunnel walk
// kept in credentialsInProfile after the cl-lgwg fix.
func TestCredentialBindingsSurfacesTunnelAttachedCredentials(t *testing.T) {
	tailnet := &config.Entity{Symbol: &config.Symbol{Name: "tailnet-auth"}}
	ep := &config.CompiledEndpoint{
		Name:   "internal_api",
		Tunnel: &config.CompiledTunnel{Name: "corp", Credential: tailnet},
	}
	policy := &config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{"internal_api": ep},
		Profiles: map[string]*config.CompiledProfile{
			"eng": {
				Endpoints: map[string]*config.CompiledEndpoint{"internal_api": ep},
			},
		},
	}
	profs, _ := credentialBindings(policy, "tailnet-auth")
	if !sliceEq(profs, []string{"eng"}) {
		t.Errorf("tailnet-auth profiles got %v want [eng] via tunnel walk", profs)
	}
}

// TestCredentialConfigOperatorFields extracts the per-credential
// operator-set HCL attrs back from the Emit hook. Postgres exposes
// `user`; the dashboard's details table renders it as a column.
func TestCredentialConfigOperatorFields(t *testing.T) {
	src := `
credential "postgres_credential" "db" {
  user = "ro_app"
}
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "cfg-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ent := policy.Credentials["db"]
	if ent == nil {
		t.Fatal("missing db credential")
	}
	cfg := credentialConfig(ent, "db")
	got, ok := cfg["user"]
	if !ok {
		t.Fatalf("expected user attr, got %v", cfg)
	}
	if !strings.Contains(got, "ro_app") {
		t.Errorf("user value %q does not contain ro_app", got)
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
