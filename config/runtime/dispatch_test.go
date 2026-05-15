package runtime_test

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
	sqlfacet "github.com/denoland/clawpatrol/config/plugins/facets/sql"
	"github.com/denoland/clawpatrol/config/runtime"
)

func newSQLMetaForVerb(verb string) *sqlfacet.Meta {
	return &sqlfacet.Meta{Verb: verb}
}

const fixture = `
credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com", "github.com"]
  credential = pat
}

profile "default" { endpoints = [github] }

rule "reads" {
  endpoint  = github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "writes" {
  endpoint  = github
  condition = "http.method in ['POST', 'PATCH', 'DELETE']"
  verdict   = "deny"
  reason    = "writes go through PR review"
}
rule "github-default" {
  endpoint = github
  priority = -100
  verdict  = "deny"
  reason   = "no policy matched"
}
`

func compile(t *testing.T) *config.CompiledPolicy {
	t.Helper()
	return compileFixture(t, fixture)
}

func compileFixture(t *testing.T, src string) *config.CompiledPolicy {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(src), "in.hcl")
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

// TestHostEndpointIsCaseInsensitive guards against a regression where a
// config-declared uppercase host (common with EKS cluster apiservers,
// e.g. "3F6827…GR7.us-east-2.eks.amazonaws.com") failed to match a
// lowercase SNI value sent by TLS clients like curl. DNS hostnames are
// case-insensitive; the lookup must be too.
func TestHostEndpointIsCaseInsensitive(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "eks" {
  hosts = ["AB123.gr7.us-east-2.eks.amazonaws.com"]
}
profile "default" { endpoints = [eks] }
`)

	if got := runtime.HostEndpoint(cp, "default", "ab123.gr7.us-east-2.eks.amazonaws.com"); got == nil || got.Name != "eks" {
		t.Fatalf("lowercase SNI against uppercase config: got %+v, want eks", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "AB123.GR7.US-EAST-2.EKS.AMAZONAWS.COM"); got == nil || got.Name != "eks" {
		t.Fatalf("uppercase lookup: got %+v, want eks", got)
	}
}

func TestHostEndpointMatchesBareSNIForPortQualifiedHost(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "api" {
  hosts = ["api.example.com:443"]
}
profile "default" { endpoints = [api] }
`)

	if got := runtime.HostEndpoint(cp, "default", "api.example.com"); got == nil || got.Name != "api" {
		t.Fatalf("bare SNI host resolved to %+v, want api", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "api.example.com:443"); got == nil || got.Name != "api" {
		t.Fatalf("exact port-qualified host resolved to %+v, want api", got)
	}
	if got := runtime.HostEndpoint(cp, "missing-profile", "api.example.com"); got == nil || got.Name != "api" {
		t.Fatalf("fallback scan resolved to %+v, want api", got)
	}
}

func TestHostEndpointMatchesBareSNIForPortQualifiedKubernetesServer(t *testing.T) {
	cp := compileFixture(t, `
endpoint "kubernetes" "cluster" {
  server = "cluster.example.com:443"
}
profile "default" { endpoints = [cluster] }
`)

	if got := runtime.HostEndpoint(cp, "default", "cluster.example.com"); got == nil || got.Name != "cluster" {
		t.Fatalf("bare Kubernetes SNI host resolved to %+v, want cluster", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "cluster.example.com:443"); got == nil || got.Name != "cluster" {
		t.Fatalf("exact Kubernetes server host resolved to %+v, want cluster", got)
	}
}

func TestHostEndpointBareHostExactBindingBeatsPortAlias(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "port_qualified" {
  hosts = ["api.example.com:443"]
}
endpoint "https" "bare" {
  hosts = ["api.example.com"]
}
profile "default" { endpoints = [port_qualified, bare] }
`)

	if got := runtime.HostEndpoint(cp, "default", "api.example.com"); got == nil || got.Name != "bare" {
		t.Fatalf("bare host resolved to %+v, want explicit bare endpoint", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "api.example.com:443"); got == nil || got.Name != "port_qualified" {
		t.Fatalf("port-qualified host resolved to %+v, want port-qualified endpoint", got)
	}
}

func TestHostEndpointDoesNotAliasNonDefaultHTTPSPort(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "api" {
  hosts = ["api.example.com:8443"]
}
profile "default" { endpoints = [api] }
`)

	if got := runtime.HostEndpoint(cp, "default", "api.example.com"); got != nil {
		t.Fatalf("bare host resolved to %+v, want nil for non-default port alias", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "api.example.com:8443"); got == nil || got.Name != "api" {
		t.Fatalf("exact non-default port host resolved to %+v, want api", got)
	}
}

func TestHostEndpointDoesNotAliasNonHTTPFamilies(t *testing.T) {
	cp := compileFixture(t, `
endpoint "postgres" "db" {
  host = "db.example.com:5432"
}
profile "default" { endpoints = [db] }
`)

	if got := runtime.HostEndpoint(cp, "default", "db.example.com"); got != nil {
		t.Fatalf("bare SQL host resolved to %+v, want nil", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "db.example.com:5432"); got == nil || got.Name != "db" {
		t.Fatalf("exact SQL host resolved to %+v, want db", got)
	}
}

func TestHostEndpointPortAliasCannotBeCapturedByNonHTTPExactCollision(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "api" {
  hosts = ["api.example.com:443"]
}
endpoint "postgres" "db" {
  host = "api.example.com:443"
}
profile "default" { endpoints = [api, db] }
`)

	if got := runtime.HostEndpoint(cp, "default", "api.example.com"); got == nil || got.Name != "api" {
		t.Fatalf("bare SNI host resolved to %+v, want HTTPS endpoint", got)
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
			req := &match.Request{Family: "http", Method: tc.method}
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

// TestMatchRequestTruncated pins the fail-closed dispatch on a
// request whose facet bytes were truncated by the wire frontend's
// inspection cap. Two rules: a verb-only allow that does NOT read
// any truncatable sql.* field, and a statement-contains deny that
// DOES. With Truncated=false the verb rule fires on a SELECT. With
// Truncated=true the verb rule (sql.verb is truncatable) is
// auto-synth-denied — the body-reading rule never even gets a turn,
// because the verb rule's priority comes first.
func TestMatchRequestTruncated(t *testing.T) {
	cp := compileFixture(t, `
endpoint "postgres" "db" {
  host = "db.example.com:5432"
}
profile "default" { endpoints = [db] }

rule "select-allow" {
  endpoint  = db
  condition = "sql.verb == 'select'"
  verdict   = "allow"
}
rule "default-deny" {
  endpoint = db
  priority = -100
  verdict  = "deny"
  reason   = "no policy matched"
}
`)
	ep := cp.Endpoints["db"]

	// Untruncated SELECT → allow fires normally.
	req := &match.Request{
		Family: "sql",
		Meta:   newSQLMetaForVerb("select"),
	}
	r := runtime.MatchRequest(ep, req)
	if r == nil || r.Name != "select-allow" || r.Outcome.Verdict != "allow" {
		t.Fatalf("untruncated select: got %+v, want select-allow allow", r)
	}

	// Truncated SELECT → verb-reading rule synthesizes deny.
	req.Truncated = true
	r = runtime.MatchRequest(ep, req)
	if r == nil {
		t.Fatalf("truncated select: got nil, want synth deny")
	}
	if r.Name != "select-allow" {
		t.Errorf("synth deny should preserve original rule name, got %q want select-allow", r.Name)
	}
	if r.Outcome.Verdict != "deny" {
		t.Errorf("synth deny verdict = %q, want deny", r.Outcome.Verdict)
	}
	if r.Outcome.Reason == "" {
		t.Errorf("synth deny reason is empty, want a non-empty fabricated reason")
	}
}

// TestMatchRequestTruncatedSkipsRulesThatDontReadTruncatedFacets
// pins the OTHER half of the fail-closed contract: a rule whose
// matcher reads zero truncatable facets still gets its normal
// Match call. Here, a higher-priority "credential = X" rule with a
// catch-all condition fires on a truncated request whose
// dispatching credential matches — the truncation only affects
// rules that actually read truncatable facet bytes.
func TestMatchRequestTruncatedSkipsRulesThatDontReadTruncatedFacets(t *testing.T) {
	cp := compileFixture(t, `
credential "bearer_token" "tok" {}
endpoint "https" "api" {
  hosts      = ["api.example.com"]
  credential = tok
}
profile "default" { endpoints = [api] }

rule "by-credential" {
  endpoint   = api
  credential = tok
  verdict    = "allow"
}
rule "body-deny" {
  endpoint  = api
  condition = "http.body.contains('drop')"
  priority  = -50
  verdict   = "deny"
}
`)
	ep := cp.Endpoints["api"]

	req := &match.Request{
		Family:     "https",
		Method:     "POST",
		Credential: "tok",
		Body:       []byte("anything"),
		Truncated:  true,
	}
	r := runtime.MatchRequest(ep, req)
	if r == nil {
		t.Fatalf("truncated request: got nil, want by-credential allow")
	}
	if r.Name != "by-credential" {
		t.Errorf("rule = %q, want by-credential (truncation must not promote a lower-priority body rule over a credential rule)", r.Name)
	}
	if r.Outcome.Verdict != "allow" {
		t.Errorf("verdict = %q, want allow (the credential rule reads no truncatable facets)", r.Outcome.Verdict)
	}
}

// TestResolveCredentialSingular: one credential, no placeholder →
// returned without consulting the endpoint plugin's detector.
func TestResolveCredentialSingular(t *testing.T) {
	cp := compile(t)
	ep := cp.Endpoints["github"]
	got := runtime.ResolveCredential(ep, &match.Request{Family: "http", Headers: http.Header{}})
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
		return &match.Request{Family: "http", Headers: h}
	}

	got := runtime.ResolveCredential(ep, mkReq("Bearer PH_prod"))
	if got == nil || got.Credential.Symbol.Name != "prod" {
		t.Errorf("Authorization=Bearer PH_prod should select prod, got %+v", got)
	}
	basicPlaceholder := base64.StdEncoding.EncodeToString([]byte("git-user:PH_test"))
	got = runtime.ResolveCredential(ep, mkReq("Basic "+basicPlaceholder))
	if got == nil || got.Credential.Symbol.Name != "test" {
		t.Errorf("Authorization=Basic base64(git-user:PH_test) should select test, got %+v", got)
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

// TestResolveCredentialDatabaseOnly: entries dispatch on
// req.Database alone — no placeholder constraint involved.
func TestResolveCredentialDatabaseOnly(t *testing.T) {
	src := `
credential "clickhouse_credential" "prod"     {}
credential "clickhouse_credential" "dev"      {}
credential "clickhouse_credential" "fallback" {}
endpoint "clickhouse_native" "ep" {
  hosts = ["x.example.com"]
  credentials = [
    { database  = "prod",          credential = prod     },
    { databases = ["dev", "qa"],   credential = dev      },
    { credential = fallback },
  ]
}
profile "default" { endpoints = [ep] }
`
	cp := compileFixture(t, src)
	ep := cp.Endpoints["ep"]

	cases := []struct {
		db   string
		want string
	}{
		{"prod", "prod"},
		{"dev", "dev"},
		{"qa", "dev"},
		{"unknown", "fallback"},
		{"", "fallback"},
	}
	for _, tc := range cases {
		t.Run(tc.db, func(t *testing.T) {
			got := runtime.ResolveCredential(ep, &match.Request{Family: "sql", Database: tc.db})
			if got == nil || got.Credential.Symbol.Name != tc.want {
				t.Errorf("db=%q got %+v, want %s", tc.db, got, tc.want)
			}
		})
	}
}

// TestResolveCredentialPlaceholderAndDatabase: most-specific wins
// when an entry constrains both placeholder and database. A
// placeholder-only entry stays available as the fallback for the
// same placeholder against a different database.
func TestResolveCredentialPlaceholderAndDatabase(t *testing.T) {
	src := `
credential "bearer_token" "ro-prod" {}
credential "bearer_token" "ro-any"  {}
credential "bearer_token" "any"     {}
endpoint "https" "ep" {
  hosts = ["x.example.com"]
  credentials = [
    { placeholder = "PH_ro", database = "prod", credential = ro-prod },
    { placeholder = "PH_ro",                    credential = ro-any  },
    { credential = any },
  ]
}
profile "default" { endpoints = [ep] }
`
	cp := compileFixture(t, src)
	ep := cp.Endpoints["ep"]

	mkReq := func(authz, db string) *match.Request {
		return &match.Request{
			Family:   "http",
			Headers:  http.Header{"Authorization": []string{authz}},
			Database: db,
		}
	}

	got := runtime.ResolveCredential(ep, mkReq("Bearer PH_ro", "prod"))
	if got == nil || got.Credential.Symbol.Name != "ro-prod" {
		t.Errorf("placeholder+db should pick ro-prod, got %+v", got)
	}
	got = runtime.ResolveCredential(ep, mkReq("Bearer PH_ro", "dev"))
	if got == nil || got.Credential.Symbol.Name != "ro-any" {
		t.Errorf("placeholder-only should pick ro-any, got %+v", got)
	}
	got = runtime.ResolveCredential(ep, mkReq("Bearer something-else", "prod"))
	if got == nil || got.Credential.Symbol.Name != "any" {
		t.Errorf("no constraints match should pick catchall, got %+v", got)
	}
}
