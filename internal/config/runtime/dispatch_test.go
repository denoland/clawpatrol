package runtime_test

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
	sqlfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/sql"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func newSQLMetaForVerb(verb string) *sqlfacet.Meta {
	return &sqlfacet.Meta{Verb: verb}
}

const fixture = `
endpoint "https" "github" {
  hosts = ["api.github.com", "github.com"]
}

credential "bearer_token" "pat" {
  endpoint = https.github
}

profile "default" { credentials = [bearer_token.pat] }

rule "reads" {
  endpoint  = https.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "writes" {
  endpoint  = https.github
  condition = "http.method in ['POST', 'PATCH', 'DELETE']"
  verdict   = "deny"
  reason    = "writes go through PR review"
}
rule "github-default" {
  endpoint = https.github
  priority = -100
  verdict  = "deny"
  reason   = "no policy matched"
}
`

func compile(t *testing.T) *config.CompiledPolicy {
	t.Helper()
	return compileFixture(t, fixture)
}

// testGatewayPrefix wraps inline test fixtures with a minimal valid
// `gateway {}` block so loader-level operational validation passes;
// runtime tests don't care about transport config, only the policy
// blocks they declare.
const testGatewayPrefix = `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

`

func compileFixture(t *testing.T, src string) *config.CompiledPolicy {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "in.hcl")
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
credential "bearer_token" "eks-cred" { endpoint = https.eks }
profile "default" { credentials = [bearer_token.eks-cred] }
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
credential "bearer_token" "api-tok" { endpoint = https.api }
profile "default" { credentials = [bearer_token.api-tok] }
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
credential "bearer_token" "tok" { endpoint = kubernetes.cluster }
profile "default" { credentials = [bearer_token.tok] }
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
credential "bearer_token" "pq-tok"   { endpoint = https.port_qualified }
credential "bearer_token" "bare-tok" { endpoint = https.bare }
profile "default" { credentials = [bearer_token.pq-tok, bearer_token.bare-tok] }
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
credential "bearer_token" "tok" { endpoint = https.api }
profile "default" { credentials = [bearer_token.tok] }
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
credential "postgres_credential" "db-cred" { endpoint = postgres.db }
profile "default" { credentials = [postgres_credential.db-cred] }
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
credential "bearer_token" "api-tok"        { endpoint = https.api }
credential "postgres_credential" "db-cred" { endpoint = postgres.db }
profile "default" { credentials = [bearer_token.api-tok, postgres_credential.db-cred] }
`)

	if got := runtime.HostEndpoint(cp, "default", "api.example.com"); got == nil || got.Name != "api" {
		t.Fatalf("bare SNI host resolved to %+v, want HTTPS endpoint", got)
	}
}

func TestHostEndpointWildcardMatches(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "aws-ep" {
  hosts = ["*.amazonaws.com"]
}
credential "bearer_token" "aws-tok" {
  endpoint = https.aws-ep
}
profile "default" { credentials = [bearer_token.aws-tok] }
`)
	cases := []struct {
		host string
		want string
	}{
		{"s3.amazonaws.com", "aws-ep"},
		{"dynamodb.us-east-1.amazonaws.com", "aws-ep"},
		{"AB.AMAZONAWS.COM", "aws-ep"},
		{"amazonaws.com", ""},
		{"notamazonaws.com", ""},
		{"foo.bar", ""},
	}
	for _, c := range cases {
		got := runtime.HostEndpoint(cp, "default", c.host)
		gotName := ""
		if got != nil {
			gotName = got.Name
		}
		if gotName != c.want {
			t.Errorf("HostEndpoint(%q) = %q, want %q", c.host, gotName, c.want)
		}
	}
}

func TestHostEndpointExactBeatsWildcard(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "aws-ep" {
  hosts = ["*.amazonaws.com"]
}
endpoint "https" "s3-ep" {
  hosts = ["s3.amazonaws.com"]
}
credential "bearer_token" "aws-tok" {
  endpoint = https.aws-ep
}
credential "bearer_token" "s3-tok" {
  endpoint = https.s3-ep
}
profile "default" { credentials = [bearer_token.aws-tok, bearer_token.s3-tok] }
`)
	if got := runtime.HostEndpoint(cp, "default", "s3.amazonaws.com"); got == nil || got.Name != "s3-ep" {
		t.Fatalf("exact host should beat wildcard: got %+v, want s3-ep", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "dynamodb.amazonaws.com"); got == nil || got.Name != "aws-ep" {
		t.Fatalf("uncovered subdomain should fall to wildcard: got %+v, want aws-ep", got)
	}
}

func TestHostEndpointLongestWildcardWins(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "east-ep" {
  hosts = ["*.us-east-1.amazonaws.com"]
}
endpoint "https" "aws-ep" {
  hosts = ["*.amazonaws.com"]
}
credential "bearer_token" "east-tok" {
  endpoint = https.east-ep
}
credential "bearer_token" "aws-tok" {
  endpoint = https.aws-ep
}
profile "default" { credentials = [bearer_token.aws-tok, bearer_token.east-tok] }
`)
	if got := runtime.HostEndpoint(cp, "default", "s3.us-east-1.amazonaws.com"); got == nil || got.Name != "east-ep" {
		t.Fatalf("longest suffix should win: got %+v, want east-ep", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "s3.us-west-2.amazonaws.com"); got == nil || got.Name != "aws-ep" {
		t.Fatalf("shorter pattern picks up the rest: got %+v, want aws-ep", got)
	}
}

func TestHostEndpointWildcardWithPortAlias(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "aws-ep" {
  hosts = ["*.amazonaws.com:443"]
}
credential "bearer_token" "aws-tok" {
  endpoint = https.aws-ep
}
profile "default" { credentials = [bearer_token.aws-tok] }
`)
	if got := runtime.HostEndpoint(cp, "default", "s3.amazonaws.com"); got == nil || got.Name != "aws-ep" {
		t.Fatalf("port-qualified wildcard should match bare SNI: got %+v, want aws-ep", got)
	}
}

func TestHostEndpointWildcardSingleTenantFallback(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "aws-ep" {
  hosts = ["*.amazonaws.com"]
}
credential "bearer_token" "aws-tok" {
  endpoint = https.aws-ep
}
profile "tenant" { credentials = [bearer_token.aws-tok] }
`)
	if got := runtime.HostEndpoint(cp, "missing-profile", "s3.amazonaws.com"); got == nil || got.Name != "aws-ep" {
		t.Fatalf("fallback scan should find wildcard match across profiles: got %+v, want aws-ep", got)
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
credential "postgres_credential" "db-cred" { endpoint = postgres.db }
profile "default" { credentials = [postgres_credential.db-cred] }

rule "select-allow" {
  endpoint  = postgres.db
  condition = "sql.verb == 'select'"
  verdict   = "allow"
}
rule "default-deny" {
  endpoint = postgres.db
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
endpoint "https" "api" {
  hosts = ["api.example.com"]
}
credential "bearer_token" "tok" {
  endpoint = https.api
}
profile "default" { credentials = [bearer_token.tok] }

rule "by-credential" {
  endpoint   = https.api
  credential = bearer_token.tok
  verdict    = "allow"
}
rule "body-deny" {
  endpoint  = https.api
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

// newSQLMetaWithStatement builds a *sqlfacet.Meta carrying just the
// raw statement — the shape parseChSQL hands the matcher on an
// unparseable Query (verb / tables / functions are zero).
func newSQLMetaWithStatement(stmt string) *sqlfacet.Meta {
	return &sqlfacet.Meta{Statement: stmt}
}

// TestMatchRequestUnparseable_StatementRuleAllowsOnUnparseable pins
// the high-priority statement-only happy path: a rule that reads only
// `sql.statement` runs normally on Unparseable=true and its verdict
// applies (here, allow). No synthesized deny is emitted because the
// statement text IS populated when the parser fails — only verb /
// tables / functions are zero.
func TestMatchRequestUnparseable_StatementRuleAllowsOnUnparseable(t *testing.T) {
	cp := compileFixture(t, `
endpoint "clickhouse_native" "ch" { hosts = ["ch.example:9000"] }
credential "clickhouse_credential" "ch-cred" { endpoint = clickhouse_native.ch }
profile "default" { credentials = [clickhouse_credential.ch-cred] }

rule "allow-known-shape" {
  endpoint  = clickhouse_native.ch
  condition = "sql.statement.contains('daily_user_metrics')"
  priority  = 100
  verdict   = "allow"
}
rule "verb-deny" {
  endpoint  = clickhouse_native.ch
  condition = "sql.verb == 'insert'"
  priority  = 50
  verdict   = "deny"
  reason    = "writes blocked"
}
`)
	ep := cp.Endpoints["ch"]

	req := &match.Request{
		Family:      "sql",
		Meta:        newSQLMetaWithStatement("WITH … INSERT INTO daily_user_metrics …"),
		Unparseable: true,
	}
	r := runtime.MatchRequest(ep, req)
	if r == nil {
		t.Fatalf("got nil, want allow-known-shape")
	}
	if r.Name != "allow-known-shape" || r.Outcome.Verdict != "allow" {
		t.Errorf("got rule=%q verdict=%q, want allow-known-shape/allow (statement rule must evaluate honestly on Unparseable)",
			r.Name, r.Outcome.Verdict)
	}
}

// TestMatchRequestUnparseable_VerbRuleSynthDeniesOnUnparseable pins
// the fail-closed core: a higher-priority statement rule that does
// NOT match the request falls through; the next rule references
// `sql.verb` which is zero because the parser refused → synthesize a
// deny attributed to that rule. The synthesized verdict and reason
// must replace the rule's original Outcome (which was allow).
func TestMatchRequestUnparseable_VerbRuleSynthDeniesOnUnparseable(t *testing.T) {
	cp := compileFixture(t, `
endpoint "clickhouse_native" "ch" { hosts = ["ch.example:9000"] }
credential "clickhouse_credential" "ch-cred" { endpoint = clickhouse_native.ch }
profile "default" { credentials = [clickhouse_credential.ch-cred] }

rule "allow-statement-prefix" {
  endpoint  = clickhouse_native.ch
  condition = "sql.statement.startsWith('SELECT')"
  priority  = 100
  verdict   = "allow"
}
rule "verb-allow" {
  endpoint  = clickhouse_native.ch
  condition = "sql.verb == 'insert'"
  priority  = 50
  verdict   = "allow"
}
`)
	ep := cp.Endpoints["ch"]

	req := &match.Request{
		Family:      "sql",
		Meta:        newSQLMetaWithStatement("WITH cte AS (...) INSERT INTO dst SELECT id FROM cte"),
		Unparseable: true,
	}
	r := runtime.MatchRequest(ep, req)
	if r == nil {
		t.Fatalf("got nil, want synth deny attributed to verb-allow")
	}
	if r.Name != "verb-allow" {
		t.Errorf("synth deny should preserve the original rule name; got %q want verb-allow", r.Name)
	}
	if r.Outcome.Verdict != "deny" {
		t.Errorf("verdict = %q, want deny (synthesized — rule references unset sql.verb on Unparseable request)",
			r.Outcome.Verdict)
	}
	if r.Outcome.Reason == "" {
		t.Errorf("synth deny reason must be non-empty")
	}
}

// TestMatchRequestUnparseable_OnlyParserFacetsSynthDenyFromHighestPriority
// covers the "only verb/tables/functions rules" scenario from the user
// spec: no statement-only rule covers the Unparseable request, every
// rule references a parser-derived facet → the highest-priority rule
// synth-denies. Lower-priority rules don't get a chance.
func TestMatchRequestUnparseable_OnlyParserFacetsSynthDenyFromHighestPriority(t *testing.T) {
	cp := compileFixture(t, `
endpoint "clickhouse_native" "ch" { hosts = ["ch.example:9000"] }
credential "clickhouse_credential" "ch-cred" { endpoint = clickhouse_native.ch }
profile "default" { credentials = [clickhouse_credential.ch-cred] }

rule "deny-writes" {
  endpoint  = clickhouse_native.ch
  condition = "sql.verb in ['insert', 'update', 'delete']"
  priority  = 100
  verdict   = "deny"
  reason    = "writes blocked"
}
rule "tables-deny" {
  endpoint  = clickhouse_native.ch
  condition = "'secrets' in sql.tables"
  priority  = 50
  verdict   = "deny"
  reason    = "secrets denied"
}
`)
	ep := cp.Endpoints["ch"]

	req := &match.Request{
		Family:      "sql",
		Meta:        newSQLMetaWithStatement("WITH cte AS (...) INSERT INTO dst SELECT * FROM cte"),
		Unparseable: true,
	}
	r := runtime.MatchRequest(ep, req)
	if r == nil {
		t.Fatalf("got nil, want synth deny from deny-writes (highest priority)")
	}
	if r.Name != "deny-writes" {
		t.Errorf("synth deny should fire on the highest-priority parser-facet rule; got %q want deny-writes", r.Name)
	}
	if r.Outcome.Verdict != "deny" {
		t.Errorf("verdict = %q, want deny", r.Outcome.Verdict)
	}
}

// TestMatchRequestUnparseable_NoRulesFallsThrough covers the
// "no sql_rule on the endpoint at all" carve-out: an Unparseable
// request must NOT auto-deny on its own — the synthesized deny only
// fires when an existing rule references an unset facet. With no
// rules attached the dispatcher returns nil and the caller's default
// (passthrough / defaults.unknown_host) applies.
func TestMatchRequestUnparseable_NoRulesFallsThrough(t *testing.T) {
	cp := compileFixture(t, `
endpoint "clickhouse_native" "ch" { hosts = ["ch.example:9000"] }
credential "clickhouse_credential" "ch-cred" { endpoint = clickhouse_native.ch }
profile "default" { credentials = [clickhouse_credential.ch-cred] }
`)
	ep := cp.Endpoints["ch"]

	req := &match.Request{
		Family:      "sql",
		Meta:        newSQLMetaWithStatement("WITH cte AS (...) INSERT INTO dst SELECT id FROM cte"),
		Unparseable: true,
	}
	r := runtime.MatchRequest(ep, req)
	if r != nil {
		t.Errorf("expected nil (no rule fires; caller applies its default), got %+v", r)
	}
}

// TestMatchRequestUnparseable_ParseableUnaffected pins that the
// Unparseable gate is a no-op when Unparseable=false — a parseable
// query against the same rule set behaves as before. Mirrors the
// equivalent assertion on the Truncated side.
func TestMatchRequestUnparseable_ParseableUnaffected(t *testing.T) {
	cp := compileFixture(t, `
endpoint "clickhouse_native" "ch" { hosts = ["ch.example:9000"] }
credential "clickhouse_credential" "ch-cred" { endpoint = clickhouse_native.ch }
profile "default" { credentials = [clickhouse_credential.ch-cred] }

rule "verb-allow-select" {
  endpoint  = clickhouse_native.ch
  condition = "sql.verb == 'select'"
  verdict   = "allow"
}
`)
	ep := cp.Endpoints["ch"]

	req := &match.Request{
		Family: "sql",
		Meta:   &sqlfacet.Meta{Verb: "select", Statement: "SELECT 1"},
	}
	r := runtime.MatchRequest(ep, req)
	if r == nil || r.Name != "verb-allow-select" || r.Outcome.Verdict != "allow" {
		t.Errorf("parseable SELECT got %+v, want verb-allow-select/allow", r)
	}
}

// TestMatchRequestUnparseable_CredentialOnlyRuleStillAllows is the
// Unparseable analogue of the Truncated/credential test: a rule that
// reads zero parser-derived facets (here, only the credential pin)
// must still fire normally on an Unparseable request. The
// fail-closed gate keys on `InspectsUnparseableFacet()`, and that
// returns false for a connection-only rule.
func TestMatchRequestUnparseable_CredentialOnlyRuleStillAllows(t *testing.T) {
	cp := compileFixture(t, `
endpoint "clickhouse_native" "ch" {
  hosts = ["ch.example:9000"]
}
credential "clickhouse_credential" "tok" {
  endpoint = clickhouse_native.ch
}
profile "default" { credentials = [clickhouse_credential.tok] }

rule "by-credential" {
  endpoint   = clickhouse_native.ch
  credential = clickhouse_credential.tok
  verdict    = "allow"
}
rule "verb-deny" {
  endpoint  = clickhouse_native.ch
  condition = "sql.verb == 'insert'"
  priority  = -50
  verdict   = "deny"
}
`)
	ep := cp.Endpoints["ch"]

	req := &match.Request{
		Family:      "sql",
		Credential:  "tok",
		Meta:        newSQLMetaWithStatement("WITH cte AS (...) INSERT INTO dst SELECT id FROM cte"),
		Unparseable: true,
	}
	r := runtime.MatchRequest(ep, req)
	if r == nil {
		t.Fatalf("got nil, want by-credential allow")
	}
	if r.Name != "by-credential" || r.Outcome.Verdict != "allow" {
		t.Errorf("got %+v, want by-credential/allow (credential-only rule reads no parser facet)", r)
	}
}

// TestResolveCredentialSingular: one credential, no placeholder →
// returned without consulting the endpoint plugin's detector.
func TestResolveCredentialSingular(t *testing.T) {
	cp := compile(t)
	ep := cp.Endpoints["github"]
	got := runtime.ResolveCredential(cp, "default", ep, &match.Request{Family: "http", Headers: http.Header{}})
	if got == nil || got.Credential.Symbol.Name != "pat" {
		t.Errorf("singular credential resolution wrong: %+v", got)
	}
}

// TestResolveCredentialSingularIgnoresDisambiguators pins the behavior
// that a single credential bound to (profile, endpoint) is returned
// regardless of its disambiguator fields. The body's `user` /
// `database` attrs still drive upstream auth (PostgresAuth() reads
// them), but the agent's StartupMessage doesn't have to mirror them
// to make the dispatcher pick the only credential present. Previously
// the agent had to set PGUSER to the credential's upstream user or
// the dispatcher returned nil and the connection failed with "no
// credential bound" — a usability footgun on every single-credential
// postgres endpoint.
func TestResolveCredentialSingularIgnoresDisambiguators(t *testing.T) {
	src := `
endpoint "postgres" "ep" { host = "db.example.com:5432" }
credential "postgres_credential" "only" {
  endpoint = postgres.ep
  user     = "iam-bot@project.iam"
  database = "prod"
}
profile "default" { credentials = [postgres_credential.only] }
`
	cp := compileFixture(t, src)
	ep := cp.Endpoints["ep"]
	cases := []*match.Request{
		{Family: "sql"},
		{Family: "sql", User: "none", Database: "postgres"},
		{Family: "sql", User: "iam-bot@project.iam", Database: "prod"},
	}
	for _, req := range cases {
		got := runtime.ResolveCredential(cp, "default", ep, req)
		if got == nil || got.Credential.Symbol.Name != "only" {
			t.Errorf("req=%+v got %+v, want credential %q", req, got, "only")
		}
	}
}

// TestCredentialMismatchReason: when a multi-credential endpoint has
// no matching entry for the agent's user/database, the helper builds
// an actionable message that lists the disambiguator values the
// operator could have supplied. Used by the postgres plugin's "no
// credential bound" error path so the agent sees which user values
// the endpoint actually accepts.
func TestCredentialMismatchReason(t *testing.T) {
	src := `
endpoint "postgres" "ep" { host = "db.example.com:5432" }
credential "postgres_credential" "ro" {
  endpoint = postgres.ep
  user     = "pg_ro"
}
credential "postgres_credential" "rw" {
  endpoint = postgres.ep
  user     = "pg_rw"
}
profile "default" { credentials = [postgres_credential.ro, postgres_credential.rw] }
`
	cp := compileFixture(t, src)
	ep := cp.Endpoints["ep"]

	if got := runtime.CredentialMismatchReason(cp, "default", ep, &match.Request{Family: "sql", User: "none"}); got == "" || !strings.Contains(got, `user="none"`) || !strings.Contains(got, "pg_ro") || !strings.Contains(got, "pg_rw") {
		t.Errorf("missing-user reason should name agent value + alternatives, got %q", got)
	}
	if got := runtime.CredentialMismatchReason(cp, "default", ep, &match.Request{Family: "sql"}); got == "" || !strings.Contains(got, "missing") {
		t.Errorf("empty-user reason should say missing, got %q", got)
	}
	// Profile with no bindings → empty (caller falls back to its own
	// "no credential bound" wording).
	if got := runtime.CredentialMismatchReason(cp, "no-such-profile", ep, &match.Request{Family: "sql"}); got != "" {
		t.Errorf("no-binding case should return empty, got %q", got)
	}
}

// TestResolveCredentialPlaceholder: multi-credential dispatch asks
// the endpoint plugin's runtime to detect the agent's placeholder
// from the actual request, then matches against the configured set.
// The trailing bare-name entry is the fallback. Placeholders live on
// the profile in v15, riding inside the credentials list as inline
// `{ placeholder = "...", credential = ... }` entries.
func TestResolveCredentialPlaceholder(t *testing.T) {
	src := `
endpoint "https" "ep" {
  hosts = ["x.example.com"]
}
credential "bearer_token" "test"     { endpoint = https.ep }
credential "bearer_token" "prod"     { endpoint = https.ep }
credential "bearer_token" "fallback" { endpoint = https.ep }
profile "default" {
  credentials = [
    { placeholder = "PH_test", credential = bearer_token.test },
    { placeholder = "PH_prod", credential = bearer_token.prod },
    bearer_token.fallback,
  ]
}
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "in.hcl")
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

	got := runtime.ResolveCredential(cp, "default", ep, mkReq("Bearer PH_prod"))
	if got == nil || got.Credential.Symbol.Name != "prod" {
		t.Errorf("Authorization=Bearer PH_prod should select prod, got %+v", got)
	}
	basicPlaceholder := base64.StdEncoding.EncodeToString([]byte("git-user:PH_test"))
	got = runtime.ResolveCredential(cp, "default", ep, mkReq("Basic "+basicPlaceholder))
	if got == nil || got.Credential.Symbol.Name != "test" {
		t.Errorf("Authorization=Basic base64(git-user:PH_test) should select test, got %+v", got)
	}
	got = runtime.ResolveCredential(cp, "default", ep, mkReq("Bearer something-else"))
	if got == nil || got.Credential.Symbol.Name != "fallback" {
		t.Errorf("no placeholder match should fall back, got %+v", got)
	}
	got = runtime.ResolveCredential(cp, "default", ep, mkReq(""))
	if got == nil || got.Credential.Symbol.Name != "fallback" {
		t.Errorf("missing Authorization should fall back, got %+v", got)
	}
}

// TestResolveCredentialDatabaseOnly: SQL credentials dispatch on
// req.Database alone — the discriminator lives on the credential
// body's `database` attr, not on the profile entry.
func TestResolveCredentialDatabaseOnly(t *testing.T) {
	src := `
endpoint "clickhouse_native" "ep" {
  hosts = ["x.example.com"]
}
credential "clickhouse_credential" "prod" {
  endpoint = clickhouse_native.ep
  database = "prod"
}
credential "clickhouse_credential" "dev" {
  endpoint = clickhouse_native.ep
  database = "dev"
}
credential "clickhouse_credential" "fallback" {
  endpoint = clickhouse_native.ep
}
profile "default" { credentials = [clickhouse_credential.prod, clickhouse_credential.dev, clickhouse_credential.fallback] }
`
	cp := compileFixture(t, src)
	ep := cp.Endpoints["ep"]

	cases := []struct {
		db   string
		want string
	}{
		{"prod", "prod"},
		{"dev", "dev"},
		{"unknown", "fallback"},
		{"", "fallback"},
	}
	for _, tc := range cases {
		t.Run(tc.db, func(t *testing.T) {
			got := runtime.ResolveCredential(cp, "default", ep, &match.Request{Family: "sql", Database: tc.db})
			if got == nil || got.Credential.Symbol.Name != tc.want {
				t.Errorf("db=%q got %+v, want %s", tc.db, got, tc.want)
			}
		})
	}
}

// TestResolveCredentialUserAndDatabase: most-specific wins when
// clickhouse credentials combine `user` and `database` discriminators.
// The (user="ro", database="prod") entry beats the user-only entry
// when both match; the user-only entry stays available for the same
// user against a different database; the catchall covers neither.
// Both block-side fields (clickhouse_credential.user /
// clickhouse_credential.database) exercise Contract 2's "database
// and/or user" multi-field discriminator.
func TestResolveCredentialUserAndDatabase(t *testing.T) {
	src := `
endpoint "clickhouse_native" "ep" { hosts = ["x.example.com"] }
credential "clickhouse_credential" "ro-prod" {
  endpoint = clickhouse_native.ep
  user     = "ro"
  database = "prod"
}
credential "clickhouse_credential" "ro-any" {
  endpoint = clickhouse_native.ep
  user     = "ro"
}
credential "clickhouse_credential" "any" {
  endpoint = clickhouse_native.ep
}
profile "default" { credentials = [clickhouse_credential.ro-prod, clickhouse_credential.ro-any, clickhouse_credential.any] }
`
	cp := compileFixture(t, src)
	ep := cp.Endpoints["ep"]

	mkReq := func(user, db string) *match.Request {
		return &match.Request{
			Family:   "sql",
			Database: db,
			User:     user,
			Meta:     &sqlfacet.Meta{Statement: user + "\x00pw"},
		}
	}

	got := runtime.ResolveCredential(cp, "default", ep, mkReq("ro", "prod"))
	if got == nil || got.Credential.Symbol.Name != "ro-prod" {
		t.Errorf("user+db should pick ro-prod, got %+v", got)
	}
	got = runtime.ResolveCredential(cp, "default", ep, mkReq("ro", "dev"))
	if got == nil || got.Credential.Symbol.Name != "ro-any" {
		t.Errorf("user-only match should pick ro-any, got %+v", got)
	}
	got = runtime.ResolveCredential(cp, "default", ep, mkReq("alice", "prod"))
	if got == nil || got.Credential.Symbol.Name != "any" {
		t.Errorf("no constraints match should pick catchall, got %+v", got)
	}
}

// TestContract1DisambiguatorBlockOrProfile verifies Contract 1 from
// PR #368: a credential disambiguator can appear on either the
// credential block itself OR inline in a profile's credentials list,
// and both shapes route the same request to the same credential.
//
// Two parallel fixtures express the same operator intent (route
// "prod" to ch-prod, "dev" to ch-dev) using the two shapes; the
// resolver must pick the same credential for the same agent-declared
// database under both.
func TestContract1DisambiguatorBlockOrProfile(t *testing.T) {
	blockSide := `
endpoint "clickhouse_native" "ep" { hosts = ["x.example.com"] }
credential "clickhouse_credential" "ch-prod" {
  endpoint = clickhouse_native.ep
  database = "prod"
}
credential "clickhouse_credential" "ch-dev" {
  endpoint = clickhouse_native.ep
  database = "dev"
}
profile "default" { credentials = [clickhouse_credential.ch-prod, clickhouse_credential.ch-dev] }
`
	profileSide := `
endpoint "clickhouse_native" "ep" { hosts = ["x.example.com"] }
credential "clickhouse_credential" "ch-prod" { endpoint = clickhouse_native.ep }
credential "clickhouse_credential" "ch-dev"  { endpoint = clickhouse_native.ep }
profile "default" {
  credentials = [
    { credential = clickhouse_credential.ch-prod, database = "prod" },
    { credential = clickhouse_credential.ch-dev,  database = "dev"  },
  ]
}
`
	for _, tc := range []struct {
		shape string
		src   string
	}{
		{"block-side", blockSide},
		{"profile-side", profileSide},
	} {
		t.Run(tc.shape, func(t *testing.T) {
			cp := compileFixture(t, tc.src)
			ep := cp.Endpoints["ep"]
			cases := []struct{ db, want string }{
				{"prod", "ch-prod"},
				{"dev", "ch-dev"},
			}
			for _, c := range cases {
				got := runtime.ResolveCredential(cp, "default", ep, &match.Request{Family: "sql", Database: c.db})
				if got == nil || got.Credential.Symbol.Name != c.want {
					t.Errorf("db=%q got %+v, want %s", c.db, got, c.want)
				}
			}
		})
	}
}

// TestContract1ProfileOverridesBlock verifies the spec's tie-break
// rule: when the same disambiguator field is set on both the
// credential block and a profile-inline entry, the profile-side
// value wins (operator's most-specific declaration).
//
// Two clickhouse credentials each carry block-side `database`
// values; the profile then overrides them. The dispatcher must
// route per the profile's overrides, not the block-side defaults.
func TestContract1ProfileOverridesBlock(t *testing.T) {
	src := `
endpoint "clickhouse_native" "ep" { hosts = ["x.example.com"] }
credential "clickhouse_credential" "ch-a" {
  endpoint = clickhouse_native.ep
  database = "default-a"
}
credential "clickhouse_credential" "ch-b" {
  endpoint = clickhouse_native.ep
  database = "default-b"
}
profile "default" {
  credentials = [
    { credential = clickhouse_credential.ch-a, database = "override-a" },
    { credential = clickhouse_credential.ch-b, database = "override-b" },
  ]
}
`
	cp := compileFixture(t, src)
	ep := cp.Endpoints["ep"]

	got := runtime.ResolveCredential(cp, "default", ep, &match.Request{Family: "sql", Database: "override-a"})
	if got == nil || got.Credential.Symbol.Name != "ch-a" {
		t.Errorf("override-a should pick ch-a, got %+v", got)
	}
	got = runtime.ResolveCredential(cp, "default", ep, &match.Request{Family: "sql", Database: "override-b"})
	if got == nil || got.Credential.Symbol.Name != "ch-b" {
		t.Errorf("override-b should pick ch-b, got %+v", got)
	}
	// The block-side defaults must NOT route any longer — they were
	// shadowed by the profile-inline override.
	got = runtime.ResolveCredential(cp, "default", ep, &match.Request{Family: "sql", Database: "default-a"})
	if got != nil {
		t.Errorf("default-a should not match (block-side shadowed), got %+v", got)
	}
}

// TestContract2PerTypeDiscriminator verifies Contract 2: the
// discriminator field is per-credential-type — postgres routes on
// `user`, clickhouse on `database` (and/or `user`), HTTP-auth on
// `placeholder`. A profile binding two credentials of the same type
// to one endpoint MUST disambiguate using a field the plugin
// supports; the compiler rejects unsupported fields at load time.
func TestContract2PerTypeDiscriminator(t *testing.T) {
	t.Run("postgres routes by user", func(t *testing.T) {
		src := `
endpoint "postgres" "pg" { host = "pg.example:5432" }
credential "postgres_credential" "ro" {
  endpoint = postgres.pg
  user     = "corp_ro"
}
credential "postgres_credential" "rw" {
  endpoint = postgres.pg
  user     = "corp_rw"
}
profile "default" { credentials = [postgres_credential.ro, postgres_credential.rw] }
`
		cp := compileFixture(t, src)
		ep := cp.Endpoints["pg"]
		mk := func(user string) *match.Request {
			return &match.Request{Family: "sql", User: user, Meta: &sqlfacet.Meta{Statement: user}}
		}
		got := runtime.ResolveCredential(cp, "default", ep, mk("corp_ro"))
		if got == nil || got.Credential.Symbol.Name != "ro" {
			t.Errorf("user=corp_ro should pick ro, got %+v", got)
		}
		got = runtime.ResolveCredential(cp, "default", ep, mk("corp_rw"))
		if got == nil || got.Credential.Symbol.Name != "rw" {
			t.Errorf("user=corp_rw should pick rw, got %+v", got)
		}
	})

	t.Run("HTTP placeholder rejected on postgres credential", func(t *testing.T) {
		src := `
endpoint "postgres" "pg" { host = "pg.example:5432" }
credential "postgres_credential" "ro" {
  endpoint = postgres.pg
  user     = "ro"
}
credential "postgres_credential" "rw" {
  endpoint = postgres.pg
  user     = "rw"
}
profile "default" {
  credentials = [
    { credential = postgres_credential.ro, placeholder = "PH_ro" },
    { credential = postgres_credential.rw, placeholder = "PH_rw" },
  ]
}
`
		_, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "in.hcl")
		if !diags.HasErrors() {
			t.Fatalf("expected load to reject `placeholder` on postgres_credential, got no errors")
		}
		var found bool
		for _, d := range diags {
			if d.Severity == 1 /* DiagError */ &&
				containsAll(d.Summary+" "+d.Detail, "placeholder", "postgres_credential", "disambiguator") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected per-type rejection diagnostic for `placeholder` on postgres_credential; got %v", diags)
		}
	})

	t.Run("HTTP credential routes by placeholder on block", func(t *testing.T) {
		// Contract 1 also verifies block-side placeholder works for
		// HTTP-auth types — the framework-peeled `placeholder` attr
		// lands on Entity.Framework.Strings["placeholder"] and
		// participates in dispatch identically to a profile-inline
		// placeholder.
		src := `
endpoint "https" "ep" { hosts = ["x.example.com"] }
credential "bearer_token" "test" {
  endpoint    = https.ep
  placeholder = "PH_test"
}
credential "bearer_token" "prod" {
  endpoint    = https.ep
  placeholder = "PH_prod"
}
credential "bearer_token" "fallback" { endpoint = https.ep }
profile "default" { credentials = [bearer_token.test, bearer_token.prod, bearer_token.fallback] }
`
		cp := compileFixture(t, src)
		ep := cp.Endpoints["ep"]
		mkReq := func(authz string) *match.Request {
			h := http.Header{}
			if authz != "" {
				h.Set("Authorization", authz)
			}
			return &match.Request{Family: "http", Headers: h}
		}
		got := runtime.ResolveCredential(cp, "default", ep, mkReq("Bearer PH_prod"))
		if got == nil || got.Credential.Symbol.Name != "prod" {
			t.Errorf("Bearer PH_prod should select prod via block-side placeholder, got %+v", got)
		}
		got = runtime.ResolveCredential(cp, "default", ep, mkReq("Bearer something-else"))
		if got == nil || got.Credential.Symbol.Name != "fallback" {
			t.Errorf("no match should fall back, got %+v", got)
		}
	})
}

// TestResolveCredentialIsolatesProfilesSharingEndpoint verifies that
// two profiles binding distinct credentials to the same endpoint
// dispatch to their own credential — the readonly profile must NEVER
// receive the writer credential and vice versa. Regression for
// cl-lgwg: the dashboard was leaking sibling-profile credentials onto
// device cards; this test pins down that the runtime dispatch table
// (CompiledProfile.EndpointCredentials) does NOT have the same flaw.
func TestResolveCredentialIsolatesProfilesSharingEndpoint(t *testing.T) {
	src := `
endpoint "postgres" "pg" { host = "pg.example:5432" }
credential "postgres_credential" "pg-readonly" {
  endpoint = postgres.pg
  user     = "agent_ro"
}
credential "postgres_credential" "pg-writer" {
  endpoint = postgres.pg
  user     = "agent_rw"
}
profile "data"     { credentials = [postgres_credential.pg-readonly] }
profile "platform" { credentials = [postgres_credential.pg-writer] }
`
	cp := compileFixture(t, src)
	ep := cp.Endpoints["pg"]

	mkReq := func(user string) *match.Request {
		return &match.Request{
			Family: "sql",
			User:   user,
			Meta:   &sqlfacet.Meta{Statement: user + "\x00pw"},
		}
	}

	got := runtime.ResolveCredential(cp, "data", ep, mkReq("agent_ro"))
	if got == nil || got.Credential.Symbol.Name != "pg-readonly" {
		t.Errorf("data profile / user=agent_ro → %+v, want pg-readonly", got)
	}
	// Data profile must NOT match writer credential even if the
	// request happens to carry the writer's user — the writer
	// credential isn't in the profile's dispatch table at all.
	got = runtime.ResolveCredential(cp, "data", ep, mkReq("agent_rw"))
	if got != nil && got.Credential.Symbol.Name == "pg-writer" {
		t.Errorf("data profile / user=agent_rw resolved sibling writer credential: %+v", got)
	}

	got = runtime.ResolveCredential(cp, "platform", ep, mkReq("agent_rw"))
	if got == nil || got.Credential.Symbol.Name != "pg-writer" {
		t.Errorf("platform profile / user=agent_rw → %+v, want pg-writer", got)
	}
	got = runtime.ResolveCredential(cp, "platform", ep, mkReq("agent_ro"))
	if got != nil && got.Credential.Symbol.Name == "pg-readonly" {
		t.Errorf("platform profile / user=agent_ro resolved sibling readonly credential: %+v", got)
	}
}

// TestResolveCredentialPassthrough: a `passthrough` credential bound
// to an endpoint and claimed by a profile resolves through the normal
// credential→endpoint→profile path — and its body satisfies NONE of
// the request-time injection interfaces, so the gateway forwards the
// request verbatim (no header, no signature, no WS rewrite) while the
// profile's policy rules still run. cl-snuf.
func TestResolveCredentialPassthrough(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "public" {
  hosts = ["status.example.com"]
}
credential "passthrough" "public_pass" { endpoint = https.public }
profile "default" { credentials = [passthrough.public_pass] }
`)
	ep := cp.Endpoints["public"]
	got := runtime.ResolveCredential(cp, "default", ep, &match.Request{Family: "http", Headers: http.Header{}})
	if got == nil || got.Credential.Symbol.Name != "public_pass" {
		t.Fatalf("passthrough resolution: got %+v, want public_pass", got)
	}
	// The point of the type: it injects nothing. Mirror the gateway's
	// dispatch type-asserts (main.go) — none must hold, or injection
	// would fire.
	body := got.Credential.Body
	if _, ok := body.(runtime.HTTPCredentialRuntime); ok {
		t.Errorf("passthrough body satisfies HTTPCredentialRuntime — would stamp auth")
	}
	if _, ok := body.(runtime.HTTPRequestSigner); ok {
		t.Errorf("passthrough body satisfies HTTPRequestSigner — would sign")
	}
	if _, ok := body.(runtime.WebSocketCredentialRuntime); ok {
		t.Errorf("passthrough body satisfies WebSocketCredentialRuntime — would rewrite WS frames")
	}
	// It carries the marker the dashboard reads to flag "no injection".
	if _, ok := body.(config.NonInjectingCredential); !ok {
		t.Errorf("passthrough body missing config.NonInjectingCredential marker")
	}
}

// TestResolveCredentialPassthroughIsolatesProfilesSharingEndpoint:
// the cl-lgwg sibling-leak guard, applied to passthrough credentials.
// Two profiles each bind their own passthrough credential to a shared
// endpoint; neither profile may resolve the other's credential.
func TestResolveCredentialPassthroughIsolatesProfilesSharingEndpoint(t *testing.T) {
	cp := compileFixture(t, `
endpoint "https" "shared" {
  hosts = ["shared.example.com"]
}
credential "passthrough" "pass-a" { endpoint = https.shared }
credential "passthrough" "pass-b" { endpoint = https.shared }
profile "a" { credentials = [passthrough.pass-a] }
profile "b" { credentials = [passthrough.pass-b] }
`)
	ep := cp.Endpoints["shared"]
	mkReq := func() *match.Request { return &match.Request{Family: "http", Headers: http.Header{}} }

	got := runtime.ResolveCredential(cp, "a", ep, mkReq())
	if got == nil || got.Credential.Symbol.Name != "pass-a" {
		t.Errorf("profile a → %+v, want pass-a", got)
	}
	if got != nil && got.Credential.Symbol.Name == "pass-b" {
		t.Errorf("profile a leaked sibling pass-b: %+v", got)
	}
	got = runtime.ResolveCredential(cp, "b", ep, mkReq())
	if got == nil || got.Credential.Symbol.Name != "pass-b" {
		t.Errorf("profile b → %+v, want pass-b", got)
	}
	if got != nil && got.Credential.Symbol.Name == "pass-a" {
		t.Errorf("profile b leaked sibling pass-a: %+v", got)
	}
}

// TestPassthroughCredentialRejectsAttributes pins the bead's
// "carries no auth-bearing fields" rule: a passthrough body is an
// empty struct, so gohcl rejects ANY attribute at decode time. No
// per-plugin Validate is needed — the type system enforces it.
func TestPassthroughCredentialRejectsAttributes(t *testing.T) {
	src := testGatewayPrefix + `
endpoint "https" "public" { hosts = ["status.example.com"] }
credential "passthrough" "bad" {
  endpoint = https.public
  token    = "should-not-be-allowed"
}
profile "default" { credentials = [passthrough.bad] }
`
	_, diags := config.LoadBytes([]byte(src), "in.hcl")
	if !diags.HasErrors() {
		t.Fatalf("passthrough credential with a `token` attr should be rejected at decode; got no errors")
	}
}

// containsAll returns true iff s contains every needle.
func containsAll(s string, needles ...string) bool {
	for _, n := range needles {
		if !containsCI(s, n) {
			return false
		}
	}
	return true
}

func containsCI(haystack, needle string) bool {
	hl := []byte(haystack)
	nl := []byte(needle)
	if len(nl) == 0 {
		return true
	}
	for i := 0; i+len(nl) <= len(hl); i++ {
		match := true
		for j := 0; j < len(nl); j++ {
			a := hl[i+j]
			b := nl[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
