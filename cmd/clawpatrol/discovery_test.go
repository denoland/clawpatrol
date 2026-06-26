package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// discoveryFixture declares two profiles whose endpoint/credential
// grants don't overlap, so the per-profile scoping is observable:
//
//	ops → github (https), prod-pg (postgres, tunneled)
//	ro  → internal (https), metrics (clickhouse_native)
const discoveryFixture = `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

tunnel "local_command" "csql" {
  command     = ["cloud_sql_proxy", "--instances", "p:r:db=tcp:5432"]
  listen      = "127.0.0.1:5432"
  ready_probe = "tcp"
  share       = "singleton"
  keepalive   = "5m"
}

endpoint "https" "github" {
  hosts       = ["api.github.com"]
  description = "GitHub REST API for the ops team"
}
endpoint "https" "internal" { hosts = ["internal.example"] }

endpoint "postgres" "prod-pg" {
  host    = "main-pg.example:5432"
  sslmode = "require"
  tunnel  = local_command.csql
}

endpoint "clickhouse_native" "metrics" {
  hosts = ["ch.example"]
  port  = 9440
  tls   = true
}

credential "bearer_token" "gh" {
  endpoint    = https.github
  placeholder = "PH_GH"
  description = "fine-grained PAT, read-only on repos"
}
credential "bearer_token" "int" {
  endpoint    = https.internal
  placeholder = "PH_INT"
}
credential "postgres_credential" "pg-rw" {
  endpoint = postgres.prod-pg
  user     = "app"
  database = "prod"
}
credential "clickhouse_credential" "ch-ro" {
  endpoint = clickhouse_native.metrics
  user     = "ro"
}

profile "ops" { credentials = [bearer_token.gh, postgres_credential.pg-rw] }
profile "ro"  { credentials = [bearer_token.int, clickhouse_credential.ch-ro] }
`

func compileDiscoveryFixture(t *testing.T) *config.CompiledPolicy {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(discoveryFixture), "discovery.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cp
}

func endpointNames(m *DiscoveryManifest) []string {
	out := make([]string, 0, len(m.Endpoints))
	for _, e := range m.Endpoints {
		out = append(out, e.Name)
	}
	return out
}

func findEndpoint(m *DiscoveryManifest, name string) *DiscoveryEndpoint {
	for i := range m.Endpoints {
		if m.Endpoints[i].Name == name {
			return &m.Endpoints[i]
		}
	}
	return nil
}

// TestDiscoveryProfileScoping is the core guarantee: each profile sees
// only its own endpoints and credentials, never the whole config.
func TestDiscoveryProfileScoping(t *testing.T) {
	policy := compileDiscoveryFixture(t)

	ops := buildDiscoveryManifest(policy, "ops")
	if got := endpointNames(ops); strings.Join(got, ",") != "github,prod-pg" {
		t.Fatalf("ops endpoints = %v, want [github prod-pg]", got)
	}
	// ops must NOT see ro's endpoints.
	if findEndpoint(ops, "internal") != nil || findEndpoint(ops, "metrics") != nil {
		t.Errorf("ops leaked ro endpoints: %v", endpointNames(ops))
	}
	opsCreds := credNames(ops)
	if opsCreds != "gh,pg-rw" {
		t.Errorf("ops credentials = %q, want gh,pg-rw", opsCreds)
	}

	ro := buildDiscoveryManifest(policy, "ro")
	if got := endpointNames(ro); strings.Join(got, ",") != "internal,metrics" {
		t.Fatalf("ro endpoints = %v, want [internal metrics]", got)
	}
	if findEndpoint(ro, "github") != nil || findEndpoint(ro, "prod-pg") != nil {
		t.Errorf("ro leaked ops endpoints: %v", endpointNames(ro))
	}
	if c := credNames(ro); c != "ch-ro,int" {
		t.Errorf("ro credentials = %q, want ch-ro,int", c)
	}
}

func credNames(m *DiscoveryManifest) string {
	out := make([]string, 0, len(m.Credentials))
	for _, c := range m.Credentials {
		out = append(out, c.Name)
	}
	return strings.Join(out, ",")
}

// TestDiscoveryEndpointDetail checks the per-endpoint connection how-to:
// host/port/sslmode, the credential placeholder, and SQL disambiguators.
func TestDiscoveryEndpointDetail(t *testing.T) {
	policy := compileDiscoveryFixture(t)
	ops := buildDiscoveryManifest(policy, "ops")

	gh := findEndpoint(ops, "github")
	if gh == nil || gh.Type != "https" {
		t.Fatalf("github endpoint missing or wrong type: %+v", gh)
	}
	if len(gh.Credentials) != 1 || gh.Credentials[0].Placeholder != "PH_GH" {
		t.Errorf("github credential placeholder = %+v, want PH_GH", gh.Credentials)
	}

	pg := findEndpoint(ops, "prod-pg")
	if pg == nil {
		t.Fatal("prod-pg endpoint missing")
	}
	if pg.Type != "postgres" || pg.Port != 5432 || pg.SSLMode != "require" {
		t.Errorf("prod-pg detail wrong: type=%q port=%d sslmode=%q", pg.Type, pg.Port, pg.SSLMode)
	}
	if len(pg.Hosts) != 1 || pg.Hosts[0] != "main-pg.example" {
		t.Errorf("prod-pg hosts = %v, want [main-pg.example]", pg.Hosts)
	}
	if len(pg.Credentials) != 1 {
		t.Fatalf("prod-pg credentials = %+v", pg.Credentials)
	}
	d := pg.Credentials[0].Disambiguators
	if d["user"] != "app" || d["database"] != "prod" {
		t.Errorf("prod-pg disambiguators = %v, want user=app database=prod", d)
	}
	if !strings.Contains(pg.Hint, "psql") || !strings.Contains(pg.Hint, "dbname=prod") {
		t.Errorf("prod-pg hint = %q, want psql ... dbname=prod", pg.Hint)
	}
}

// TestDiscoveryDescriptions asserts the optional `description` on an
// endpoint and a credential block reaches both the JSON manifest and
// the markdown render. Operators add these as human/LLM-readable notes;
// they're useless if they don't surface.
func TestDiscoveryDescriptions(t *testing.T) {
	policy := compileDiscoveryFixture(t)
	ops := buildDiscoveryManifest(policy, "ops")

	const epDesc = "GitHub REST API for the ops team"
	const credDesc = "fine-grained PAT, read-only on repos"

	gh := findEndpoint(ops, "github")
	if gh == nil {
		t.Fatal("github endpoint missing")
	}
	if gh.Description != epDesc {
		t.Errorf("endpoint description = %q, want %q", gh.Description, epDesc)
	}
	if len(gh.Credentials) != 1 || gh.Credentials[0].Description != credDesc {
		t.Errorf("credential ref description = %+v, want %q", gh.Credentials, credDesc)
	}

	// Top-level credentials view carries it too.
	var ghCred *DiscoveryCredential
	for i := range ops.Credentials {
		if ops.Credentials[i].Name == "gh" {
			ghCred = &ops.Credentials[i]
		}
	}
	if ghCred == nil {
		t.Fatal("gh credential missing from manifest")
	}
	if ghCred.Description != credDesc {
		t.Errorf("credential description = %q, want %q", ghCred.Description, credDesc)
	}

	// Both descriptions render into the markdown an LLM consumes.
	md := ops.Markdown()
	if !strings.Contains(md, epDesc) {
		t.Errorf("markdown missing endpoint description %q:\n%s", epDesc, md)
	}
	if !strings.Contains(md, credDesc) {
		t.Errorf("markdown missing credential description %q:\n%s", credDesc, md)
	}

	// And into the JSON.
	js := string(renderJSON(t, policy, "ops"))
	if !strings.Contains(js, epDesc) || !strings.Contains(js, credDesc) {
		t.Errorf("json missing descriptions:\n%s", js)
	}
}

// TestDiscoveryTunnelHidden asserts a tunneled endpoint reads no
// differently from a directly-reachable one. The gateway brings the
// tunnel up transparently, so the agent dials the same host either way —
// the tunnel's name/type would be noise it can't act on. A tunneled
// endpoint must still surface its host (the one thing the agent needs).
func TestDiscoveryTunnelHidden(t *testing.T) {
	policy := compileDiscoveryFixture(t)
	ops := buildDiscoveryManifest(policy, "ops")

	pg := findEndpoint(ops, "prod-pg")
	if pg == nil {
		t.Fatal("prod-pg endpoint missing")
	}
	// The host the agent dials is still reported — that's all it needs.
	if len(pg.Hosts) != 1 || pg.Hosts[0] != "main-pg.example" {
		t.Errorf("prod-pg hosts = %v, want [main-pg.example]", pg.Hosts)
	}

	// No tunnel detail leaks into either render. The JSON has no `tunnel`
	// key; the markdown has no `Tunnel:` line, REQUIRED or otherwise.
	js := string(renderJSON(t, policy, "ops"))
	if strings.Contains(js, "\"tunnel\"") || strings.Contains(js, "csql") || strings.Contains(js, "local_command") {
		t.Errorf("json leaked tunnel detail:\n%s", js)
	}
	md := ops.Markdown()
	if strings.Contains(md, "Tunnel") || strings.Contains(md, "csql") {
		t.Errorf("markdown leaked tunnel detail:\n%s", md)
	}
}

// TestDiscoveryClickhouseDetail covers the clickhouse_native port/host
// extraction and its hint.
func TestDiscoveryClickhouseDetail(t *testing.T) {
	policy := compileDiscoveryFixture(t)
	ro := buildDiscoveryManifest(policy, "ro")
	ch := findEndpoint(ro, "metrics")
	if ch == nil || ch.Type != "clickhouse_native" || ch.Port != 9440 {
		t.Fatalf("metrics detail wrong: %+v", ch)
	}
	if len(ch.Hosts) != 1 || ch.Hosts[0] != "ch.example" {
		t.Errorf("metrics hosts = %v", ch.Hosts)
	}
	if !strings.Contains(ch.Hint, "clickhouse-client") || !strings.Contains(ch.Hint, "--user ro") {
		t.Errorf("metrics hint = %q", ch.Hint)
	}
}

// envPushdownFixture has two profiles: `ai` reaches a credential that
// pushes env vars (gemini_api_key → GOOGLE_API_KEY / GEMINI_API_KEY),
// while `plain` reaches only a bearer endpoint that pushes none. So the
// env-var listing and its profile scoping are both observable.
const envPushdownFixture = `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "github" { hosts = ["api.github.com"] }
endpoint "https" "gemini" { hosts = ["generativelanguage.googleapis.com"] }

credential "bearer_token" "gh" {
  endpoint    = https.github
  placeholder = "PH_GH"
}
credential "gemini_api_key" "gem" {
  endpoint = https.gemini
}

profile "ai"    { credentials = [gemini_api_key.gem] }
profile "plain" { credentials = [bearer_token.gh] }
`

func envVarNames(m *DiscoveryManifest) []string {
	out := make([]string, 0, len(m.EnvVars))
	for _, e := range m.EnvVars {
		out = append(out, e.Name)
	}
	return out
}

// TestDiscoveryEnvVars: a profile whose credential pushes env vars
// surfaces them (name/value/description/type); a profile without one
// reports none; and the listing never leaks another profile's vars.
func TestDiscoveryEnvVars(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(envPushdownFixture), "envpushdown.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ai := buildDiscoveryManifest(policy, "ai")
	if got := strings.Join(envVarNames(ai), ","); got != "GOOGLE_API_KEY,GEMINI_API_KEY" {
		t.Fatalf("ai env vars = %q, want GOOGLE_API_KEY,GEMINI_API_KEY", got)
	}
	for _, ev := range ai.EnvVars {
		if ev.Type != "gemini_api_key" {
			t.Errorf("env var %s type = %q, want gemini_api_key", ev.Name, ev.Type)
		}
		if ev.Value == "" || ev.Description == "" {
			t.Errorf("env var %s missing value/description: %+v", ev.Name, ev)
		}
	}

	// Plain profile pushes no env vars, and never sees ai's.
	plain := buildDiscoveryManifest(policy, "plain")
	if len(plain.EnvVars) != 0 {
		t.Errorf("plain env vars = %v, want none", envVarNames(plain))
	}

	// Markdown reflects the listing.
	md := ai.Markdown()
	if !strings.Contains(md, "## Environment variables (2)") || !strings.Contains(md, "`GEMINI_API_KEY`") {
		t.Errorf("markdown missing env var section:\n%s", md)
	}
	plainMD := plain.Markdown()
	if !strings.Contains(plainMD, "_None pushed for this profile._") {
		t.Errorf("plain markdown should report no env vars:\n%s", plainMD)
	}
	if strings.Contains(plainMD, "GEMINI_API_KEY") {
		t.Errorf("plain markdown leaked ai's env vars:\n%s", plainMD)
	}
}

// TestDiscoveryRendersBothFormats checks markdown and JSON come from one
// representation and reflect the same scoping.
func TestDiscoveryRendersBothFormats(t *testing.T) {
	policy := compileDiscoveryFixture(t)

	// JSON via ?format=json.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://clawpatrol.internal/?format=json", nil)
	writeDiscoveryResponse(rec, req, policy, "ops")
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("json content-type = %q", ct)
	}
	var m DiscoveryManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if m.Profile != "ops" || strings.Join(endpointNames(&m), ",") != "github,prod-pg" {
		t.Errorf("json manifest = %+v", m)
	}

	// Markdown default (no query, no Accept).
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "https://clawpatrol.internal/", nil)
	writeDiscoveryResponse(rec2, req2, policy, "ops")
	if ct := rec2.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("markdown content-type = %q", ct)
	}
	body := rec2.Body.String()
	if !strings.Contains(body, "profile: ops") || !strings.Contains(body, "api.github.com") {
		t.Errorf("markdown body missing expected content:\n%s", body)
	}
	if strings.Contains(body, "internal.example") || strings.Contains(body, "ch.example") {
		t.Errorf("markdown leaked another profile's endpoints:\n%s", body)
	}
}

// TestDiscoveryUnknownProfile: a device whose resolved profile isn't in
// policy gets an empty manifest with a note, not an error or a config
// dump.
func TestDiscoveryUnknownProfile(t *testing.T) {
	policy := compileDiscoveryFixture(t)
	m := buildDiscoveryManifest(policy, "does-not-exist")
	if len(m.Endpoints) != 0 || len(m.Credentials) != 0 {
		t.Errorf("unknown profile should be empty, got %+v", m)
	}
	if len(m.Notes) == 0 {
		t.Errorf("unknown profile should carry an explanatory note")
	}
}

// TestDiscoveryEmptyProfileGuidance: a profile that grants nothing must
// not hand the agent a bare "none/none" manifest. It explains the empty
// state and points at the dashboard (gateway.public_url) where the
// device's profile gets configured. A non-empty profile carries no such
// pointer — it already has everything actionable.
func TestDiscoveryEmptyProfileGuidance(t *testing.T) {
	policy := compileDiscoveryFixture(t)

	// "does-not-exist" resolves to no policy entry → empty manifest.
	empty := buildDiscoveryManifest(policy, "does-not-exist")
	if !empty.isEmpty() {
		t.Fatalf("expected empty manifest, got %+v", empty)
	}
	if empty.Dashboard != "https://gw.example.test" {
		t.Errorf("empty manifest dashboard = %q, want gateway public_url", empty.Dashboard)
	}
	md := empty.Markdown()
	for _, want := range []string{"This profile is empty", "https://gw.example.test", "re-fetch this manifest"} {
		if !strings.Contains(md, want) {
			t.Errorf("empty manifest markdown missing %q:\n%s", want, md)
		}
	}

	// A populated profile gets neither the dashboard pointer nor the
	// empty-state guidance.
	ops := buildDiscoveryManifest(policy, "ops")
	if ops.Dashboard != "" {
		t.Errorf("non-empty manifest should not surface dashboard, got %q", ops.Dashboard)
	}
	if strings.Contains(ops.Markdown(), "This profile is empty") {
		t.Errorf("non-empty manifest leaked empty-profile guidance")
	}
}

// TestDiscoveryEmptyProfileNoPublicURL: when public_url is unset, the
// empty-state guidance still renders — minus the URL — rather than
// printing a dangling "open the dashboard at " line.
func TestDiscoveryEmptyProfileNoPublicURL(t *testing.T) {
	const noURL = `gateway {
  state_dir = "/opt/clawpatrol"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint    = "127.0.0.1:51820"
  }
}

endpoint "https" "github" { hosts = ["api.github.com"] }
credential "bearer_token" "gh" {
  endpoint    = https.github
  placeholder = "PH_GH"
}
profile "empty" { credentials = [] }
`
	gw, diags := config.LoadBytes([]byte(noURL), "nourl.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	m := buildDiscoveryManifest(policy, "empty")
	if m.Dashboard != "" {
		t.Errorf("dashboard should be empty when public_url unset, got %q", m.Dashboard)
	}
	md := m.Markdown()
	if !strings.Contains(md, "This profile is empty") {
		t.Errorf("guidance missing:\n%s", md)
	}
	if strings.Contains(md, "open the dashboard at\n") || strings.Contains(md, "dashboard at ") {
		t.Errorf("dangling dashboard URL line rendered:\n%s", md)
	}
}

// TestDiscoveryHITLFlagging is the core HITL guarantee: an endpoint with
// a rule routed through a human approver (human_approver or the built-in
// dashboard) is flagged; an endpoint approved only by an automated (llm)
// approver, or with no approve rule at all, is not. The hitl.hcl fixture
// pairs all four cases in one profile.
func TestDiscoveryHITLFlagging(t *testing.T) {
	policy := compileDiscoveryFile(t, "hitl.hcl")
	m := buildDiscoveryManifest(policy, "ops")

	want := map[string]bool{
		"deploy": true,  // human_approver
		"admin":  true,  // built-in dashboard approver
		"search": false, // llm_approver — automated, no human wait
		"status": false, // no approve rule
	}
	for name, wantHITL := range want {
		ep := findEndpoint(m, name)
		if ep == nil {
			t.Fatalf("endpoint %q missing", name)
		}
		if ep.HITL != wantHITL {
			t.Errorf("endpoint %q HITL = %v, want %v", name, ep.HITL, wantHITL)
		}
	}

	if m.HITL == nil {
		t.Fatal("manifest HITL summary missing")
	}
	if got := strings.Join(m.HITL.GatedEndpoints, ","); got != "admin,deploy" {
		t.Errorf("gated endpoints = %q, want admin,deploy", got)
	}
	if m.HITL.PendingPath != "/pending" {
		t.Errorf("pending path = %q", m.HITL.PendingPath)
	}
	if !strings.Contains(m.HITL.Explanation, "parked indefinitely") {
		t.Errorf("explanation missing the indefinite-parking warning:\n%s", m.HITL.Explanation)
	}
	// The async-poll machinery must not be documented — sync HITL only.
	if strings.Contains(m.HITL.Explanation, "operation_id") || strings.Contains(m.HITL.Explanation, "status_url") {
		t.Errorf("explanation leaks async HITL machinery:\n%s", m.HITL.Explanation)
	}

	// The llm approver's own auth credential (judge, kept out of the
	// profile) must never surface in the manifest.
	js := string(renderJSON(t, policy, "ops"))
	if strings.Contains(js, "PH_JUDGE") || strings.Contains(js, "judge") {
		t.Errorf("manifest leaked the llm approver's private credential:\n%s", js)
	}

	// Markdown carries the section, the pending-list URL, and per-endpoint
	// markers only on the gated endpoints.
	md := m.Markdown()
	if !strings.Contains(md, "## Human-in-the-loop approval") {
		t.Errorf("markdown missing HITL section:\n%s", md)
	}
	if !strings.Contains(md, "clawpatrol.internal/pending") {
		t.Errorf("markdown missing internal pending URL:\n%s", md)
	}
	if c := strings.Count(md, "- Human-in-the-loop: a matching request may be PARKED"); c != 2 {
		t.Errorf("per-endpoint HITL marker count = %d, want 2 (deploy, admin)", c)
	}
}

// TestDiscoveryHITLAbsentWhenNoEndpoints: a profile that grants nothing
// gets no HITL summary — there is nothing to gate or poll, only the
// empty-state guidance.
func TestDiscoveryHITLAbsentWhenEmpty(t *testing.T) {
	policy := compileDiscoveryFixture(t)
	empty := buildDiscoveryManifest(policy, "does-not-exist")
	if empty.HITL != nil {
		t.Errorf("empty manifest should carry no HITL summary, got %+v", empty.HITL)
	}
	// A populated profile with no HITL rules still gets the section (the
	// mechanism is worth documenting), but with an empty gated set.
	ops := buildDiscoveryManifest(policy, "ops")
	if ops.HITL == nil {
		t.Fatal("populated manifest should carry the HITL summary")
	}
	if len(ops.HITL.GatedEndpoints) != 0 {
		t.Errorf("fixture has no HITL rules; gated = %v", ops.HITL.GatedEndpoints)
	}
	if !strings.Contains(ops.Markdown(), "None of this profile's endpoints currently gate") {
		t.Errorf("markdown should say no endpoints are gated")
	}
}

// TestDiscoveryAsyncHITL covers the async-fallback summary: only an
// endpoint gated by an async-capable approver with a sync wait window is
// listed as going async, with the right timing; sync-only gated endpoints
// (no sync window, or a dashboard approver) stay out of the async block
// while remaining in the gated set; and the documented protocol carries
// the exact field names and constants the gateway actually serves.
func TestDiscoveryAsyncHITL(t *testing.T) {
	policy := compileDiscoveryFile(t, "hitl_async.hcl")
	m := buildDiscoveryManifest(policy, "ops")

	if m.HITL == nil {
		t.Fatal("manifest HITL summary missing")
	}
	// All three gated endpoints (async deploy, sync-only release + admin)
	// are still in the gated set; status has no rule.
	if got := strings.Join(m.HITL.GatedEndpoints, ","); got != "admin,deploy,release" {
		t.Errorf("gated endpoints = %q, want admin,deploy,release", got)
	}

	if m.HITL.Async == nil {
		t.Fatal("async HITL block missing")
	}
	a := m.HITL.Async
	// Only deploy goes async: release has async_grant but no sync window,
	// admin is a dashboard approver, status is not gated at all.
	if len(a.Endpoints) != 1 || a.Endpoints[0].Name != "deploy" {
		t.Fatalf("async endpoints = %+v, want only deploy", a.Endpoints)
	}
	if a.Endpoints[0].SyncWait != "1m30s" {
		t.Errorf("deploy sync_wait = %q, want 1m30s", a.Endpoints[0].SyncWait)
	}
	// poll TTL = approver timeout (600s) - sync wait (90s) = 8m30s.
	if a.Endpoints[0].PollTTL != "8m30s" {
		t.Errorf("deploy poll_ttl = %q, want 8m30s", a.Endpoints[0].PollTTL)
	}
	if a.StatusPathTemplate != "/api/hitl/operations/{operation_id}/status" {
		t.Errorf("status path template = %q", a.StatusPathTemplate)
	}
	if a.RetryHeader != "Clawpatrol-HITL-Operation" {
		t.Errorf("retry header = %q", a.RetryHeader)
	}
	if a.PollIntervalSeconds != 5 {
		t.Errorf("poll interval = %d, want 5", a.PollIntervalSeconds)
	}
	// The protocol prose must name the fields and states an agent acts on.
	for _, want := range []string{"202", "operation_id", "status_url", "approved_waiting_for_retry", "pending_approval", "expired", "retry_expires_at"} {
		if !strings.Contains(a.Explanation, want) {
			t.Errorf("async explanation missing %q:\n%s", want, a.Explanation)
		}
	}

	// Markdown carries the async subsection and the per-endpoint timing.
	md := m.Markdown()
	if !strings.Contains(md, "### Asynchronous approval (202 + polling)") {
		t.Errorf("markdown missing async subsection:\n%s", md)
	}
	if !strings.Contains(md, "deploy: returns 202 after 1m30s") {
		t.Errorf("markdown missing deploy async timing:\n%s", md)
	}
	if strings.Contains(md, "release: returns 202") || strings.Contains(md, "admin: returns 202") {
		t.Errorf("sync-only endpoint leaked into async list:\n%s", md)
	}
}

// TestDiscoveryAsyncHITLAbsentWithoutOptIn: the async block is omitted
// when the profile does not opt into async grants, even though the same
// approver is async-capable — the gateway would never hand back a 202, so
// the manifest must not promise it.
func TestDiscoveryAsyncHITLAbsentWithoutOptIn(t *testing.T) {
	// hitl.hcl gates deploy via a plain human approver (no async_grant, no
	// profile opt-in): sync HITL summary present, async block absent.
	policy := compileDiscoveryFile(t, "hitl.hcl")
	m := buildDiscoveryManifest(policy, "ops")
	if m.HITL == nil {
		t.Fatal("manifest HITL summary missing")
	}
	if m.HITL.Async != nil {
		t.Errorf("async block should be absent without async config, got %+v", m.HITL.Async)
	}
	if strings.Contains(m.Markdown(), "Asynchronous approval") {
		t.Errorf("markdown should not document async without async config")
	}
}

func TestIsInternalHost(t *testing.T) {
	cases := map[string]bool{
		"clawpatrol.internal":      true,
		"ClawPatrol.Internal":      true,
		"clawpatrol.internal.":     true,
		"clawpatrol.internal:443":  true,
		"clawpatrol":               false,
		"api.github.com":           false,
		"":                         false,
		"clawpatrol.internal.evil": false,
	}
	for host, want := range cases {
		if got := isInternalHost(host); got != want {
			t.Errorf("isInternalHost(%q) = %v, want %v", host, got, want)
		}
	}
}
