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

endpoint "https" "github"   { hosts = ["api.github.com"] }
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

// TestDiscoveryTunnelReported asserts a tunneled endpoint surfaces the
// tunnel the agent must have active to reach it.
func TestDiscoveryTunnelReported(t *testing.T) {
	policy := compileDiscoveryFixture(t)
	ops := buildDiscoveryManifest(policy, "ops")

	pg := findEndpoint(ops, "prod-pg")
	if pg == nil || pg.Tunnel == nil {
		t.Fatalf("prod-pg tunnel not reported: %+v", pg)
	}
	if pg.Tunnel.Name != "csql" || pg.Tunnel.Type != "local_command" {
		t.Errorf("prod-pg tunnel = %+v, want csql/local_command", pg.Tunnel)
	}
	// The non-tunneled endpoint must not invent one.
	if gh := findEndpoint(ops, "github"); gh.Tunnel != nil {
		t.Errorf("github should have no tunnel, got %+v", gh.Tunnel)
	}
	// Markdown spells out the REQUIRED tunnel so an LLM acts on it.
	md := ops.Markdown()
	if !strings.Contains(md, "Tunnel: REQUIRED") || !strings.Contains(md, "csql") {
		t.Errorf("markdown missing tunnel requirement:\n%s", md)
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

// TestDiscoveryRendersBothFormats checks markdown and JSON come from one
// representation and reflect the same scoping.
func TestDiscoveryRendersBothFormats(t *testing.T) {
	policy := compileDiscoveryFixture(t)

	// JSON via ?format=json.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://clawpatrol/?format=json", nil)
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
	req2 := httptest.NewRequest("GET", "https://clawpatrol/", nil)
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

func TestIsDiscoveryHost(t *testing.T) {
	cases := map[string]bool{
		"clawpatrol":      true,
		"ClawPatrol":      true,
		"clawpatrol.":     true,
		"clawpatrol:443":  true,
		"api.github.com":  false,
		"":                false,
		"clawpatrol.evil": false,
	}
	for host, want := range cases {
		if got := isDiscoveryHost(host); got != want {
			t.Errorf("isDiscoveryHost(%q) = %v, want %v", host, got, want)
		}
	}
}
