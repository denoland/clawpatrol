package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

// gatewayWithPolicy builds a minimal *Gateway whose Policy() returns
// the compiled HCL. Enough for the exporter, which is invoked
// directly here (bypassing route + auth).
func gatewayWithPolicy(t *testing.T, hcl string) *Gateway {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(hcl), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	g := &Gateway{}
	g.policy.Store(policy)
	return g
}

const fixtureHCL = `
admin_email = "x@example.com"
credential "bearer_token" "tok" {}
endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = tok
}
profile "default" { endpoints = [github] }
`

// TestExporterHTTPSHappyPath: a recorded HTTPS Event reshapes into
// an Action JSON that re-parses cleanly with the expected fields.
func TestExporterHTTPSHappyPath(t *testing.T) {
	w := &webMux{g: gatewayWithPolicy(t, fixtureHCL)}
	ev := &Event{
		ID:       "evt-1",
		Mode:     "mitm",
		Family:   "https",
		Host:     "api.github.com",
		Method:   "GET",
		Path:     "/user",
		AgentIP:  "100.64.0.7",
		Action:   "allow",
		Endpoint: "github",
		Rule:     "github-reads",
		ReqHeaders: map[string]string{
			"Authorization": "***",
			"User-Agent":    "clawpatrol-test",
		},
	}
	rw := httptest.NewRecorder()
	w.writeActionFixture(rw, ev)

	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("Content-Disposition"); !strings.Contains(got, `filename="evt-1.json"`) {
		t.Errorf("missing/incorrect Content-Disposition: %q", got)
	}

	var f Fixture
	if err := json.Unmarshal(rw.Body.Bytes(), &f); err != nil {
		t.Fatalf("emitted body doesn't reparse as Fixture: %v\nbody=%s", err, rw.Body.String())
	}
	if f.Action.HTTP == nil {
		t.Fatal("expected http block, got nil")
	}
	if f.Action.Host != "api.github.com" {
		t.Errorf("host=%q want api.github.com", f.Action.Host)
	}
	if f.Action.HTTP.Method != "GET" {
		t.Errorf("method=%q want GET", f.Action.HTTP.Method)
	}
	if f.Action.HTTP.Path != "/user" {
		t.Errorf("path=%q want /user", f.Action.HTTP.Path)
	}
	want := Match{Verdict: "allow", Rule: "github-reads", Endpoint: "github"}
	if f.Match != want {
		t.Errorf("match=%+v want %+v", f.Match, want)
	}
}

// Events recorded before the Endpoint column was populated have
// no endpoint to find; the exporter must 400 with a clear reason.
func TestExporterRejectsEmptyEndpoint(t *testing.T) {
	w := &webMux{g: gatewayWithPolicy(t, fixtureHCL)}
	ev := &Event{ID: "evt-2", Action: "allow"} // Endpoint == ""
	rw := httptest.NewRecorder()
	w.writeActionFixture(rw, ev)

	if rw.Code != 400 {
		t.Fatalf("status=%d want 400; body=%s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "predates endpoint tracking") {
		t.Errorf("body=%q want explanatory error", rw.Body.String())
	}
}

// match.endpoint is always emitted (the exporter knows it at
// write time); the runner can rely on it for shared-host dispatch.
func TestExporterAlwaysEmitsEndpoint(t *testing.T) {
	const hcl = `
admin_email = "x@example.com"
credential "bearer_token" "a" {}
credential "bearer_token" "b" {}
endpoint "https" "alpha" {
  hosts      = ["api.example.com"]
  credential = a
}
endpoint "https" "beta" {
  hosts      = ["api.example.com"]
  credential = b
}
profile "default" { endpoints = [alpha, beta] }
`
	w := &webMux{g: gatewayWithPolicy(t, hcl)}
	ev := &Event{
		ID: "evt-3", Mode: "mitm", Family: "https",
		Host: "api.example.com", Method: "GET", Path: "/x",
		Action: "allow", Endpoint: "beta", Rule: "",
	}
	rw := httptest.NewRecorder()
	w.writeActionFixture(rw, ev)

	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	var f Fixture
	if err := json.Unmarshal(rw.Body.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	if f.Match.Endpoint != "beta" {
		t.Errorf("expected match.endpoint=beta, got %q", f.Match.Endpoint)
	}
}

// approved / denied (and their pre-migration aliases hitl_allow /
// hitl_deny) collapse to "approve" in the fixture (the chain is
// terminal — see site/doc/clawpatrol-test.md). in_flight is a start
// event and isn't exportable.
func TestExporterEventActionMapping(t *testing.T) {
	for _, action := range []string{"approved", "denied", "hitl_allow", "hitl_deny"} {
		m, ok := matchFromEvent(&Event{Action: action, Rule: "r", Endpoint: "ep"})
		if !ok || m.Verdict != "approve" {
			t.Errorf("%s → (%+v, %v), want approve", action, m, ok)
		}
	}
	if _, ok := matchFromEvent(&Event{Action: "in_flight"}); ok {
		t.Error("in_flight should not be exportable")
	}
}

// SQL exporter pulls the raw statement out of Event.Facets and pins
// host to the endpoint's HCL-declared address (not Event.Host, which
// is the dst IP). 400 when the recorded event has no statement.
func TestExporterSQLHappyPath(t *testing.T) {
	const hcl = `
admin_email = "x@example.com"
credential "postgres_credential" "pg-cred" { user = "agent" }
endpoint "postgres" "pg" {
  host       = "pg.internal:5432"
  credential = pg-cred
}
profile "default" { endpoints = [pg] }
`
	w := &webMux{g: gatewayWithPolicy(t, hcl)}
	ev := &Event{
		ID: "evt-sql-1", Mode: "pg", Family: "sql",
		Host: "10.0.0.5", Action: "allow", Endpoint: "pg",
		Rule:   "pg-reads",
		Facets: map[string]any{"statement": "SELECT 1"},
	}
	rw := httptest.NewRecorder()
	w.writeActionFixture(rw, ev)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	var f Fixture
	if err := json.Unmarshal(rw.Body.Bytes(), &f); err != nil {
		t.Fatalf("reparse: %v\nbody=%s", err, rw.Body.String())
	}
	if f.Action.SQL == nil || f.Action.SQL.Statement != "SELECT 1" {
		t.Errorf("sql=%+v want statement=SELECT 1", f.Action.SQL)
	}
	if f.Action.Host != "pg.internal:5432" {
		t.Errorf("host=%q want pg.internal:5432 (HCL host, not Event.Host)", f.Action.Host)
	}
}

func TestExporterSQLRejectsMissingStatement(t *testing.T) {
	const hcl = `
admin_email = "x@example.com"
credential "postgres_credential" "pg-cred" { user = "agent" }
endpoint "postgres" "pg" {
  host       = "pg.internal:5432"
  credential = pg-cred
}
profile "default" { endpoints = [pg] }
`
	w := &webMux{g: gatewayWithPolicy(t, hcl)}
	ev := &Event{ID: "evt-sql-2", Action: "allow", Endpoint: "pg"}
	rw := httptest.NewRecorder()
	w.writeActionFixture(rw, ev)
	if rw.Code != 400 {
		t.Fatalf("status=%d want 400; body=%s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "no statement recorded") {
		t.Errorf("body=%q want explanatory error", rw.Body.String())
	}
}

// k8s exporter reads verb/resource/namespace/name/params from
// Event.Facets — the same shape the live k8s facet's Report emits.
// Params is map[string]any in JSON; the exporter flattens it to
// map[string]string.
func TestExporterK8sHappyPath(t *testing.T) {
	const hcl = `
admin_email = "x@example.com"
credential "mtls_credential" "kube-mtls" {}
endpoint "kubernetes" "kube" {
  server     = "10.0.0.7"
  hosts      = ["10.0.0.7"]
  credential = kube-mtls
}
profile "default" { endpoints = [kube] }
`
	w := &webMux{g: gatewayWithPolicy(t, hcl)}
	ev := &Event{
		ID: "evt-k8s-1", Mode: "mitm", Family: "k8s",
		Host: "10.0.0.7", Action: "deny", Endpoint: "kube",
		Rule: "k8s-no-secrets",
		Facets: map[string]any{
			"verb": "get", "resource": "secrets",
			"namespace": "default", "name": "mysecret",
			"params": map[string]any{"watch": "true"},
		},
	}
	rw := httptest.NewRecorder()
	w.writeActionFixture(rw, ev)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	var f Fixture
	if err := json.Unmarshal(rw.Body.Bytes(), &f); err != nil {
		t.Fatalf("reparse: %v\nbody=%s", err, rw.Body.String())
	}
	if f.Action.K8s == nil {
		t.Fatal("expected k8s block")
	}
	got := *f.Action.K8s
	want := K8sAction{
		Verb: "get", Resource: "secrets",
		Namespace: "default", Name: "mysecret",
		Params: map[string]string{"watch": "true"},
	}
	if got.Verb != want.Verb || got.Resource != want.Resource ||
		got.Namespace != want.Namespace || got.Name != want.Name {
		t.Errorf("k8s=%+v want %+v", got, want)
	}
	if got.Params["watch"] != "true" {
		t.Errorf("params=%v want flattened watch=true", got.Params)
	}
	if f.Match.Verdict != "deny" {
		t.Errorf("verdict=%q want deny", f.Match.Verdict)
	}
}

// End-to-end contract between exporter and runner: an Event written
// by the dispatch path → exporter JSON → runOneFixture → the same
// match the exporter recorded. Catches contract drift between the
// two halves of the feature.
func TestExporterRunnerRoundTrip(t *testing.T) {
	const hcl = `
admin_email = "x@example.com"
credential "bearer_token" "tok" {}
endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = tok
}
rule "reads" {
  endpoint  = github
  condition = "http.method == 'GET'"
  verdict   = "allow"
}
profile "default" { endpoints = [github] }
`
	gw := gatewayWithPolicy(t, hcl)
	w := &webMux{g: gw}
	ev := &Event{
		ID: "evt-rt", Mode: "mitm", Family: "https",
		Host: "api.github.com", Method: "GET", Path: "/user",
		AgentIP: "100.64.0.7", Action: "allow",
		Endpoint: "github", Rule: "reads",
	}
	rw := httptest.NewRecorder()
	w.writeActionFixture(rw, ev)
	if rw.Code != 200 {
		t.Fatalf("export status=%d body=%s", rw.Code, rw.Body.String())
	}
	tmp := filepath.Join(t.TempDir(), "rt.json")
	if err := os.WriteFile(tmp, rw.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, msg, err := runOneFixture(gw.Policy(), tmp)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !ok {
		t.Fatalf("round-trip mismatch:\n%s", msg)
	}
}

// passthrough fixtures parse fine but the runner rejects them at
// replay (site/doc/clawpatrol-test.md). Lock in both halves so a future change has
// to pick one side intentionally.
func TestRunnerRejectsPassthrough(t *testing.T) {
	gw := gatewayWithPolicy(t, fixtureHCL)
	body := `{"action":{"host":"api.github.com","http":{"method":"GET","path":"/x"}},` +
		`"match":{"verdict":"passthrough","endpoint":"github"}}`
	tmp := filepath.Join(t.TempDir(), "pt.json")
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, _, err := runOneFixture(gw.Policy(), tmp)
	if ok {
		t.Fatal("expected runner to reject passthrough fixture")
	}
	if err == nil || !strings.Contains(err.Error(), "passthrough") {
		t.Fatalf("err=%v, want passthrough rejection", err)
	}
}
