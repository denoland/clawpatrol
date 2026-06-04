package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestConfigApplyRejectsWhenDashboardWritesDisabled(t *testing.T) {
	w := configApplyTestMux(t, false)
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"append_hcl": `rule "x" { endpoint = https.github verdict = "deny" }`,
	}))
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "dashboard config writes are disabled") {
		t.Fatalf("body=%s", rw.Body.String())
	}
}

func TestConfigApplyRejectsRevisionMismatch(t *testing.T) {
	w := configApplyTestMux(t, true)
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"base_revision": "not-current",
		"append_hcl":    `rule "x" { endpoint = https.github verdict = "deny" }`,
	}))
	if rw.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "config changed") {
		t.Fatalf("body=%s", rw.Body.String())
	}
}

func TestConfigApplyRejectsInvalidSnippet(t *testing.T) {
	w := configApplyTestMux(t, true)
	before, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"base_revision": revisionForBytes(before),
		"append_hcl":    `rule "bad" { endpoint = https.missing verdict = "deny" }`,
	}))
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	after, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("config changed after rejected apply")
	}
}

func TestConfigApplyMergesGeneratedProfileCredentials(t *testing.T) {
	w := configApplyTestMux(t, true)
	before, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	snippet := `endpoint "https" "tinyclouds_org" {
  hosts = ["tinyclouds.org"]
}

credential "passthrough" "tinyclouds_org_passthrough" {
  endpoint = https.tinyclouds_org
}

rule "block_tinyclouds_org" {
  endpoint = https.tinyclouds_org
  verdict = "deny"
}

profile "default" {
  credentials = [passthrough.tinyclouds_org_passthrough]
}`
	candidate := appendConfigSnippet(before, snippet)
	if strings.Count(string(candidate), `profile "default"`) != 1 {
		t.Fatalf("candidate should keep one default profile block:\n%s", candidate)
	}
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"base_revision": revisionForBytes(before),
		"append_hcl":    snippet,
	}))
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	after, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(after), `profile "default"`) != 1 {
		t.Fatalf("config should keep one default profile block:\n%s", after)
	}
	if !strings.Contains(string(after), `passthrough.tinyclouds_org_passthrough`) {
		t.Fatalf("config missing merged profile credential:\n%s", after)
	}
	if !strings.Contains(string(after), `bearer_token.tok`) {
		t.Fatalf("config should retain existing credential:\n%s", after)
	}
	ep := runtime.HostEndpoint(w.g.Policy(), "default", "tinyclouds.org")
	if ep == nil || ep.Name != "tinyclouds_org" {
		t.Fatalf("HostEndpoint = %#v, want generated endpoint", ep)
	}
}

// TestConfigApplyBailsOnComplexProfileBody confirms the regex merge
// refuses to touch profile blocks it can't safely rewrite (inline
// disambiguator entries, here) — the fallback is a plain append that
// validates as a duplicate-profile error rather than silently
// corrupting the existing block.
func TestConfigApplyBailsOnComplexProfileBody(t *testing.T) {
	w := configApplyTestMux(t, true)
	// Replace the simple "default" profile in the seed config with a
	// disambiguator-heavy one so the merge has to bail.
	complexSrc := `gateway {
  state_dir = "` + filepath.ToSlash(filepath.Dir(w.g.cfgPath)) + `"
  dashboard_config_writes = true
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "127.0.0.1:51820"
  }
}

endpoint "https" "github" {
  hosts = ["api.github.com"]
}
credential "bearer_token" "tok-a" { endpoint = https.github }
credential "bearer_token" "tok-b" { endpoint = https.github }

profile "default" {
  credentials = [
    { placeholder = "PH_a", credential = bearer_token.tok-a },
    { placeholder = "PH_b", credential = bearer_token.tok-b },
  ]
}
`
	if err := os.WriteFile(w.g.cfgPath, []byte(complexSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, policy, err := loadConfig(w.g.cfgPath)
	if err != nil {
		t.Fatalf("reload seeded config: %v", err)
	}
	w.g.cfg.Store(cfg)
	w.g.policy.Store(policy)

	before, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	snippet := `endpoint "https" "tinyclouds_org" {
  hosts = ["tinyclouds.org"]
}
credential "passthrough" "tinyclouds_org_passthrough" {
  endpoint = https.tinyclouds_org
}
profile "default" {
  credentials = [passthrough.tinyclouds_org_passthrough]
}`
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"base_revision": revisionForBytes(before),
		"append_hcl":    snippet,
	}))
	// Plain append produces a duplicate "default" profile, which
	// loadConfig rejects. We want the file unchanged and a 400 with
	// the loader's error.
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	after, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("config changed after rejected apply")
	}
	// The disambiguator entries must still be intact in the
	// untouched config.
	if !strings.Contains(string(after), `placeholder = "PH_a"`) {
		t.Fatalf("disambiguator body corrupted:\n%s", after)
	}
}

func TestConfigApplyAppendsAndReloads(t *testing.T) {
	w := configApplyTestMux(t, true)
	before, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	snippet := `rule "block-delete" {
  endpoint = https.github
  condition = "http.method == \"DELETE\""
  verdict = "deny"
}`
	rw := httptest.NewRecorder()
	w.apiConfigApply(rw, jsonReq(map[string]string{
		"base_revision": revisionForBytes(before),
		"append_hcl":    snippet,
	}))
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	after, err := os.ReadFile(w.g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), `rule "block-delete"`) {
		t.Fatalf("config missing appended rule:\n%s", after)
	}
	ep := w.g.Policy().Endpoints["github"]
	if ep == nil {
		t.Fatal("github endpoint missing after reload")
	}
	found := false
	for _, rule := range ep.Rules {
		if rule.Name == "block-delete" {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy did not reload appended rule: %+v", ep.Rules)
	}
}

func configApplyTestMux(t *testing.T, writes bool) *webMux {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	src := `gateway {
  state_dir = "` + filepath.ToSlash(dir) + `"
  dashboard_config_writes = ` + map[bool]string{true: "true", false: "false"}[writes] + `
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "127.0.0.1:51820"
  }
}

endpoint "https" "github" {
  hosts = ["api.github.com"]
}
credential "bearer_token" "tok" { endpoint = https.github }
profile "default" { credentials = [bearer_token.tok] }
`
	if err := os.WriteFile(cfgPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, policy, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	db, err := OpenDB(filepath.Join(dir, "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{cfgPath: cfgPath, stateDir: dir, db: db}
	g.cfg.Store(cfg)
	g.policy.Store(policy)
	return &webMux{g: g}
}

func jsonReq(v any) *http.Request {
	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(v)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", &b)
	req.Header.Set("Content-Type", "application/json")
	return req
}
