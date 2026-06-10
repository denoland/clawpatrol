package main

import (
	"flag"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// updateGolden regenerates the .md/.json golden files instead of
// asserting against them. Run `go test ./cmd/clawpatrol -run
// TestDiscoveryGolden -update` after an intentional output change, then
// eyeball the diff before committing.
var updateGolden = flag.Bool("update", false, "rewrite discovery golden files")

// discoveryGoldenCases are functional end-to-end checks: each loads one
// HCL config, renders one profile's manifest through both output paths,
// and asserts the result byte-for-byte against a committed golden. They
// cover the distinct config shapes a profile can produce — an empty
// profile, a simple single-endpoint/single-credential profile, a
// profile with multiple credentials bound to one endpoint, and a
// profile whose endpoint sits behind a tunnel.
var discoveryGoldenCases = []struct {
	name    string // golden file stem under testdata/discovery/
	hcl     string // HCL fixture file under testdata/discovery/
	profile string // profile to render
}{
	{name: "empty", hcl: "empty.hcl", profile: "empty"},
	{name: "simple", hcl: "simple.hcl", profile: "simple"},
	{name: "multicred", hcl: "multicred.hcl", profile: "dba"},
	{name: "tunnel", hcl: "tunnel.hcl", profile: "tunneled"},
	{name: "envvars", hcl: "envvars.hcl", profile: "ai"},
}

func compileDiscoveryFile(t *testing.T, file string) *config.CompiledPolicy {
	t.Helper()
	path := filepath.Join("testdata", "discovery", file)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	gw, diags := config.LoadBytes(src, file)
	if diags.HasErrors() {
		t.Fatalf("load %s: %v", file, diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile %s: %v", file, err)
	}
	return cp
}

// renderJSON drives the real HTTP response path (?format=json) so the
// golden captures exactly what an agent receives, trailing newline and
// all, not a side rendering.
func renderJSON(t *testing.T, policy *config.CompiledPolicy, profile string) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://clawpatrol.internal/?format=json", nil)
	writeDiscoveryResponse(rec, req, policy, profile)
	return rec.Body.Bytes()
}

func checkGolden(t *testing.T, name, ext string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "discovery", name+ext)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create)", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s mismatch (run with -update to refresh).\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestDiscoveryGolden(t *testing.T) {
	for _, tc := range discoveryGoldenCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := compileDiscoveryFile(t, tc.hcl)

			m := buildDiscoveryManifest(policy, tc.profile)
			checkGolden(t, tc.name, ".md", []byte(m.Markdown()))
			checkGolden(t, tc.name, ".json", renderJSON(t, policy, tc.profile))
		})
	}
}
