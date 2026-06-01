package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// TestLoadDirectory exercises the multi-file directory loader. The
// shape under test: a baseline config split into several .hcl files,
// loaded as a directory, must resolve to the same shape as the
// equivalent single-file load — including cross-file references and
// stable ordering.
func TestLoadDirectory(t *testing.T) {
	dir := t.TempDir()

	writeHCL(t, dir, "00-gateway.hcl", `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

defaults {
  unknown_host  = "passthrough"
  llm_fail_mode = "closed"
}
`)

	// Endpoint declared in one file, credential referencing it from
	// another, rule referencing both from a third — proves the symbol
	// table is built from the merged view, not from any single file.
	writeHCL(t, dir, "10-endpoints.hcl", `
endpoint "https" "github" {
  hosts = ["api.github.com", "github.com"]
}
`)

	writeHCL(t, dir, "20-credentials.hcl", `
credential "bearer_token" "github" {
  endpoint = https.github
}
`)

	writeHCL(t, dir, "30-rules.hcl", `
approver "human_approver" "ops" {
  channel = "#agent-ops"
  timeout = 600
}

rule "github-reads" {
  endpoint  = https.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = https.github
  condition = "http.method in ['POST', 'PATCH', 'DELETE']"
  approve   = [human_approver.ops]
}

profile "default" {
  credentials = [bearer_token.github]
}
`)

	gw, diags := config.Load(dir)
	if diags.HasErrors() {
		t.Fatalf("unexpected diagnostics:\n%s", diags.Error())
	}
	if gw == nil || gw.Policy == nil {
		t.Fatalf("expected non-nil gateway and policy")
	}

	if _, ok := gw.Policy.Endpoints["github"]; !ok {
		t.Errorf("endpoint github missing from merged policy")
	}
	if _, ok := gw.Policy.Credentials["github"]; !ok {
		t.Errorf("credential github missing")
	}
	if _, ok := gw.Policy.Rules["github-reads"]; !ok {
		t.Errorf("rule github-reads missing")
	}
	if _, ok := gw.Policy.Rules["github-writes"]; !ok {
		t.Errorf("rule github-writes missing")
	}
	if _, ok := gw.Policy.Approvers["ops"]; !ok {
		t.Errorf("approver ops missing")
	}
	if _, ok := gw.Policy.Profiles["default"]; !ok {
		t.Errorf("profile default missing")
	}

	// Symbol ranges should still point at the originating file, not
	// the directory or a synthesized name. Operators rely on this for
	// jump-to-line diagnostics across files.
	endpoint := gw.Policy.Endpoints["github"]
	if !strings.HasSuffix(endpoint.Symbol.Block.DefRange.Filename, "10-endpoints.hcl") {
		t.Errorf("endpoint range filename = %q, want suffix 10-endpoints.hcl", endpoint.Symbol.Block.DefRange.Filename)
	}
	rule := gw.Policy.Rules["github-reads"]
	if !strings.HasSuffix(rule.Symbol.Block.DefRange.Filename, "30-rules.hcl") {
		t.Errorf("rule range filename = %q, want suffix 30-rules.hcl", rule.Symbol.Block.DefRange.Filename)
	}
}

// TestLoadDirectoryEquivalentToSingleFile verifies that splitting a
// single-file fixture across multiple files produces the same set of
// declared entities. This is the "ordering doesn't change semantics"
// contract — references resolve against the merged symbol table.
func TestLoadDirectoryEquivalentToSingleFile(t *testing.T) {
	single, diags := config.Load(filepath.Join("testdata", "feature_minimal.hcl"))
	if diags.HasErrors() {
		t.Fatalf("single-file load failed: %s", diags.Error())
	}

	dir := t.TempDir()
	// Reverse-order filenames: rules first alphabetically, gateway
	// last. The loader must still resolve everything correctly because
	// the symbol table is built across all files before any reference
	// is checked.
	writeHCL(t, dir, "a-rules.hcl", `
rule "github-reads" {
  endpoint  = https.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = https.github
  condition = "http.method in ['POST', 'PATCH', 'DELETE']"
  approve   = [human_approver.ops]
}

profile "default" {
  credentials = [bearer_token.github]
}
`)
	writeHCL(t, dir, "b-creds.hcl", `
credential "bearer_token" "github" {
  endpoint = https.github
}

approver "human_approver" "ops" {
  channel = "#agent-ops"
  timeout = 600
}
`)
	writeHCL(t, dir, "c-endpoints.hcl", `
endpoint "https" "github" {
  hosts = ["api.github.com", "github.com"]
}
`)
	writeHCL(t, dir, "d-gateway.hcl", `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

defaults {
  unknown_host  = "passthrough"
  llm_fail_mode = "closed"
}
`)

	multi, diags := config.Load(dir)
	if diags.HasErrors() {
		t.Fatalf("directory load failed:\n%s", diags.Error())
	}

	if got, want := len(multi.Policy.Endpoints), len(single.Policy.Endpoints); got != want {
		t.Errorf("endpoint count: multi=%d, single=%d", got, want)
	}
	if got, want := len(multi.Policy.Credentials), len(single.Policy.Credentials); got != want {
		t.Errorf("credential count: multi=%d, single=%d", got, want)
	}
	if got, want := len(multi.Policy.Rules), len(single.Policy.Rules); got != want {
		t.Errorf("rule count: multi=%d, single=%d", got, want)
	}
	if got, want := len(multi.Policy.Approvers), len(single.Policy.Approvers); got != want {
		// Approvers contains the built-in "dashboard"; same on both.
		t.Errorf("approver count: multi=%d, single=%d", got, want)
	}
	if got, want := len(multi.Policy.Profiles), len(single.Policy.Profiles); got != want {
		t.Errorf("profile count: multi=%d, single=%d", got, want)
	}
}

// TestLoadDirectoryRejectsDuplicateEntity exercises pass-1's existing
// duplicate-name check across files: declaring the same endpoint
// `name` in two files must be a load error.
func TestLoadDirectoryRejectsDuplicateEntity(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-gateway.hcl", minimalGateway)
	writeHCL(t, dir, "10-a.hcl", `
endpoint "https" "shared" {
  hosts = ["a.example.com"]
}
`)
	writeHCL(t, dir, "20-b.hcl", `
endpoint "https" "shared" {
  hosts = ["b.example.com"]
}
`)

	_, diags := config.Load(dir)
	if !diags.HasErrors() {
		t.Fatalf("expected duplicate-name diagnostic, got none")
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Summary, "Duplicate endpoint name") {
			found = true
			if d.Subject == nil || !strings.HasSuffix(d.Subject.Filename, "20-b.hcl") {
				t.Errorf("duplicate diag subject = %v, want filename suffix 20-b.hcl", d.Subject)
			}
		}
	}
	if !found {
		t.Errorf("expected 'Duplicate endpoint name' diagnostic. Got:\n%s", diags.Error())
	}
}

// TestLoadDirectoryRejectsDuplicateGatewayBlock checks the
// singleton-block contract: only one `gateway {}` block is allowed
// across the whole module. gohcl emits the diagnostic with both
// source ranges.
func TestLoadDirectoryRejectsDuplicateGatewayBlock(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-a.hcl", `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
`)
	writeHCL(t, dir, "10-b.hcl", `
gateway {
  state_dir = "/elsewhere"
  wireguard {
    subnet_cidr = "10.99.0.0/24"
  }
}
`)
	_, diags := config.Load(dir)
	if !diags.HasErrors() {
		t.Fatal("expected duplicate gateway diagnostic")
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Summary, "Duplicate gateway block") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Duplicate gateway block' diagnostic. Got:\n%s", diags.Error())
	}
}

// TestLoadDirectoryEmpty is a regression guard against silently
// booting a gateway with no policy because the operator pointed
// `-config` at the wrong directory.
func TestLoadDirectoryEmpty(t *testing.T) {
	dir := t.TempDir()
	_, diags := config.Load(dir)
	if !diags.HasErrors() {
		t.Fatal("expected 'no HCL files' diagnostic for empty directory")
	}
	if !strings.Contains(diags.Error(), "No HCL config files found") {
		t.Errorf("diagnostic text mismatch: %s", diags.Error())
	}
}

// TestLoadDirectorySkipsHiddenAndNonHCL ensures editor temporaries
// and unrelated files don't get pulled into the parse.
func TestLoadDirectorySkipsHiddenAndNonHCL(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "00-gateway.hcl", minimalGateway)
	// Editor swap file — must be ignored.
	if err := os.WriteFile(filepath.Join(dir, ".00-gateway.hcl.swp"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	// README in same directory — must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Subdirectory with another .hcl — non-recursive, must be ignored.
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeHCL(t, sub, "x.hcl", `endpoint "https" "ignored" { hosts = ["never.example.com"] }`)

	gw, diags := config.Load(dir)
	if diags.HasErrors() {
		t.Fatalf("unexpected diagnostics: %s", diags.Error())
	}
	if _, ok := gw.Policy.Endpoints["ignored"]; ok {
		t.Errorf("subdir endpoint was loaded; LoadDir must be non-recursive")
	}
}

// TestLoadDirectorySingleFileWorksLikeBefore confirms that the
// directory loader is a pure superset — a directory with one file
// behaves like that single file.
func TestLoadDirectorySingleFileWorksLikeBefore(t *testing.T) {
	dir := t.TempDir()
	writeHCL(t, dir, "only.hcl", `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

endpoint "https" "github" {
  hosts = ["api.github.com"]
}
`)

	gw, diags := config.Load(dir)
	if diags.HasErrors() {
		t.Fatalf("unexpected diagnostics: %s", diags.Error())
	}
	if _, ok := gw.Policy.Endpoints["github"]; !ok {
		t.Errorf("single-file-in-dir endpoint missing")
	}
}

// TestLoadFileStillWorks is a regression guard that passing a regular
// file path to Load still works (no directory-mode override).
func TestLoadFileStillWorks(t *testing.T) {
	gw, diags := config.Load(filepath.Join("testdata", "feature_minimal.hcl"))
	if diags.HasErrors() {
		t.Fatalf("file load failed: %s", diags.Error())
	}
	if gw.Policy == nil {
		t.Fatal("nil policy")
	}
}

func writeHCL(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

const minimalGateway = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
`
