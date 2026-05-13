package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Re-uses config/testdata fixtures so we don't drift from the suite
// that owns the load/compile contract.
func TestValidateCmd(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    int
		prefix  string // wanted output prefix
		mustHas string // substring that must appear in output
	}{
		{"ok-minimal", []string{"config/testdata/feature_minimal.hcl"}, 0, "ok: ", "1 profile(s)"},
		{"err-unknown-endpoint", []string{"config/testdata/error_unknown_endpoint.hcl"}, 1, "", "mystery"},
		{"err-name-collision", []string{"config/testdata/error_name_collision.hcl"}, 1, "", "shared"},
		{"usage-no-args", nil, 2, "usage:", "validate"},
		{"usage-too-many", []string{"a.hcl", "b.hcl"}, 2, "usage:", "validate"},
		{"usage-help", []string{"--help"}, 2, "usage:", "validate"},
		{"err-missing-file", []string{filepath.Join(t.TempDir(), "nope.hcl")}, 1, "", "nope.hcl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, code := validateCmd(tc.args)
			if code != tc.want {
				t.Fatalf("exit = %d, want %d (msg=%q)", code, tc.want, msg)
			}
			if tc.prefix != "" && !strings.HasPrefix(msg, tc.prefix) {
				t.Errorf("msg = %q, want prefix %q", msg, tc.prefix)
			}
			if tc.mustHas != "" && !strings.Contains(msg, tc.mustHas) {
				t.Errorf("msg = %q, want substring %q", msg, tc.mustHas)
			}
		})
	}
}

// TestValidateCmdEmitsAllDiagnostics — when the HCL has multiple
// independent errors, validate prints each one on its own line so the
// user can fix them in a single editor round-trip. Regression: the
// previous implementation called diags.Error() which prints only the
// first error followed by "and N other diagnostic(s)".
func TestValidateCmdEmitsAllDiagnostics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.hcl")
	body := `listen      = "0.0.0.0:8443"
info_listen = "0.0.0.0:9080"
public_url  = "http://x:9080"
ca_dir      = "/tmp/ca"
log_path    = "/tmp/x.log"
oauth_dir   = "/tmp/oauth"
control        = "wireguard"
wg_endpoint    = "1.2.3.4:51820"
wg_subnet_cidr = "10.55.0.0/24"
credential "anthropic_oauth_subscription" "claude" {}
endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  credential = claude
}
profile "default" {
  endpoints = [anthropic, missing-one, also-missing]
}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	msg, code := validateCmd([]string{path})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (msg=%q)", code, msg)
	}
	// Both unknown-variable diagnostics must surface, not just one.
	for _, want := range []string{"missing-one", "also-missing"} {
		if !strings.Contains(msg, want) {
			t.Errorf("msg missing %q\nfull:\n%s", want, msg)
		}
	}
	// Must not be the truncated stock hcl.Diagnostics format.
	if strings.Contains(msg, "other diagnostic") {
		t.Errorf("unexpected truncation; msg = %q", msg)
	}
}

// TestValidateCmdBadHCL covers syntactically broken HCL (parse error
// before compile even gets a chance). Inline so the fixture set in
// config/testdata stays focused on semantic checks.
func TestValidateCmdBadHCL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.hcl")
	if err := os.WriteFile(path, []byte("endpoint \"https\" \"x\" { hosts = [\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	msg, code := validateCmd([]string{path})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (msg=%q)", code, msg)
	}
	if !strings.Contains(msg, "Missing expression") && !strings.Contains(msg, "expression") {
		t.Errorf("msg = %q, want HCL parse diagnostic", msg)
	}
}
