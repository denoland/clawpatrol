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

	"github.com/denoland/clawpatrol/config"
)

const baseHCL = `
listen          = "127.0.0.1:8080"
state_dir       = "/tmp/x"

endpoint "https" "anthropic" {
  hosts = ["api.anthropic.com"]
}

profile "default" {
  endpoints = [anthropic]
}
`

const riskyTunnelHCL = baseHCL + `
tunnel "local_command" "shell-x" {
  command = ["sh", "-c", "echo pwned"]
  listen  = "127.0.0.1:9999"
}
`

const riskyTunnelHCL2 = baseHCL + `
tunnel "local_command" "shell-x" {
  command = ["sh", "-c", "echo pwned"]
  listen  = "127.0.0.1:9999"
}

tunnel "local_command" "shell-y" {
  command = ["sh", "-c", "echo also"]
  listen  = "127.0.0.1:9998"
}
`

// TestPreviewSurfacesHighRiskAdditions: a draft that adds a
// local_command tunnel returns the block name in high_risk_additions.
func TestPreviewSurfacesHighRiskAdditions(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	if err := os.WriteFile(cfgPath, []byte(baseHCL), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{cfgPath: cfgPath}}
	req := httptest.NewRequest(http.MethodPost, "/api/config/preview",
		strings.NewReader(riskyTunnelHCL))
	rr := httptest.NewRecorder()
	w.apiConfigPreview(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got struct {
		HighRisk []string `json:"high_risk_additions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(got.HighRisk) != 1 || got.HighRisk[0] != "shell-x" {
		t.Fatalf("high_risk_additions = %v, want [shell-x]", got.HighRisk)
	}
}

// TestPreviewSkipsExistingRiskyTunnels: a draft that just edits an
// already-declared local_command tunnel does NOT trip the gate.
func TestPreviewSkipsExistingRiskyTunnels(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	if err := os.WriteFile(cfgPath, []byte(riskyTunnelHCL), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{cfgPath: cfgPath}}
	// Edit the existing block: bump the listen port. Name unchanged.
	edited := strings.Replace(riskyTunnelHCL, "127.0.0.1:9999", "127.0.0.1:8888", 1)
	req := httptest.NewRequest(http.MethodPost, "/api/config/preview",
		strings.NewReader(edited))
	rr := httptest.NewRecorder()
	w.apiConfigPreview(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got struct {
		HighRisk []string `json:"high_risk_additions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(got.HighRisk) != 0 {
		t.Fatalf("high_risk_additions = %v, want []", got.HighRisk)
	}
}

// TestSaveWithoutConfirmRejectsHighRisk: save endpoint returns 412
// when a high-risk addition is present and confirm_high_risk is false.
func TestSaveWithoutConfirmRejectsHighRisk(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	if err := os.WriteFile(cfgPath, []byte(baseHCL), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{cfgPath: cfgPath}}
	preview := previewConfigForTest(t, w, riskyTunnelHCL)

	payload, _ := json.Marshal(map[string]any{
		"content":           preview.Formatted,
		"expected_revision": preview.Revision,
		"preview_token":     preview.PreviewToken,
		"confirm_high_risk": false,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/config/save", bytes.NewReader(payload))
	rr := httptest.NewRecorder()
	w.apiConfigSave(rr, req)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412, body = %s", rr.Code, rr.Body.String())
	}
	contents, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(contents, []byte(baseHCL)) {
		t.Fatalf("unconfirmed save wrote file: %q", contents)
	}
	// Body should surface the disallowed block name.
	var body struct {
		HighRisk []string `json:"high_risk_additions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body json: %v", err)
	}
	if len(body.HighRisk) != 1 || body.HighRisk[0] != "shell-x" {
		t.Fatalf("body.high_risk_additions = %v, want [shell-x]", body.HighRisk)
	}
}

// TestSaveWithConfirmPermitsHighRisk: same payload with
// confirm_high_risk:true writes the file.
func TestSaveWithConfirmPermitsHighRisk(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	if err := os.WriteFile(cfgPath, []byte(baseHCL), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{cfgPath: cfgPath}}
	preview := previewConfigForTest(t, w, riskyTunnelHCL)

	payload, _ := json.Marshal(map[string]any{
		"content":           preview.Formatted,
		"expected_revision": preview.Revision,
		"preview_token":     preview.PreviewToken,
		"confirm_high_risk": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/config/save", bytes.NewReader(payload))
	rr := httptest.NewRecorder()
	w.apiConfigSave(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	contents, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(contents), `tunnel "local_command" "shell-x"`) {
		t.Fatalf("confirmed save didn't write file:\n%s", contents)
	}
}

// TestSaveAllowTunnelsRejectsDisallowedType: when --allow-tunnels is
// set, a save introducing a non-allowlisted tunnel type is rejected
// at validate time with 403 — even before the confirm gate.
func TestSaveAllowTunnelsRejectsDisallowedType(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	if err := os.WriteFile(cfgPath, []byte(baseHCL), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{
		cfgPath:      cfgPath,
		allowTunnels: map[string]bool{"ssh_command": true},
	}}
	req := httptest.NewRequest(http.MethodPost, "/api/config/preview",
		strings.NewReader(riskyTunnelHCL))
	rr := httptest.NewRecorder()
	w.apiConfigPreview(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "local_command") {
		t.Fatalf("body doesn't mention disallowed type: %s", rr.Body.String())
	}
}

// TestRiskyTunnelDiffMultiAdds: introducing two new local_command
// blocks at once surfaces both names, sorted.
func TestRiskyTunnelDiffMultiAdds(t *testing.T) {
	got := riskyTunnelDiff([]byte(baseHCL), []byte(riskyTunnelHCL2))
	want := []string{"shell-x", "shell-y"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("riskyTunnelDiff = %v, want %v", got, want)
	}
}

// TestParseAllowTunnels: handles trimming + empty entries.
func TestParseAllowTunnels(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"ssh_command", []string{"ssh_command"}},
		{"ssh_command, kubernetes_port_forward", []string{"kubernetes_port_forward", "ssh_command"}},
		{" , , ", nil},
	}
	for _, tc := range cases {
		got := parseAllowTunnels(tc.in)
		if tc.want == nil {
			if got != nil {
				t.Errorf("parseAllowTunnels(%q) = %v, want nil", tc.in, got)
			}
			continue
		}
		gotList := make([]string, 0, len(got))
		for k := range got {
			gotList = append(gotList, k)
		}
		if len(gotList) != len(tc.want) {
			t.Errorf("parseAllowTunnels(%q) = %v, want %v", tc.in, gotList, tc.want)
			continue
		}
		seen := map[string]bool{}
		for _, k := range gotList {
			seen[k] = true
		}
		for _, want := range tc.want {
			if !seen[want] {
				t.Errorf("parseAllowTunnels(%q) missing %q (got %v)", tc.in, want, gotList)
			}
		}
	}
}

// TestDisallowedTunnelTypesInHCL: parses HCL and reports tunnels not
// in the allowlist.
func TestDisallowedTunnelTypesInHCL(t *testing.T) {
	allow := map[string]bool{"ssh_command": true}
	got := disallowedTunnelTypesInHCL([]byte(riskyTunnelHCL), allow)
	if len(got) != 1 || !strings.Contains(got[0], "shell-x") {
		t.Fatalf("disallowedTunnelTypesInHCL = %v, want [shell-x (local_command)]", got)
	}
}

// TestRiskyTunnelDiffParseFailure: unparseable new HCL returns nil
// (don't double-report; validateAndFormatConfig handles the parse error).
func TestRiskyTunnelDiffParseFailure(t *testing.T) {
	got := riskyTunnelDiff([]byte(baseHCL), []byte("garbage {{{ not hcl"))
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

// guard: keep config import alive in case test compilation rejigs.
var _ = config.LoadBytes
