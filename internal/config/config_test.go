package config_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

var update = flag.Bool("update", false, "regenerate testdata goldens")

// TestLoad walks config/testdata for fixtures.
//
//	feature_*.hcl  → load must succeed; Dump compared to feature_*.want.json
//	error_*.hcl    → load must surface diagnostics matching error_*.errors.txt
//	full.hcl       → the verbatim v14 spec; load must succeed; Dump compared
//	                 to full.want.json
//
// Run with -update to regenerate goldens.
func TestLoad(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".hcl") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".hcl")
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("testdata", e.Name())
			gw, diags := config.Load(path)

			if strings.HasPrefix(name, "error_") {
				checkErrorFixture(t, path, name, diags)
				return
			}
			if diags.HasErrors() {
				t.Fatalf("unexpected diagnostics:\n%s", renderDiags(diags, path))
			}
			checkFeatureFixture(t, path, name, gw)
		})
	}
}

func checkFeatureFixture(t *testing.T, hclPath, name string, gw *config.Gateway) {
	t.Helper()
	got, err := gw.Dump()
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	wantPath := filepath.Join("testdata", name+".want.json")
	if *update {
		writeGolden(t, wantPath, got)
		return
	}
	want, err := os.ReadFile(wantPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("missing golden %s — run with -update to create", wantPath)
		}
		t.Fatalf("read golden: %v", err)
	}
	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Errorf("dump mismatch for %s (-want +got):\n%s", hclPath, diff)
	}
}

func checkErrorFixture(t *testing.T, hclPath, name string, diags hcl.Diagnostics) {
	t.Helper()
	got := renderDiags(diags, hclPath)
	wantPath := filepath.Join("testdata", name+".errors.txt")
	if *update {
		writeGolden(t, wantPath, []byte(got))
		return
	}
	want, err := os.ReadFile(wantPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("missing golden %s — run with -update to create", wantPath)
		}
		t.Fatalf("read golden: %v", err)
	}
	if diff := cmp.Diff(string(want), got); diff != "" {
		t.Errorf("diagnostics mismatch for %s (-want +got):\n%s", hclPath, diff)
	}
}

// renderDiags reduces an hcl.Diagnostics to a compact "<severity>:
// <summary> — <detail>" form scoped by source (filename:line:col),
// stripped of absolute paths so goldens stay portable across machines.
// hcl.NewDiagnosticTextWriter is overkill here; the compact form is
// what makes the goldens reviewable.
func renderDiags(diags hcl.Diagnostics, hclPath string) string {
	if !diags.HasErrors() && len(diags) == 0 {
		return "(no diagnostics)\n"
	}
	base := filepath.Base(hclPath)
	var out bytes.Buffer
	for _, d := range diags {
		sev := "error"
		if d.Severity == hcl.DiagWarning {
			sev = "warning"
		}
		loc := ""
		if d.Subject != nil {
			loc = strings.TrimPrefix(d.Subject.Filename, filepath.Dir(hclPath)+"/")
			if loc == "" || loc == d.Subject.Filename {
				loc = base
			}
			loc = loc + ":" + itoa(d.Subject.Start.Line) + ":" + itoa(d.Subject.Start.Column)
		}
		out.WriteString(sev)
		out.WriteString(": ")
		if loc != "" {
			out.WriteString(loc)
			out.WriteString(": ")
		}
		out.WriteString(d.Summary)
		if d.Detail != "" {
			out.WriteString(" — ")
			out.WriteString(d.Detail)
		}
		out.WriteString("\n")
	}
	return out.String()
}

func itoa(n int) string {
	// Avoiding strconv import to keep imports lean; n is always small.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestLoadKeysPolicyMapsByQName confirms that Policy.Credentials,
// .Endpoints, .Approvers (the two-label kinds) key by QName so that
// blocks of different types sharing a name coexist as distinct
// entries. Profile / rule / policy stay bare-name since QName ==
// Name for one-label kinds.
func TestLoadKeysPolicyMapsByQName(t *testing.T) {
	src := `
endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential "bearer_token" "ops" {
  endpoint = https.api
}
credential "header_token" "ops" {
  endpoint  = https.api
  header    = "X-Token"
}
profile "default" {
  credentials = [bearer_token.ops, { credential = header_token.ops, placeholder = "PH_alt" }]
}
`
	gw, diags := config.LoadBytes([]byte(src), "qname.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %s", renderDiags(diags, "qname.hcl"))
	}
	if _, ok := gw.Policy.Credentials["bearer_token.ops"]; !ok {
		t.Errorf(`Policy.Credentials missing "bearer_token.ops"`)
	}
	if _, ok := gw.Policy.Credentials["header_token.ops"]; !ok {
		t.Errorf(`Policy.Credentials missing "header_token.ops"`)
	}
	if _, ok := gw.Policy.Endpoints["https.api"]; !ok {
		t.Errorf(`Policy.Endpoints missing "https.api"`)
	}
	if _, ok := gw.Policy.Profiles["default"]; !ok {
		t.Errorf(`Policy.Profiles missing "default" (one-label, QName == Name)`)
	}
}

func writeGolden(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write golden %s: %v", path, err)
	}
}
