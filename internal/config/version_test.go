package config_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
)

// minimalConfig is the smallest body that loads without errors: one
// transport with a dial target. Prefixed per-test with a schema_version
// line (or not) to exercise the version gate.
const minimalConfig = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
`

func loadStr(t *testing.T, src string) (*config.Gateway, hcl.Diagnostics) {
	t.Helper()
	return config.LoadBytes([]byte(src), "version_test.hcl")
}

func hasWarning(diags hcl.Diagnostics, summary string) bool {
	for _, d := range diags {
		if d.Severity == hcl.DiagWarning && d.Summary == summary {
			return true
		}
	}
	return false
}

func errorText(diags hcl.Diagnostics) string {
	var b strings.Builder
	for _, d := range diags {
		if d.Severity == hcl.DiagError {
			b.WriteString(d.Summary)
			b.WriteString(": ")
			b.WriteString(d.Detail)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// Absent schema_version loads as legacy (version 0) and warns, without
// erroring.
func TestSchemaVersionAbsentWarns(t *testing.T) {
	gw, diags := loadStr(t, minimalConfig)
	if diags.HasErrors() {
		t.Fatalf("unexpected errors: %s", errorText(diags))
	}
	if !hasWarning(diags, "No schema_version declared") {
		t.Fatalf("expected absent-version warning, got: %v", diags)
	}
	if gw.SchemaVersion != 0 {
		t.Fatalf("SchemaVersion = %d, want 0", gw.SchemaVersion)
	}
}

// An explicit current version loads clean — no warning.
func TestSchemaVersionExplicitNoWarn(t *testing.T) {
	gw, diags := loadStr(t, "schema_version = 1\n"+minimalConfig)
	if diags.HasErrors() {
		t.Fatalf("unexpected errors: %s", errorText(diags))
	}
	if hasWarning(diags, "No schema_version declared") {
		t.Fatalf("did not expect absent-version warning with explicit version")
	}
	if gw.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", gw.SchemaVersion)
	}
}

// A version newer than the binary supports fails with the single
// upgrade error and nothing else — the lenient pre-pass suppresses the
// strict-decode noise from the (unknown) newer-grammar attribute.
func TestSchemaVersionTooNew(t *testing.T) {
	src := "schema_version = 2\n" + minimalConfig + "\nfuture_block \"x\" {}\n"
	_, diags := loadStr(t, src)
	if !diags.HasErrors() {
		t.Fatalf("expected an error for version > max")
	}
	got := errorText(diags)
	if !strings.Contains(got, "too new") || !strings.Contains(got, "Upgrade clawpatrol") {
		t.Fatalf("expected upgrade error, got: %s", got)
	}
	if strings.Contains(got, "Unsupported") || strings.Contains(got, "future_block") {
		t.Fatalf("strict-decode noise leaked past the version gate: %s", got)
	}
}

// A version below the supported minimum fails with the migrate error.
// Min is currently 0, so only a negative version trips this arm; the
// check still guards the window for when Min advances.
func TestSchemaVersionTooOld(t *testing.T) {
	_, diags := loadStr(t, "schema_version = -1\n"+minimalConfig)
	got := errorText(diags)
	if !strings.Contains(got, "too old") {
		t.Fatalf("expected too-old error, got: %s", got)
	}
}

// A non-integer version is rejected as malformed rather than silently
// coerced.
func TestSchemaVersionInvalid(t *testing.T) {
	_, diags := loadStr(t, "schema_version = \"nope\"\n"+minimalConfig)
	got := errorText(diags)
	if !strings.Contains(got, "Invalid schema_version") {
		t.Fatalf("expected invalid-version error, got: %s", got)
	}
}
