package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/tools/docgen/internal/render"
)

// TestGeneratedDocIsFresh fails when site/doc/config-reference.md
// drifts from what the generator currently produces. Run
// `go run ./tools/docgen` from the repo root and commit the result.
func TestGeneratedDocIsFresh(t *testing.T) {
	got, err := render.Generate()
	if err != nil {
		t.Fatalf("render.Generate: %v", err)
	}

	root := repoRoot(t)
	path := filepath.Join(root, "site", "doc", "config-reference.md")
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	if string(want) == got {
		return
	}

	wantLines := strings.Split(string(want), "\n")
	gotLines := strings.Split(got, "\n")
	t.Errorf("site/doc/config-reference.md is stale.\n"+
		"Run `go run ./tools/docgen` from the repo root and commit the result.\n"+
		"Committed: %d lines; generated: %d lines.\n%s",
		len(wantLines), len(gotLines), firstDiff(wantLines, gotLines))
}

func TestGatewayPluginBlockIsOptional(t *testing.T) {
	got, err := render.Generate()
	if err != nil {
		t.Fatalf("render.Generate: %v", err)
	}
	const row = "| `plugin` | `block` | no |"
	if !strings.Contains(got, row) {
		t.Fatalf("generated config reference should mark top-level plugin blocks optional; missing row prefix %q", row)
	}
}

func TestEnrollmentRequiredFields(t *testing.T) {
	got, err := render.Generate()
	if err != nil {
		t.Fatalf("render.Generate: %v", err)
	}
	const heading = "### `enrollment \"kubernetes_token_review\" \"<name>\"`"
	start := strings.Index(got, heading)
	if start < 0 {
		t.Fatalf("generated config reference missing %s", heading)
	}
	section := got[start:]
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	for _, row := range []string{
		"| `audience` | `string` | yes |",
		"| `match` | `block` | yes |",
		"| `keepalive_interval` | `string` | no |",
		"| `keepalive_reap_count` | `int` | no |",
		"| `namespace` | `string` | yes |",
		"| `service_account` | `string` | yes |",
		"| `profile_label` | `string` | no |",
		"| `profiles` | `[]string` | yes |",
	} {
		if !strings.Contains(section, row) {
			t.Errorf("generated config reference missing row prefix %q", row)
		}
	}
	if !strings.Contains(section, `enrollment "kubernetes_token_review" "example" {
  audience = "example"
  match {
    namespace = "example"
    service_account = "example"
    profiles = ["example"]
  }
}`) {
		t.Error("generated Kubernetes enrollment example omits required fields")
	}
}

func firstDiff(a, b []string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return fmt.Sprintf("First differing line %d:\n  committed: %s\n  generated: %s\n",
				i+1, a[i], b[i])
		}
	}
	if len(a) != len(b) {
		return fmt.Sprintf("Files agree on the first %d lines but lengths differ.\n", n)
	}
	return ""
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// .../internal/tools/docgen/docgen_test.go → repo root is 3 levels up.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
