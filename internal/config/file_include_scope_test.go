package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
)

func TestResolveFileIncludesStaysInsideConfigDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("CERT"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "k.pem"), []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	ok := func(marker, want string) {
		t.Helper()
		got, diags := resolveFileIncludes("<<file:"+marker+">>", dir, "e", hcl.Range{})
		if diags.HasErrors() {
			t.Fatalf("%q: unexpected diagnostics: %v", marker, diags)
		}
		if got != want {
			t.Fatalf("%q: got %q, want %q", marker, got, want)
		}
	}
	ok("ca.pem", "CERT")
	ok("sub/k.pem", "KEY")
	ok("sub/../ca.pem", "CERT")

	rejected := func(marker string) {
		t.Helper()
		got, diags := resolveFileIncludes("x<<file:"+marker+">>y", dir, "e", hcl.Range{})
		if !diags.HasErrors() {
			t.Fatalf("%q: expected a diagnostic, got %q", marker, got)
		}
		if strings.Contains(got, "SECRET") || strings.Contains(got, "CERT") {
			t.Fatalf("%q: file contents leaked into output %q", marker, got)
		}
		if got != "xy" {
			t.Fatalf("%q: marker not removed: %q", marker, got)
		}
	}
	rejected(outside)
	rejected("../" + filepath.Base(filepath.Dir(outside)) + "/secret")
	rejected("..")
	rejected("")
}
