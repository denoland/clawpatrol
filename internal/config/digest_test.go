package config_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

func loadFull(t *testing.T) *config.Gateway {
	t.Helper()
	gw, diags := config.Load(filepath.Join("testdata", "full.hcl"))
	if diags.HasErrors() {
		t.Fatalf("load full.hcl: %s", diags.Error())
	}
	return gw
}

func TestPolicyDigestStable(t *testing.T) {
	gw := loadFull(t)
	d1 := config.PolicyDigest(gw)
	d2 := config.PolicyDigest(gw)
	if len(d1) == 0 {
		t.Fatal("digest is empty")
	}
	if len(d1) != len(d2) {
		t.Fatalf("digest not stable: %d vs %d keys", len(d1), len(d2))
	}
	for k, v := range d1 {
		if d2[k] != v {
			t.Fatalf("digest key %q unstable", k)
		}
	}
	if _, ok := d1["gateway"]; !ok {
		t.Errorf("expected a 'gateway' operational key, got keys: %v", keys(d1))
	}
}

func TestPolicyDigestKeysCoverEntities(t *testing.T) {
	gw := loadFull(t)
	d := config.PolicyDigest(gw)
	// full.hcl declares profiles; every profile should appear as
	// "profile <name>".
	var profileKeys int
	for k := range d {
		if strings.HasPrefix(k, "profile ") {
			profileKeys++
		}
	}
	if profileKeys == 0 {
		t.Fatalf("expected at least one profile key, got: %v", keys(d))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
