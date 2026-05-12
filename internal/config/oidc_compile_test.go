package config_test

import (
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

func TestCompileOIDCEnrollmentPolicy(t *testing.T) {
	gw := loadOIDCEnrollmentConfig(t, `
enrollment "oidc" "gha" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = ci
  ttl     = "30m"
  max_ttl = "1h"
  match = {
    repository_id = "123456"
    workflow_ref  = "denoland/clawpatrol/.github/workflows/ci.yml@refs/heads/main"
  }
  metadata = {
    owner = "denoland"
  }
}
`)
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	if cp.OIDCAudience != "https://gateway.example.com" {
		t.Fatalf("OIDCAudience = %q, want normalized public_url", cp.OIDCAudience)
	}
	prof := cp.Profiles["ci"]
	if prof == nil {
		t.Fatal("missing compiled ci profile")
	}
	if !prof.AllowEphemeralOIDC {
		t.Fatal("compiled ci profile did not preserve allow_ephemeral_oidc")
	}
	if len(cp.OIDCEnrollments) != 1 {
		t.Fatalf("OIDCEnrollments length = %d, want 1", len(cp.OIDCEnrollments))
	}
	enr := cp.OIDCEnrollments[0]
	if enr.Name != "gha" {
		t.Fatalf("enrollment name = %q, want gha", enr.Name)
	}
	if enr.Issuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("issuer = %q", enr.Issuer)
	}
	if enr.Profile != prof {
		t.Fatalf("enrollment profile pointer = %+v, want ci compiled profile", enr.Profile)
	}
	if enr.TTL != 30*time.Minute || enr.MaxTTL != time.Hour {
		t.Fatalf("TTL/MaxTTL = %v/%v, want 30m/1h", enr.TTL, enr.MaxTTL)
	}
	if got := enr.Match["repository_id"]; got != "123456" {
		t.Fatalf("match repository_id = %#v", got)
	}
	if got := enr.Metadata["owner"]; got != "denoland" {
		t.Fatalf("metadata owner = %#v", got)
	}
	byIssuer := cp.OIDCEnrollmentsByIssuer["https://token.actions.githubusercontent.com"]
	if len(byIssuer) != 1 || byIssuer[0] != enr {
		t.Fatalf("issuer index = %+v, want compiled enrollment", byIssuer)
	}
}

func TestCompileOIDCEnrollmentPreservesDeclarationOrder(t *testing.T) {
	gw := loadOIDCEnrollmentConfig(t, `
enrollment "oidc" "first" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = ci
  ttl     = "15m"
  max_ttl = "1h"
  match = { repository_id = "1" }
}

enrollment "oidc" "second" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = ci
  ttl     = "15m"
  max_ttl = "1h"
  match = { repository_id = "2" }
}
`)
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := []string{cp.OIDCEnrollments[0].Name, cp.OIDCEnrollments[1].Name}
	want := []string{"first", "second"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OIDCEnrollments order = %v, want %v", got, want)
		}
	}
}

func loadOIDCEnrollmentConfig(t *testing.T, enrollment string) *config.Gateway {
	t.Helper()
	src := `
public_url = "https://gateway.example.com/"

credential "bearer_token" "pat" {}
endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}
profile "ci" {
  endpoints = [github]
  allow_ephemeral_oidc = true
}
` + enrollment
	gw, diags := config.LoadBytes([]byte(src), "oidc_compile_test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	return gw
}
