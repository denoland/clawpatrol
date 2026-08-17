package runtime_test

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestMatchOIDCEnrollmentAcceptsGitHubActionsClaims(t *testing.T) {
	cp := compileOIDCPolicy(t, `
enrollment "oidc" "gha-main" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "ci"
  ttl     = "30m"
  max_ttl = "1h"
  match = {
    repository_id = "123456"
    workflow_ref  = "denoland/clawpatrol/.github/workflows/ci.yml@refs/heads/main"
    ref           = "refs/heads/main"
    event_name    = "push"
  }
}
`)

	matched, profile, err := runtime.MatchOIDCEnrollment(cp, &config.OIDCClaimRequest{
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: []string{"https://gateway.example.com"},
		Claims: map[string]any{
			"repository_id": "123456",
			"workflow_ref":  "denoland/clawpatrol/.github/workflows/ci.yml@refs/heads/main",
			"ref":           "refs/heads/main",
			"event_name":    "push",
		},
	})
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if matched == nil || matched.Name != "gha-main" {
		t.Fatalf("matched = %+v, want gha-main", matched)
	}
	if profile == nil || profile.Name != "ci" {
		t.Fatalf("profile = %+v, want ci", profile)
	}
}

func TestMatchOIDCEnrollmentRejectsWrongIssuerAudienceAndClaims(t *testing.T) {
	cp := compileOIDCPolicy(t, `
enrollment "oidc" "gha-main" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "ci"
  ttl     = "30m"
  max_ttl = "1h"
  match = { repository_id = "123456" }
}
`)

	cases := []struct {
		name string
		req  config.OIDCClaimRequest
	}{
		{
			name: "wrong issuer",
			req: config.OIDCClaimRequest{
				Issuer:   "https://issuer.example.com",
				Audience: []string{"https://gateway.example.com"},
				Claims:   map[string]any{"repository_id": "123456"},
			},
		},
		{
			name: "wrong audience",
			req: config.OIDCClaimRequest{
				Issuer:   "https://token.actions.githubusercontent.com",
				Audience: []string{"https://other.example.com"},
				Claims:   map[string]any{"repository_id": "123456"},
			},
		},
		{
			name: "wrong claim",
			req: config.OIDCClaimRequest{
				Issuer:   "https://token.actions.githubusercontent.com",
				Audience: []string{"https://gateway.example.com"},
				Claims:   map[string]any{"repository_id": "999999"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, profile, err := runtime.MatchOIDCEnrollment(cp, &tc.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if matched != nil || profile != nil {
				t.Fatalf("matched/profile = %+v/%+v, want nil", matched, profile)
			}
		})
	}
}

func TestMatchOIDCEnrollmentRequiresAuthorizedPartyForMultiAudience(t *testing.T) {
	cp := compileOIDCPolicy(t, `
enrollment "oidc" "gha-main" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "ci"
  ttl     = "30m"
  max_ttl = "1h"
  match = { repository_id = "123456" }
}
`)

	base := config.OIDCClaimRequest{
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: []string{"https://gateway.example.com", "https://other.example.com"},
		Claims:   map[string]any{"repository_id": "123456"},
	}
	if matched, _, err := runtime.MatchOIDCEnrollment(cp, &base); err != nil || matched != nil {
		t.Fatalf("multi-audience without azp matched=%+v err=%v, want no match", matched, err)
	}
	base.AuthorizedParty = "https://other.example.com"
	if matched, _, err := runtime.MatchOIDCEnrollment(cp, &base); err != nil || matched != nil {
		t.Fatalf("multi-audience wrong azp matched=%+v err=%v, want no match", matched, err)
	}
	base.AuthorizedParty = "https://gateway.example.com"
	if matched, _, err := runtime.MatchOIDCEnrollment(cp, &base); err != nil || matched == nil {
		t.Fatalf("multi-audience matching azp matched=%+v err=%v, want match", matched, err)
	}
}

func TestMatchOIDCEnrollmentRejectsAmbiguousRules(t *testing.T) {
	cp := compileOIDCPolicy(t, `
enrollment "oidc" "first" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "ci"
  ttl     = "30m"
  max_ttl = "1h"
  match = { repository_id = "123456" }
}

enrollment "oidc" "second" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "ci"
  ttl     = "30m"
  max_ttl = "1h"
  match = { repository_id = "123456" }
}
`)
	matched, profile, err := runtime.MatchOIDCEnrollment(cp, &config.OIDCClaimRequest{
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: []string{"https://gateway.example.com"},
		Claims:   map[string]any{"repository_id": "123456"},
	})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("err = %v, want ambiguous match error", err)
	}
	if matched != nil || profile != nil {
		t.Fatalf("ambiguous match returned %+v/%+v, want nil", matched, profile)
	}
}

func TestMatchOIDCEnrollmentDoesNotFallbackToAnotherProfile(t *testing.T) {
	cp := &config.CompiledPolicy{
		OIDCAudience: "https://gateway.example.com",
		Profiles: map[string]*config.CompiledProfile{
			"default": {Name: "default", AllowEphemeralOIDC: true},
		},
		OIDCEnrollmentsByIssuer: map[string][]*config.CompiledOIDCEnrollment{
			"https://token.actions.githubusercontent.com": {
				{
					Name:    "broken",
					Issuer:  "https://token.actions.githubusercontent.com",
					Profile: nil,
					Match:   map[string]any{"repository_id": "123456"},
				},
			},
		},
	}
	matched, profile, err := runtime.MatchOIDCEnrollment(cp, &config.OIDCClaimRequest{
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: []string{"https://gateway.example.com"},
		Claims:   map[string]any{"repository_id": "123456"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched != nil || profile != nil {
		t.Fatalf("matched/profile = %+v/%+v, want nil without profile fallback", matched, profile)
	}
}

func compileOIDCPolicy(t *testing.T, enrollment string) *config.CompiledPolicy {
	t.Helper()
	src := `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.com/"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "pat" {
  endpoint = https.github
}

profile "ci" {
  credentials          = [bearer_token.pat]
  allow_ephemeral_oidc = true
}
` + enrollment
	gw, diags := config.LoadBytes([]byte(src), "oidc_runtime_test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cp
}
