package config_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// loadRemoteMCPOAuth loads an inline policy fragment wrapped in the
// minimal gateway prefix and returns the error-level diagnostics
// (warnings such as the legacy-grammar notice are ignored).
func loadRemoteMCPOAuth(t *testing.T, src string) hclDiagSummaries {
	t.Helper()
	_, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "in.hcl")
	out := make(hclDiagSummaries, 0, len(diags))
	for _, d := range diags {
		if d.Severity != hcl.DiagError {
			continue
		}
		out = append(out, d.Summary+": "+d.Detail)
	}
	return out
}

type hclDiagSummaries []string

func (s hclDiagSummaries) contains(sub string) bool {
	for _, m := range s {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

func TestRemoteMCPOAuthBindingValid(t *testing.T) {
	src := `
endpoint "remote_mcp" "acme" {
  url = "https://mcp.acme.test/mcp"
}
credential "remote_mcp_oauth" "acme" {
  endpoint = remote_mcp.acme
  scopes   = ["mcp:read"]
}
profile "p" { credentials = [remote_mcp_oauth.acme] }
`
	if diags := loadRemoteMCPOAuth(t, src); len(diags) > 0 {
		t.Fatalf("expected no diagnostics, got: %v", diags)
	}
}

func TestRemoteMCPOAuthBindingRejectsUnbound(t *testing.T) {
	src := `
credential "remote_mcp_oauth" "acme" {
  scopes = ["mcp:read"]
}
profile "p" { credentials = [remote_mcp_oauth.acme] }
`
	if diags := loadRemoteMCPOAuth(t, src); !diags.contains("must bind exactly one remote_mcp endpoint") {
		t.Fatalf("expected unbound rejection, got: %v", diags)
	}
}

func TestRemoteMCPOAuthBindingRejectsEndpointsList(t *testing.T) {
	src := `
endpoint "remote_mcp" "a" { url = "https://mcp.a.test/mcp" }
endpoint "remote_mcp" "b" { url = "https://mcp.b.test/mcp" }
credential "remote_mcp_oauth" "acme" {
  endpoints = [remote_mcp.a, remote_mcp.b]
}
profile "p" { credentials = [remote_mcp_oauth.acme] }
`
	if diags := loadRemoteMCPOAuth(t, src); !diags.contains("must bind exactly one remote_mcp endpoint") {
		t.Fatalf("expected endpoints-list rejection, got: %v", diags)
	}
}

func TestRemoteMCPOAuthBindingRejectsNonRemoteMCP(t *testing.T) {
	src := `
endpoint "https" "web" { hosts = ["api.acme.test"] }
credential "remote_mcp_oauth" "acme" {
  endpoint = https.web
}
profile "p" { credentials = [remote_mcp_oauth.acme] }
`
	if diags := loadRemoteMCPOAuth(t, src); !diags.contains("non-remote_mcp endpoint") {
		t.Fatalf("expected non-remote_mcp rejection, got: %v", diags)
	}
}

func TestRemoteMCPOAuthRejectsProviderCompat(t *testing.T) {
	src := `
endpoint "remote_mcp" "acme" { url = "https://mcp.acme.test/mcp" }
credential "remote_mcp_oauth" "acme" {
  endpoint        = remote_mcp.acme
  provider_compat = "grain"
}
profile "p" { credentials = [remote_mcp_oauth.acme] }
`
	if diags := loadRemoteMCPOAuth(t, src); !diags.contains("Unsupported provider_compat") {
		t.Fatalf("expected provider_compat rejection, got: %v", diags)
	}
}

func TestRemoteMCPOAuthRejectsResourceURLOverride(t *testing.T) {
	src := `
endpoint "remote_mcp" "acme" { url = "https://mcp.acme.test/mcp" }
credential "remote_mcp_oauth" "acme" {
  endpoint     = remote_mcp.acme
  resource_url = "https://other.example.test/mcp"
}
profile "p" { credentials = [remote_mcp_oauth.acme] }
`
	if diags := loadRemoteMCPOAuth(t, src); !diags.contains("Unsupported resource_url") {
		t.Fatalf("expected resource_url rejection, got: %v", diags)
	}
}
