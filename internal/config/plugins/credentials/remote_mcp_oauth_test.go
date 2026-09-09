package credentials

import (
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestRemoteMCPOAuthInjectHTTPSetsBearer(t *testing.T) {
	c := &RemoteMCPOAuth{}
	req, _ := http.NewRequest(http.MethodPost, "https://mcp.example.test/mcp", nil)
	if err := c.InjectHTTP(t.Context(), req, runtime.Secret{Kind: "oauth_bearer", Bytes: []byte("access-token-123")}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer access-token-123" {
		t.Errorf("Authorization = %q, want bearer", got)
	}
}

func TestRemoteMCPOAuthInjectHTTPNoTokenIsNoop(t *testing.T) {
	c := &RemoteMCPOAuth{}
	req, _ := http.NewRequest(http.MethodPost, "https://mcp.example.test/mcp", nil)
	if err := c.InjectHTTP(t.Context(), req, runtime.Secret{}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty when no token", got)
	}
}

func TestRemoteMCPOAuthFlowShape(t *testing.T) {
	c := &RemoteMCPOAuth{Scopes: []string{"mcp:read", "offline_access"}, ResourceURL: "https://mcp.example.test/mcp"}
	flow := c.OAuthFlow()
	if flow.Flow != "remote_mcp_oauth" {
		t.Errorf("flow = %q", flow.Flow)
	}
	if flow.Header != "Authorization" || flow.Prefix != "Bearer " {
		t.Errorf("header/prefix = %q/%q", flow.Header, flow.Prefix)
	}
	if flow.OAuth.ResourceURL != "https://mcp.example.test/mcp" {
		t.Errorf("resource url = %q", flow.OAuth.ResourceURL)
	}
	if len(flow.OAuth.Scopes) != 2 {
		t.Errorf("scopes = %#v", flow.OAuth.Scopes)
	}
	// SecretSlots is intentionally empty — the token is OAuth-captured.
	if len(c.SecretSlots()) != 0 {
		t.Errorf("SecretSlots = %#v, want none", c.SecretSlots())
	}
}
