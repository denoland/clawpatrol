package credentials

import "testing"

// TestNotionMCPOAuthUsesLoopbackRedirectURI pins the loopback redirect
// URI on the Notion MCP OAuth flow. Notion rejects non-loopback plain
// HTTP redirects, and the dashboard may run over plain HTTP, so the
// flow must register the localhost callback rather than the dashboard's
// own /oauth/callback page. See notion_mcp_oauth.go for the full
// rationale.
func TestNotionMCPOAuthUsesLoopbackRedirectURI(t *testing.T) {
	flow := (&NotionMCPOAuth{}).OAuthFlow()
	if flow == nil {
		t.Fatal("OAuthFlow() = nil, want non-nil")
	}
	if flow.Flow != "notion_mcp" {
		t.Errorf("Flow = %q, want %q", flow.Flow, "notion_mcp")
	}
	if got, want := flow.OAuth.RedirectURI, "http://localhost:8900/callback"; got != want {
		t.Errorf("OAuth.RedirectURI = %q, want %q", got, want)
	}
}
