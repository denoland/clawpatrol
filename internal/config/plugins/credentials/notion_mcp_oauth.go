package credentials

// notion_mcp_oauth: OAuth flow against mcp.notion.com (Notion's hosted
// MCP server). Uses RFC 7591 dynamic client registration so no Notion-
// side integration setup is required — the dashboard registers a client
// on the fly when the user clicks "Connect", and persists the per-
// credential client_id alongside the tokens (see migration 0013).
//
// The resulting bearer is scoped to mcp.notion.com only. For
// api.notion.com (the regular Notion REST API), use notion_oauth and
// paste a manual integration token.

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// NotionMCPOAuth is part of the clawpatrol plugin API.
type NotionMCPOAuth struct{}

// InjectHTTP is part of the clawpatrol plugin API.
func (n *NotionMCPOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	return nil
}

// SecretSlots intentionally returns nothing: the token is captured
// through the OAuth flow, never pasted by the operator.
func (*NotionMCPOAuth) SecretSlots() []config.SecretSlot { return nil }

// OAuthFlow returns Notion's MCP OAuth flow. ClientID is intentionally
// empty — the dashboard registers one at connect time (Flow="notion_mcp"
// branch in oauth.go) and persists it per-credential.
func (n *NotionMCPOAuth) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		Flow:   "notion_mcp",
		OAuth: config.OAuthConfig{
			AuthURL:     "https://mcp.notion.com/authorize",
			TokenURL:    "https://mcp.notion.com/token",
			RegisterURL: "https://mcp.notion.com/register",
		},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*NotionMCPOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "notion_mcp_oauth",
		New:     newer[NotionMCPOAuth](),
		Runtime: (*NotionMCPOAuth)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
