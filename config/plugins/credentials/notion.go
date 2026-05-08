package credentials

// notion_oauth: Bearer token in Authorization + Notion-Version header.
//
// Two modes, controlled entirely through the dashboard (no HCL config):
//
//   - Simple (client_id slot not set): operator pastes an integration token
//     via SecretSlots; gateway stamps Authorization: Bearer + Notion-Version.
//   - OAuth (client_id + client_secret slots set): full auth-code flow via
//     https://api.notion.com/v1/oauth/authorize. Dashboard operator sets the
//     Notion OAuth app credentials once per profile; users connect via the
//     dashboard OAuth button. All three client credentials are stored in
//     credential_secrets (credential, profile, slot) — one row per slot,
//     one profile per tenant, readable only via the dashboard secret API.

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type NotionOAuth struct{}

func (n *NotionOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	if req.Header.Get("Notion-Version") == "" {
		req.Header.Set("Notion-Version", "2022-06-28")
	}
	return nil
}

func (*NotionOAuth) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Label: "Notion OAuth access token", Description: "secret_… integration token or OAuth access_token. Used in simple (non-OAuth-app) mode."},
		{Name: "client_id", Label: "OAuth app client ID", Description: "From your Notion integration's OAuth credentials page. Required for the OAuth connect flow."},
		{Name: "client_secret", Label: "OAuth app client secret", Description: "From your Notion integration's OAuth credentials page."},
		{Name: "redirect_uri", Label: "Redirect URI", Description: "Must match the redirect URI registered in your Notion integration. Defaults to the gateway public URL."},
	}
}

// OAuthFlow returns the Notion OAuth auth-code flow when extras["client_id"]
// is set (i.e. the operator has configured the Notion OAuth app credentials
// via the dashboard for this profile). Returns nil in simple token-paste mode.
func (n *NotionOAuth) OAuthFlow(extras map[string]string) *config.OAuthIntegration {
	clientID := extras["client_id"]
	if clientID == "" {
		return nil
	}
	redirectURI := extras["redirect_uri"]
	if redirectURI == "" {
		redirectURI = "https://deno.clawpatrol.dev"
	}
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		OAuth: config.OAuthConfig{
			ClientID:     clientID,
			ClientSecret: extras["client_secret"],
			AuthURL:      "https://api.notion.com/v1/oauth/authorize",
			TokenURL:     "https://mcp.notion.com/token",
			RedirectURI:  redirectURI,
		},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*NotionOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "notion_oauth",
		New:     newer[NotionOAuth](),
		Runtime: (*NotionOAuth)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
