package credentials

// notion_oauth: Bearer token in Authorization + Notion-Version header.
//
// Two modes depending on HCL configuration:
//
//   - Simple (no client_id): single token paste via SecretSlots, no refresh.
//   - OAuth (client_id + client_secret set): full auth-code flow via
//     https://api.notion.com/v1/oauth/authorize. Dashboard opens the
//     auth URL, user connects, gateway exchanges + auto-refreshes.
//
// The Notion OAuth app (client_id / client_secret / redirect_uri) is
// gateway config — set it in HCL. Per-user access tokens are stored in
// the OAuth registry keyed by owner, as with every other OAuth credential.
// Multiple Notion apps on one gateway = multiple credential blocks in HCL.

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type NotionOAuth struct {
	ClientID     string `hcl:"client_id,optional"`
	ClientSecret string `hcl:"client_secret,optional"`
	RedirectURI  string `hcl:"redirect_uri,optional"`
}

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
	return []config.SecretSlot{{Label: "Notion OAuth access token", Description: "secret_… integration token or OAuth access_token. Stamped as Authorization: Bearer + Notion-Version header."}}
}

// OAuthFlow returns the Notion OAuth auth-code flow when client_id is
// configured. Returns nil in simple token-paste mode.
func (n *NotionOAuth) OAuthFlow(_ map[string]string) *config.OAuthIntegration {
	if n.ClientID == "" {
		return nil
	}
	redirectURI := n.RedirectURI
	if redirectURI == "" {
		redirectURI = "https://deno.clawpatrol.dev"
	}
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		OAuth: config.OAuthConfig{
			ClientID:     n.ClientID,
			ClientSecret: n.ClientSecret,
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
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*NotionOAuth)
			if v.ClientID != "" {
				b.SetAttributeValue("client_id", cty.StringVal(v.ClientID))
			}
			if v.ClientSecret != "" {
				b.SetAttributeValue("client_secret", cty.StringVal(v.ClientSecret))
			}
			if v.RedirectURI != "" {
				b.SetAttributeValue("redirect_uri", cty.StringVal(v.RedirectURI))
			}
		},
	})
}
