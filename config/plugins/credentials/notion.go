package credentials

// notion_oauth: Bearer token in Authorization + Notion-Version header.
//
// Two modes depending on HCL configuration:
//
//   - Simple (no client_id): single token paste via SecretSlots, no refresh.
//   - OAuth (client_id set): full auth-code flow via
//     https://api.notion.com/v1/oauth/authorize. Dashboard opens the
//     auth URL, user pastes the code, gateway exchanges + auto-refreshes.
//
// client_secret is NOT stored in HCL — it is an operator secret kept in the
// credential_secrets table (credential=<name>, profile="", slot="client_secret").
// Multiple notion_oauth credentials in one gateway each carry their own secret,
// injected via the extras map at OAuth-flow time.

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type NotionOAuth struct {
	ClientID    string `hcl:"client_id,optional"`
	RedirectURI string `hcl:"redirect_uri,optional"`
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
// configured. Returns nil when operating in simple token-paste mode.
// extras["client_secret"] must be set via the credential_secrets table
// (profile="") — it is intentionally absent from the HCL struct so
// separate notion_oauth credentials on the same gateway each carry
// independent secrets.
func (n *NotionOAuth) OAuthFlow(extras map[string]string) *config.OAuthIntegration {
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
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*NotionOAuth)
			if v.ClientID != "" {
				b.SetAttributeValue("client_id", cty.StringVal(v.ClientID))
			}
			if v.RedirectURI != "" {
				b.SetAttributeValue("redirect_uri", cty.StringVal(v.RedirectURI))
			}
		},
	})
}
