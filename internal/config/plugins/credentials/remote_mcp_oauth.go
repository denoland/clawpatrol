package credentials

// remote_mcp_oauth: a strict, generic OAuth credential for remote MCP
// servers that ship standards-conformant authorization metadata
// (RFC 9728 Protected Resource Metadata + RFC 8414 Authorization
// Server Metadata, RFC 7591 dynamic client registration, RFC 7636 PKCE,
// RFC 8707 resource indicators).
//
// It binds exactly one `remote_mcp` endpoint and discovers everything
// else — issuer, authorization/token/registration endpoints, client_id
// — from the bound resource URL at connect time. No per-provider shims
// live here: providers that deviate from the specs (e.g. issuer
// mismatch) are intentionally rejected, and the deferred `provider_compat`
// follow-up is where such relaxations will land.

import (
	"context"
	"net/http"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// RemoteMCPOAuth is part of the clawpatrol plugin API.
type RemoteMCPOAuth struct {
	// Scopes are sent both during dynamic client registration and the
	// authorization request. Empty lets the provider choose defaults.
	Scopes []string `hcl:"scopes,optional"`
	// ResourceURL is reserved for a follow-up that can safely canonicalize
	// an alternate Protected Resource Metadata URL against the bound
	// remote_mcp endpoint. The strict generic credential rejects non-empty
	// values today so tokens cannot be minted for one resource and injected
	// into another.
	ResourceURL string `hcl:"resource_url,optional"`
	// ProviderCompat is reserved for a follow-up of provider-specific
	// compatibility shims. The strict generic credential rejects any
	// non-empty value today (see validateRemoteMCPOAuth).
	ProviderCompat string `hcl:"provider_compat,optional"`
}

// InjectHTTP is part of the clawpatrol plugin API. It stamps the OAuth
// access token (captured by the flow, refreshed by the registry) as a
// bearer on the bound request only — the dispatcher resolves this
// credential per (profile, endpoint, request), so the header never
// leaks onto unrelated traffic.
func (r *RemoteMCPOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	return nil
}

// SecretSlots intentionally returns nothing: the token is captured
// through the OAuth flow, never pasted by the operator.
func (*RemoteMCPOAuth) SecretSlots() []config.SecretSlot { return nil }

// OAuthFlow returns the marker flow. The host enriches OAuth.ResourceURL
// from the bound remote_mcp endpoint (when the operator omits the
// override) and discovers the auth/token/registration endpoints from it
// before starting the flow — see cmd/clawpatrol/oauth_remote_mcp.go.
func (r *RemoteMCPOAuth) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		Flow:   "remote_mcp_oauth",
		OAuth: config.OAuthConfig{
			Scopes:      append([]string(nil), r.Scopes...),
			ResourceURL: r.ResourceURL,
		},
	}
}

// validateRemoteMCPOAuth rejects any non-empty provider_compat value.
// The binding to exactly one remote_mcp endpoint is enforced by the
// loader's validateCredentialBindings (it needs the resolved endpoint
// table, which a per-plugin Validate doesn't have).
func validateRemoteMCPOAuth(d any, _ string, ctx *config.BuildCtx) hcl.Diagnostics {
	c := d.(*RemoteMCPOAuth)
	var diags hcl.Diagnostics
	if c.ResourceURL != "" {
		r := ctx.Block.DefRange
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Unsupported resource_url on remote_mcp_oauth credential",
			Detail:   "remote_mcp_oauth discovers OAuth metadata from its bound remote_mcp endpoint in this release. A separate resource_url override could mint tokens for one resource and inject them into another, so it is reserved for a future canonicalized compatibility change.",
			Subject:  &r,
		})
	}
	if c.ProviderCompat != "" {
		r := ctx.Block.DefRange
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Unsupported provider_compat on remote_mcp_oauth credential",
			Detail:   "remote_mcp_oauth is strict and generic in this release; provider-specific compatibility (for example Grain issuer-mismatch handling) belongs in a follow-up provider_compat change.",
			Subject:  &r,
		})
	}
	return diags
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*RemoteMCPOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "remote_mcp_oauth",
		Disambiguators: []string{"placeholder"},
		New:            newer[RemoteMCPOAuth](),
		Runtime:        (*RemoteMCPOAuth)(nil),
		Validate:       validateRemoteMCPOAuth,
		Build:          passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*RemoteMCPOAuth)
			if len(v.Scopes) > 0 {
				b.SetAttributeValue("scopes", config.StringListVal(v.Scopes))
			}
			if v.ResourceURL != "" {
				b.SetAttributeValue("resource_url", cty.StringVal(v.ResourceURL))
			}
			if v.ProviderCompat != "" {
				b.SetAttributeValue("provider_compat", cty.StringVal(v.ProviderCompat))
			}
		},
	})
}
