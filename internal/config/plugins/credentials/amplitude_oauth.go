package credentials

// amplitude_oauth: OAuth bearer for Amplitude's hosted MCP server.
// The amp CLI reads AMPLITUDE_ACCESS_TOKEN / AMPLITUDE_OAUTH_TOKEN and
// AMPLITUDE_REGION; the gateway rewrites the Authorization header at
// MITM time and refreshes tokens through the OAuth registry.

import (
	"context"
	"net/http"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const (
	amplitudeOAuthScopes      = "mcp:read mcp:write offline_access"
	amplitudeOAuthRedirectURI = "http://localhost:8900/callback"
)

// AmplitudeOAuth is part of the clawpatrol plugin API.
type AmplitudeOAuth struct {
	// Region selects Amplitude's MCP host. Valid values are "us" and
	// "eu". Empty defaults to "us" to match amplitude-cli.
	Region string `hcl:"region,optional"`
}

// InjectHTTP is part of the clawpatrol plugin API.
func (a *AmplitudeOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	return nil
}

// EnvVars is part of the clawpatrol plugin API.
func (a *AmplitudeOAuth) EnvVars() []config.EnvVar {
	region := a.normalizedRegion()
	return []config.EnvVar{
		{Name: "AMPLITUDE_ACCESS_TOKEN", Value: phAmplitude, Description: "Amplitude CLI OAuth access token placeholder"},
		{Name: "AMPLITUDE_OAUTH_TOKEN", Value: phAmplitude, Description: "Amplitude CLI OAuth access token placeholder"},
		{Name: "AMPLITUDE_REGION", Value: region, Description: "Amplitude region for MCP host selection"},
	}
}

// OAuthFlow returns Amplitude MCP's dynamic-client OAuth flow. Amplitude
// only allows insecure redirect URIs for localhost, so we register the
// same loopback callback shape as amplitude-cli. The dashboard falls
// back to copy-pasting the code from the browser URL; the gateway stores
// the issued client_id beside the token so refresh works after restart.
func (a *AmplitudeOAuth) OAuthFlow() *config.OAuthIntegration {
	base := amplitudeMCPBaseURL(a.normalizedRegion())
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		Flow:   "dynamic_mcp",
		OAuth: config.OAuthConfig{
			AuthURL:     base + "/authorize",
			TokenURL:    base + "/token",
			RegisterURL: base + "/register",
			RedirectURI: amplitudeOAuthRedirectURI,
			Scopes:      strings.Fields(amplitudeOAuthScopes),
		},
	}
}

func (a *AmplitudeOAuth) normalizedRegion() string {
	switch strings.ToLower(strings.TrimSpace(a.Region)) {
	case "eu":
		return "eu"
	default:
		return "us"
	}
}

func amplitudeMCPBaseURL(region string) string {
	if strings.EqualFold(region, "eu") {
		return "https://mcp.eu.amplitude.com"
	}
	return "https://mcp.amplitude.com"
}

func buildAmplitudeOAuth(decoded any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	a := decoded.(*AmplitudeOAuth)
	a.Region = strings.ToLower(strings.TrimSpace(a.Region))
	if a.Region == "" {
		a.Region = "us"
	}
	if a.Region != "us" && a.Region != "eu" {
		return a, hcl.Diagnostics{&hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid Amplitude region",
			Detail:   `region must be "us" or "eu"`,
		}}
	}
	return a, nil
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*AmplitudeOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "amplitude_oauth",
		Disambiguators: []string{"placeholder"},
		New:            newer[AmplitudeOAuth](),
		Runtime:        (*AmplitudeOAuth)(nil),
		Build:          buildAmplitudeOAuth,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			v := body.(*AmplitudeOAuth)
			if v.Region != "" && v.Region != "us" {
				b.SetAttributeValue("region", cty.StringVal(v.Region))
			}
		},
	})
}
