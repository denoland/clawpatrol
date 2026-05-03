package config

// OAuthConfig is the per-provider OAuth client config — auth/token URLs,
// scopes, and the bootstrap refresh token. Per-owner access tokens are
// persisted by the gateway's OAuthRegistry and refresh through the
// usual oauth2.TokenSource path; this struct only carries the static
// flow definition that doesn't change per user.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	DeviceURL    string // used by Flow="device"
	RedirectURI  string
	Scopes       []string
	RefreshToken string // bootstrap; per-owner tokens override
}

// OAuthIntegration packages an OAuthConfig with the header shape the
// runtime uses to inject the resulting access token. Owned by the
// credential plugin that ships the provider — anthropic_oauth_subscription
// returns the Anthropic flow, github_oauth returns the gh device flow,
// etc. The host's OAuthRegistry registers these by credential bare name
// at policy load.
type OAuthIntegration struct {
	ID     string
	Type   string
	Header string
	Prefix string
	Flow   string // "auth_code" (default) | "device"
	OAuth  OAuthConfig
}

// OAuthFlowProvider is the optional interface a credential plugin's
// decoded body implements when it represents an OAuth-flow credential.
// registerOAuthCredentials walks every loaded credential, type-asserts
// to this, and registers the returned flow under the credential's
// bare name.
//
// Drop-in for adding a new OAuth provider: ship a credential plugin
// type whose body implements OAuthFlow() and you're done — no host
// changes, no auxiliary maps to update.
type OAuthFlowProvider interface {
	OAuthFlow() *OAuthIntegration
}
