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
	// OptionalScopes is the catalog of opt-in scopes the dashboard
	// shows as a checklist before kicking off the OAuth flow. Plugins
	// that don't surface a picker leave this empty; the connect modal
	// then goes straight to the OAuth start without a picker step.
	OptionalScopes []OptionalScopeGroup
}

// OptionalScopeGroup is one section of the connect-time scope picker
// (e.g. "ssh keys", "packages"). Each group holds zero or more
// OptionalScope rows that the user can individually toggle on top of
// OAuthConfig.Scopes.
type OptionalScopeGroup struct {
	Title  string          `json:"title"`
	Scopes []OptionalScope `json:"scopes"`
}

// OptionalScope is one toggleable scope in the picker. ID is the
// literal scope value sent to the IdP (e.g. "admin:public_key");
// Label is a short human description rendered next to the checkbox.
type OptionalScope struct {
	ID    string `json:"id"`
	Label string `json:"label"`
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

// OAuthProfileFetcher is the optional interface an OAuth-flow
// credential plugin's body implements when it knows how to enrich a
// freshly-issued access token with the connected account's identity
// (display name + avatar). The host calls this once at exchange time
// and persists the result on the credentials row; the dashboard
// surfaces the display name as the card subtitle so two same-type
// OAuth credentials can be told apart at a glance.
//
// Plugins that don't implement this leave the identity empty — the
// dashboard then shows no subtitle (the green dot + status text still
// indicate the connection state). Implementations should be
// best-effort: a failed userinfo fetch returns ("", "") rather than
// surfacing an error to the connect flow.
type OAuthProfileFetcher interface {
	FetchOAuthProfile(accessToken string) (displayName, avatarURL string)
}
