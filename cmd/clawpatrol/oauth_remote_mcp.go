package main

// Generic, strict OAuth for remote MCP servers (Flow="remote_mcp_oauth").
//
// Unlike notion_mcp / dynamic_mcp — which hard-code a provider's
// authorize/token/register URLs — this flow discovers everything from
// the bound remote_mcp endpoint's resource URL at connect time:
//
//  1. RFC 9728 Protected Resource Metadata  → the authorization server(s)
//  2. RFC 8414 Authorization Server Metadata → authorize/token/register
//  3. RFC 7591 dynamic client registration   → a PKCE public client_id
//  4. RFC 7636 PKCE + RFC 8707 resource       → the authorization URL
//
// Strictness (no provider_compat shims in this release):
//   - exactly one authorization server may be advertised (no ambiguity),
//   - the AS metadata `issuer` must match the advertised issuer exactly,
//   - the authorize/token/registration endpoints must live on the
//     issuer's own origin — an AS document cannot point the token
//     endpoint at a foreign host (endpoint-substitution guard).
//
// The discovered, non-secret metadata (issuer + endpoints + resource +
// client_id) is persisted in gateway_blobs so refresh after a restart
// uses the same validated token endpoint without re-running discovery
// against a resource server that may since have been tampered with.
// Tokens are never written here — they flow through OAuthRegistry and
// the credentials table like every other OAuth credential.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// remoteMCPMetaBlobKind is the gateway_blobs namespace for persisted
// remote_mcp_oauth discovery + DCR metadata. Rows are keyed by the
// credential's bare name.
const remoteMCPMetaBlobKind = "remote_mcp_oauth_meta"

// remoteMCPMeta is the non-secret discovery + registration result we
// persist per credential. No token material is ever stored here.
type remoteMCPMeta struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint,omitempty"`
	Resource              string   `json:"resource"`
	ClientID              string   `json:"client_id,omitempty"`
	RedirectURI           string   `json:"redirect_uri,omitempty"`
	Scopes                []string `json:"scopes,omitempty"`
}

// protectedResourceMetadata is the RFC 9728 document subset we read.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// authServerMetadata is the RFC 8414 / OIDC discovery subset we read.
type authServerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

// oauthHTTPClient returns the base HTTP client used for OAuth discovery
// and dynamic client registration. Tests set w.httpClient to an
// httptest TLS server's client (which trusts the test cert); production
// uses the shared default client.
func (w *webMux) oauthHTTPClient() *http.Client {
	if w != nil && w.httpClient != nil {
		return w.httpClient
	}
	return http.DefaultClient
}

// noRedirectOAuthHTTPClient clones base and disables redirect following.
// remote_mcp_oauth validates discovered endpoints before use; following a
// provider-controlled redirect would bypass that validation and can leak
// authorization codes, PKCE verifiers, DCR payloads, refresh tokens, or
// enable SSRF. Returning http.ErrUseLastResponse makes callers see the
// 3xx response as a normal non-OK/non-2xx failure without replaying the
// request to the Location target.
func noRedirectOAuthHTTPClient(base *http.Client) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	clone := *base
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

// startRemoteMCPOAuthFlow drives the strict generic remote MCP OAuth
// flow: discover, (re)register a client, persist metadata, and return a
// PKCE authorization URL carrying the resource indicator. The token
// exchange reuses the shared apiOAuthExchange path (the session carries
// the discovered token endpoint, client_id, and resource).
func (w *webMux) startRemoteMCPOAuthFlow(rw http.ResponseWriter, r *http.Request, id string, flow *OAuthIntegration) {
	resourceURL := strings.TrimSpace(flow.OAuth.ResourceURL)
	if resourceURL == "" {
		http.Error(rw, "remote_mcp_oauth: no resource url — bind a remote_mcp endpoint (endpoint = remote_mcp.<name>) or set resource_url", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), oauthUpstreamTimeout)
	defer cancel()

	client := noRedirectOAuthHTTPClient(w.oauthHTTPClient())
	meta, err := discoverRemoteMCPMeta(ctx, client, resourceURL, flow.OAuth.Scopes)
	if err != nil {
		http.Error(rw, "remote_mcp_oauth discovery: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Reuse a previously registered client_id only when the discovered
	// authorization server is unchanged — if the resource server now
	// points at a different issuer or token endpoint, re-register so a
	// rotated/hijacked AS cannot ride a stale client registration.
	clientID := ""
	redirectURI := w.dashboardRedirectURI(r, "/oauth/callback")
	if prior, ok := loadRemoteMCPMeta(w.g.blobs, id); ok &&
		prior.ClientID != "" &&
		issuerEqual(prior.Issuer, meta.Issuer) &&
		prior.TokenEndpoint == meta.TokenEndpoint &&
		prior.RedirectURI == redirectURI &&
		stringSlicesEqual(prior.Scopes, flow.OAuth.Scopes) {
		clientID = prior.ClientID
	}
	if clientID == "" {
		if meta.RegistrationEndpoint == "" {
			http.Error(rw, "remote_mcp_oauth: provider requires a client_id but advertises no registration_endpoint", http.StatusBadGateway)
			return
		}
		clientID, err = registerOAuthClientClient(ctx, client, meta.RegistrationEndpoint, redirectURI, flow.OAuth.Scopes)
		if err != nil {
			http.Error(rw, "remote_mcp_oauth dynamic client registration: "+err.Error(), http.StatusBadGateway)
			return
		}
	}
	meta.ClientID = clientID
	meta.RedirectURI = redirectURI

	verifier := randomString(64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomString(32)
	cfg := &oauth2.Config{
		ClientID:    clientID,
		Scopes:      flow.OAuth.Scopes,
		RedirectURL: redirectURI,
		Endpoint: oauth2.Endpoint{
			AuthURL:   meta.AuthorizationEndpoint,
			TokenURL:  meta.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	authURL := cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("resource", meta.Resource),
	)

	w.mu.Lock()
	w.sessions[state] = &oauthSession{
		verifier:    verifier,
		state:       state,
		cfg:         cfg,
		id:          id,
		created:     time.Now(),
		dynClientID: clientID,
		resource:    meta.Resource,
		httpClient:  client,
		remoteMCPMeta: &remoteMCPMeta{
			Issuer:                meta.Issuer,
			AuthorizationEndpoint: meta.AuthorizationEndpoint,
			TokenEndpoint:         meta.TokenEndpoint,
			RegistrationEndpoint:  meta.RegistrationEndpoint,
			Resource:              meta.Resource,
			ClientID:              meta.ClientID,
			RedirectURI:           meta.RedirectURI,
			Scopes:                append([]string(nil), meta.Scopes...),
		},
	}
	for k, s := range w.sessions {
		if time.Since(s.created) > 10*time.Minute {
			delete(w.sessions, k)
		}
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]string{"auth_url": authURL, "state": state})
}

// discoverRemoteMCPMeta runs strict RFC 9728 → RFC 8414 discovery from a
// resource URL and returns the validated, non-secret metadata (without a
// client_id). Every deviation from the specs is a hard error.
func discoverRemoteMCPMeta(ctx context.Context, client *http.Client, resourceURL string, scopes []string) (remoteMCPMeta, error) {
	var meta remoteMCPMeta
	ru, err := url.Parse(strings.TrimSpace(resourceURL))
	if err != nil || ru.Scheme != "https" || ru.Host == "" {
		return meta, fmt.Errorf("resource url %q must be an absolute https url", resourceURL)
	}

	prm, err := fetchProtectedResourceMetadata(ctx, client, ru)
	if err != nil {
		return meta, err
	}
	switch len(prm.AuthorizationServers) {
	case 1:
	case 0:
		return meta, fmt.Errorf("protected resource metadata advertises no authorization_servers")
	default:
		return meta, fmt.Errorf("protected resource metadata advertises %d authorization servers; strict mode requires exactly one", len(prm.AuthorizationServers))
	}
	issuer := strings.TrimSpace(prm.AuthorizationServers[0])
	if issuer == "" {
		return meta, fmt.Errorf("protected resource metadata authorization_servers[0] is empty")
	}

	// Canonical resource for the RFC 8707 indicator: the metadata's own
	// `resource` value when present (it is authoritative), else the
	// configured URL. A declared resource must match the configured
	// resource exactly enough that path/query tenant boundaries cannot be
	// crossed by a malicious resource server.
	resource := strings.TrimSpace(prm.Resource)
	if resource == "" {
		resource = canonicalResourceURL(ru)
	} else if !sameResource(resource, resourceURL) {
		return meta, fmt.Errorf("protected resource metadata resource %q does not match the configured resource %q", resource, resourceURL)
	}

	asm, err := fetchAuthServerMetadata(ctx, client, issuer)
	if err != nil {
		return meta, err
	}
	if !issuerEqual(asm.Issuer, issuer) {
		return meta, fmt.Errorf("authorization server issuer mismatch: metadata issuer %q != advertised issuer %q", asm.Issuer, issuer)
	}
	if asm.AuthorizationEndpoint == "" || asm.TokenEndpoint == "" {
		return meta, fmt.Errorf("authorization server metadata is missing authorization_endpoint or token_endpoint")
	}
	// Endpoint-substitution guard: every endpoint must be https and on
	// the issuer's own origin. This is what blocks an AS document from
	// redirecting the token endpoint (and thus the refresh token) to an
	// attacker-controlled host.
	for _, ep := range []struct{ name, val string }{
		{"authorization_endpoint", asm.AuthorizationEndpoint},
		{"token_endpoint", asm.TokenEndpoint},
	} {
		if err := requireIssuerOrigin(ep.name, ep.val, issuer); err != nil {
			return meta, err
		}
	}
	if asm.RegistrationEndpoint != "" {
		if err := requireIssuerOrigin("registration_endpoint", asm.RegistrationEndpoint, issuer); err != nil {
			return meta, err
		}
	}

	return remoteMCPMeta{
		Issuer:                strings.TrimRight(issuer, "/"),
		AuthorizationEndpoint: asm.AuthorizationEndpoint,
		TokenEndpoint:         asm.TokenEndpoint,
		RegistrationEndpoint:  asm.RegistrationEndpoint,
		Resource:              resource,
		Scopes:                append([]string(nil), scopes...),
	}, nil
}

// fetchProtectedResourceMetadata fetches the RFC 9728 document. The
// well-known path is constructed by inserting the well-known suffix
// between host and path; the path-less form is tried as a fallback for
// servers that serve metadata at the host root.
func fetchProtectedResourceMetadata(ctx context.Context, client *http.Client, ru *url.URL) (protectedResourceMetadata, error) {
	base := ru.Scheme + "://" + ru.Host
	var candidates []string
	if p := strings.Trim(ru.Path, "/"); p != "" {
		candidates = append(candidates, base+"/.well-known/oauth-protected-resource/"+p)
	}
	candidates = append(candidates, base+"/.well-known/oauth-protected-resource")

	var lastErr error
	for _, c := range candidates {
		var doc protectedResourceMetadata
		if err := getOAuthJSON(ctx, client, c, &doc); err != nil {
			lastErr = err
			continue
		}
		return doc, nil
	}
	return protectedResourceMetadata{}, fmt.Errorf("protected resource metadata discovery failed: %w", lastErr)
}

// fetchAuthServerMetadata fetches RFC 8414 (oauth-authorization-server)
// then OIDC (openid-configuration) discovery documents for an issuer,
// trying the spec's path-aware constructions in order.
func fetchAuthServerMetadata(ctx context.Context, client *http.Client, issuer string) (authServerMetadata, error) {
	iu, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil || iu.Scheme != "https" || iu.Host == "" {
		return authServerMetadata{}, fmt.Errorf("authorization server issuer %q must be an absolute https url", issuer)
	}
	base := iu.Scheme + "://" + iu.Host
	var candidates []string
	if p := strings.Trim(iu.Path, "/"); p != "" {
		candidates = append(candidates,
			base+"/.well-known/oauth-authorization-server/"+p,
			base+"/"+p+"/.well-known/openid-configuration",
			base+"/.well-known/openid-configuration/"+p,
		)
	} else {
		candidates = append(candidates,
			base+"/.well-known/oauth-authorization-server",
			base+"/.well-known/openid-configuration",
		)
	}

	var lastErr error
	for _, c := range candidates {
		var doc authServerMetadata
		if err := getOAuthJSON(ctx, client, c, &doc); err != nil {
			lastErr = err
			continue
		}
		return doc, nil
	}
	return authServerMetadata{}, fmt.Errorf("authorization server metadata discovery failed: %w", lastErr)
}

// getOAuthJSON GETs a small JSON document into out, bounding the body
// size and treating any non-200 as an error.
func getOAuthJSON(ctx context.Context, client *http.Client, urlStr string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", urlStr, resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("GET %s: decode metadata: %w", urlStr, err)
	}
	return nil
}

// requireIssuerOrigin rejects an endpoint that is not an https URL on
// the issuer's exact origin (scheme + host + port).
func requireIssuerOrigin(name, endpoint, issuer string) error {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s %q must be an absolute https url", name, endpoint)
	}
	if !sameOrigin(endpoint, issuer) {
		return fmt.Errorf("%s %q is not on the issuer origin %q (possible endpoint substitution)", name, endpoint, issuer)
	}
	return nil
}

// sameOrigin reports whether two URLs share scheme and host (incl. port),
// case-insensitively. Path/query are ignored.
func sameOrigin(a, b string) bool {
	ua, err := url.Parse(strings.TrimSpace(a))
	if err != nil {
		return false
	}
	ub, err := url.Parse(strings.TrimSpace(b))
	if err != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

func sameResource(a, b string) bool {
	ua, err := url.Parse(strings.TrimSpace(a))
	if err != nil {
		return false
	}
	ub, err := url.Parse(strings.TrimSpace(b))
	if err != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Host, ub.Host) &&
		ua.EscapedPath() == ub.EscapedPath() &&
		ua.RawQuery == ub.RawQuery
}

func canonicalResourceURL(u *url.URL) string {
	resource := u.Scheme + "://" + u.Host + u.EscapedPath()
	if u.RawQuery != "" {
		resource += "?" + u.RawQuery
	}
	return resource
}

// issuerEqual compares two issuer identifiers, tolerating a single
// trailing slash difference (RFC 8414 issuers carry no path component
// for most providers, but some include one).
func issuerEqual(a, b string) bool {
	return strings.TrimRight(strings.TrimSpace(a), "/") == strings.TrimRight(strings.TrimSpace(b), "/")
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// loadRemoteMCPMeta reads persisted discovery metadata for a credential.
func loadRemoteMCPMeta(blobs runtime.BlobStore, id string) (remoteMCPMeta, bool) {
	var m remoteMCPMeta
	if blobs == nil {
		return m, false
	}
	b, ok, err := blobs.Get(remoteMCPMetaBlobKind, id)
	if err != nil || !ok {
		return m, false
	}
	if json.Unmarshal(b, &m) != nil {
		return remoteMCPMeta{}, false
	}
	return m, true
}

// saveRemoteMCPMeta persists non-secret discovery metadata for a
// credential. No-op when no blob store is wired (tests without a db).
func saveRemoteMCPMeta(blobs runtime.BlobStore, id string, m remoteMCPMeta) error {
	if blobs == nil {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return blobs.Put(remoteMCPMetaBlobKind, id, b)
}

// boundRemoteMCPURL returns the URL of the remote_mcp endpoint a
// credential binds, or "" when it binds no remote_mcp endpoint. Used to
// drive discovery from the endpoint the operator already declared,
// without duplicating the URL on the credential.
func boundRemoteMCPURL(policy *config.CompiledPolicy, ent *config.Entity) string {
	if policy == nil || ent == nil {
		return ""
	}
	epName := ent.Framework.Ref("endpoint")
	if epName == "" {
		return ""
	}
	ep := policy.Endpoints[epName]
	if ep == nil {
		return ""
	}
	if u, ok := ep.Body.(interface{ RemoteMCPURL() string }); ok {
		return u.RemoteMCPURL()
	}
	return ""
}
