package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/denoland/clawpatrol/internal/config"
)

const ScopeUser = "user"

// oauthResponseLimit caps every io.ReadAll on an OAuth provider's
// response body. Token / device-code / userinfo replies are tiny JSON
// blobs (a few hundred bytes); 64 KiB is generous enough to absorb
// unexpectedly large error payloads from misbehaving providers
// without letting a hostile or malfunctioning endpoint balloon
// process memory on every flow attempt.
const oauthResponseLimit = 64 << 10

// oauthUpstreamTimeout bounds every outbound call we make to a
// third-party OAuth endpoint (token, device-code, refresh). Without
// this, a wedged provider would tie up the dashboard handler — and
// the registry mutex, in the refresh-source case — until the client
// disconnects.
const oauthUpstreamTimeout = 30 * time.Second

// OAuthConfig + OAuthIntegration moved to config/oauth.go so credential
// plugins can ship their own OAuth flow data without import cycles.
// Aliased here so existing call sites in this package don't churn.
type (
	OAuthConfig      = config.OAuthConfig
	OAuthIntegration = config.OAuthIntegration
)

// oauthState is one credential: tokens for a single integration.
// Persisted in the credentials table; one row per id.
type oauthState struct {
	cfg         *oauth2.Config
	source      oauth2.TokenSource
	header      string
	prefix      string
	id          string
	displayName string // human-readable name (e.g. github login)
	avatarURL   string // dashboard pfp
	// clientID is the dynamically-registered OAuth client_id for flows
	// that use RFC 7591 (notion_mcp). Static-ClientID flows (github,
	// anthropic, codex) leave this empty and use cfg.ClientID. Persisted
	// in the credentials table alongside the tokens so refresh works
	// across gateway restarts.
	clientID string
	db       *sql.DB
	mu       sync.Mutex
}

// OAuthRegistry holds all configured OAuth integrations and one token
// state per integration. Keyed by integration_id.
type OAuthRegistry struct {
	mu           sync.RWMutex
	integrations map[string]*OAuthIntegration
	states       map[string]*oauthState // key: id
	db           *sql.DB
}

func NewOAuthRegistry(items []OAuthIntegration, db *sql.DB) (*OAuthRegistry, error) {
	r := &OAuthRegistry{
		integrations: map[string]*OAuthIntegration{},
		states:       map[string]*oauthState{},
		db:           db,
	}
	for i := range items {
		r.integrations[items[i].ID] = &items[i]
	}
	if err := r.loadFromDB(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *OAuthRegistry) Integration(id string) *OAuthIntegration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.integrations[id]
}

func (r *OAuthRegistry) IntegrationIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.integrations))
	for id := range r.integrations {
		ids = append(ids, id)
	}
	return ids
}

func (r *OAuthRegistry) get(id string) *oauthState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.states[id]
}

// Inject sets the auth header on req using the named credential.
// Returns (overrode, err). overrode=false means no token yet; caller
// may pass agent's existing header through, or fail.
func (r *OAuthRegistry) Inject(id string, req *http.Request) (bool, error) {
	if id == "" {
		return false, nil
	}
	s := r.get(id)
	if s == nil || s.source == nil {
		return false, nil
	}
	t, err := s.source.Token()
	if err != nil {
		return false, fmt.Errorf("oauth %q: token: %w", id, err)
	}
	req.Header.Set(s.header, s.prefix+t.AccessToken)
	return true, nil
}

// Token returns the current access token for the credential —
// refreshing it through the underlying oauth2.TokenSource if it's
// stale. Empty string + nil error means no token has been captured
// yet; the caller decides between fail-closed and pass-through.
//
// Used by the runtime SecretStore bridge so credential plugins
// (which know how to format Authorization / x-api-key / cookie)
// can stamp the bytes onto the request — OAuthRegistry.Inject
// hardcodes the header shape and predates the per-credential plugin
// model.
func (r *OAuthRegistry) Token(id string) (string, error) {
	if id == "" {
		return "", nil
	}
	s := r.get(id)
	if s == nil || s.source == nil {
		return "", nil
	}
	t, err := s.source.Token()
	if err != nil {
		return "", fmt.Errorf("oauth %q: token: %w", id, err)
	}
	return t.AccessToken, nil
}

// Register adds an OAuth integration definition at runtime. Used at
// gateway boot to register OAuth-flow credentials from the new
// policy under their bare-name as the ID. Idempotent: re-registering
// the same ID with an identical definition is a no-op; replacing one
// with a different definition overwrites.
func (r *OAuthRegistry) Register(id string, def OAuthIntegration) {
	if id == "" {
		return
	}
	def.ID = id
	r.mu.Lock()
	defer r.mu.Unlock()
	r.integrations[id] = &def
}

// Status returns connected info for the named credential.
func (r *OAuthRegistry) Status(id string) (connected bool, expiry time.Time) {
	s := r.get(id)
	if s == nil || s.source == nil {
		return false, time.Time{}
	}
	t, err := s.source.Token()
	if err != nil || t.AccessToken == "" {
		return false, time.Time{}
	}
	return true, t.Expiry
}

// Profile returns the (display_name, avatar_url) the dashboard
// renders for this credential. Empty strings when no userinfo
// enricher ran for this provider, when the row pre-dates
// 0003_credential_profile, or when the userinfo fetch failed at
// exchange time.
func (r *OAuthRegistry) Profile(id string) (displayName, avatarURL string) {
	s := r.get(id)
	if s == nil {
		return "", ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.displayName, s.avatarURL
}

// Revoke deletes the credential's token and its DB row.
func (r *OAuthRegistry) Revoke(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.states[id]; !ok {
		return
	}
	if r.db != nil {
		_, _ = r.db.Exec("DELETE FROM credentials WHERE id=?", id)
	}
	delete(r.states, id)
}

// Set stores tokens captured externally (browser auth flow callback).
func (r *OAuthRegistry) Set(ctx context.Context, id string, tok *oauth2.Token) error {
	return r.SetWithClient(ctx, id, tok, "")
}

// SetWithClient is Set + a dynamically registered client_id. Pass empty
// clientID for static-ClientID flows; pass the per-credential client_id
// for RFC 7591 dynamic registration flows (notion_mcp). The clientID is
// stamped onto the in-memory state and persisted alongside the tokens so
// refresh continues to work after restart.
//
// The userinfo fetch (fetchOAuthProfile) runs OUTSIDE the registry lock
// so a slow/hung provider can't block other OAuth operations (Status,
// Inject, Revoke) for the duration of the round-trip.
func (r *OAuthRegistry) SetWithClient(ctx context.Context, id string, tok *oauth2.Token, clientID string) error {
	r.mu.Lock()
	it, ok := r.integrations[id]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("oauth registry: unknown integration: %s", id)
	}
	s := r.states[id]
	if s == nil {
		s = newState(it, r.db)
		r.states[id] = s
	}
	if clientID != "" {
		s.clientID = clientID
		s.cfg.ClientID = clientID
	}
	s.setToken(tok)
	r.mu.Unlock()

	// Network call is best-effort and decorative; failure is logged
	// inside fetchOAuthProfile and the credential row stays usable
	// without display_name/avatar_url populated.
	name, avatar := fetchOAuthProfile(ctx, id, tok.AccessToken)
	if name != "" || avatar != "" {
		s.persistProfile(name, avatar)
	}
	return nil
}

// OAuthProfile holds the human-identity bits we surface on the
// dashboard (real name + avatar). Populated after a successful token
// exchange by hitting the provider's userinfo endpoint.
type OAuthProfile struct {
	DisplayName string
	AvatarURL   string
}

// oauthProfileFetchTimeout caps each fetchOAuthProfile call so a
// hung userinfo endpoint can't stall the OAuth callback handler that
// triggered it. The dashboard treats missing profile bits as
// "decorate later"; a couple of seconds is enough for healthy
// providers without making the user wait on a wedged one.
const oauthProfileFetchTimeout = 5 * time.Second

// fetchOAuthProfile returns the (display_name, avatar_url) for a
// freshly-issued token. Per-provider — `github` hits api.github.com/
// user; others currently return empty until their userinfo wiring
// lands. Failure is non-fatal: profile metadata is decorative and
// missing data falls back to the provider icon on the dashboard.
//
// ctx is the request-scope context from the OAuth callback handler;
// fetchOAuthProfile derives a bounded timeout child so a hung upstream
// can't outlive the original HTTP request.
func fetchOAuthProfile(ctx context.Context, id, accessToken string) (string, string) {
	switch id {
	case "github":
		ctx, cancel := context.WithTimeout(ctx, oauthProfileFetchTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
		if err != nil {
			return "", ""
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", ""
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			return "", ""
		}
		var u struct {
			Login     string `json:"login"`
			Name      string `json:"name"`
			AvatarURL string `json:"avatar_url"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, oauthResponseLimit)).Decode(&u); err != nil {
			return "", ""
		}
		display := u.Login
		if u.Name != "" {
			display = u.Name
		}
		return display, u.AvatarURL
	}
	return "", ""
}

func newState(it *OAuthIntegration, db *sql.DB) *oauthState {
	cfg := &oauth2.Config{
		ClientID:     resolveTemplate(it.OAuth.ClientID),
		ClientSecret: resolveTemplate(it.OAuth.ClientSecret),
		Scopes:       it.OAuth.Scopes,
		RedirectURL:  it.OAuth.RedirectURI,
		Endpoint:     oauth2.Endpoint{AuthURL: it.OAuth.AuthURL, TokenURL: it.OAuth.TokenURL},
	}
	header := it.Header
	if header == "" {
		header = "Authorization"
	}
	prefix := it.Prefix
	if prefix == "" && header == "Authorization" {
		prefix = "Bearer "
	}
	return &oauthState{
		cfg:    cfg,
		header: header,
		prefix: prefix,
		id:     it.ID,
		db:     db,
	}
}

func (s *oauthState) setToken(tok *oauth2.Token) {
	var base oauth2.TokenSource
	switch {
	case isAnthropicTokenURL(s.cfg.Endpoint.TokenURL):
		// Anthropic's token endpoint requires a JSON body for refresh
		// (returns "Invalid request format" otherwise). Stdlib oauth2
		// only sends form-urlencoded.
		base = &anthropicRefreshSource{cfg: s.cfg, current: tok}
	case isNotionMCPTokenURL(s.cfg.Endpoint.TokenURL):
		// Notion's MCP token endpoint refreshes via form-urlencoded body
		// and expects the dynamically registered client_id (no static
		// ClientSecret — PKCE-only public client).
		base = &notionMCPRefreshSource{cfg: s.cfg, current: tok}
	default:
		base = s.cfg.TokenSource(context.Background(), tok)
	}
	s.source = oauth2.ReuseTokenSourceWithExpiry(
		tok,
		&persistingSource{base: base, state: s},
		60*time.Second,
	)
	s.persist(tok)
}

// anthropicRefreshSource refreshes Anthropic OAuth tokens via JSON
// body. Stateful: holds the current token (with refresh_token) and
// rotates on refresh.
type anthropicRefreshSource struct {
	mu      sync.Mutex
	cfg     *oauth2.Config
	current *oauth2.Token
}

func (a *anthropicRefreshSource) Token() (*oauth2.Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current.Valid() {
		return a.current, nil
	}
	if a.current.RefreshToken == "" {
		return nil, fmt.Errorf("anthropic refresh: no refresh_token")
	}
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": a.current.RefreshToken,
		"client_id":     a.cfg.ClientID,
	})
	// oauth2.TokenSource.Token() has no context parameter; bound the
	// refresh round-trip ourselves so a wedged Anthropic endpoint
	// can't pin a.mu forever, blocking every Inject/Status on this
	// credential.
	ctx, cancel := context.WithTimeout(context.Background(), oauthUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", a.cfg.Endpoint.TokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("anthropic refresh: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("anthropic refresh %d: %s", resp.StatusCode, string(respBytes))
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(respBytes, &tr); err != nil {
		return nil, err
	}
	t := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if t.RefreshToken == "" {
		t.RefreshToken = a.current.RefreshToken
	}
	if tr.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	a.current = t
	return t, nil
}

type persistingSource struct {
	base  oauth2.TokenSource
	state *oauthState
}

func (p *persistingSource) Token() (*oauth2.Token, error) {
	t, err := p.base.Token()
	if err != nil {
		return nil, err
	}
	p.state.persist(t)
	return t, nil
}

// persistProfile updates the human-identity columns for this
// credential's row. Called after fetchOAuthProfile populates them
// post-exchange. UPDATE-only — relies on persist() having INSERTed
// the row first. Best-effort: a failed write surfaces only as
// missing avatar on the dashboard.
func (s *oauthState) persistProfile(displayName, avatarURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`
		UPDATE credentials
		   SET display_name = ?, avatar_url = ?
		 WHERE id = ?
	`, displayName, avatarURL, s.id)
	s.displayName = displayName
	s.avatarURL = avatarURL
}

func (s *oauthState) persist(t *oauth2.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	var expiryNs int64
	if !t.Expiry.IsZero() {
		expiryNs = t.Expiry.UnixNano()
	}
	_, _ = s.db.Exec(`
		INSERT INTO credentials (id, access_token, token_type, refresh_token, expiry_ns, updated_ns, client_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			access_token  = excluded.access_token,
			token_type    = excluded.token_type,
			refresh_token = excluded.refresh_token,
			expiry_ns     = excluded.expiry_ns,
			updated_ns    = excluded.updated_ns,
			client_id     = excluded.client_id
	`, s.id, t.AccessToken, t.TokenType, t.RefreshToken, expiryNs, time.Now().UnixNano(), nullableString(s.clientID))
}

// nullableString returns sql.NullString so that the empty-string case is
// persisted as SQL NULL — static-ClientID flows leave client_id NULL
// rather than "" so a future schema-shape check can distinguish them.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// LoadFromDB rehydrates every credential row whose integration is
// currently registered. Safe to call repeatedly — re-running after
// registerOAuthCredentials picks up tokens for IDs that were
// registered after NewOAuthRegistry's initial pass. Idempotent:
// existing in-memory state for an id is overwritten with the
// DB-stored token.
func (r *OAuthRegistry) LoadFromDB() error {
	return r.loadFromDB()
}

// loadFromDB rehydrates every credential row whose integration is
// still declared in r.integrations.
func (r *OAuthRegistry) loadFromDB() error {
	if r.db == nil {
		return nil
	}
	rows, err := r.db.Query("SELECT id, access_token, token_type, refresh_token, expiry_ns, display_name, avatar_url, client_id FROM credentials")
	if err != nil {
		return fmt.Errorf("oauth registry: query credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			id                  string
			access, typ, refr   sql.NullString
			expiryNs            sql.NullInt64
			displayName, avatar sql.NullString
			clientID            sql.NullString
		)
		if err := rows.Scan(&id, &access, &typ, &refr, &expiryNs, &displayName, &avatar, &clientID); err != nil {
			return fmt.Errorf("oauth registry: scan credential row: %w", err)
		}
		it, ok := r.integrations[id]
		if !ok {
			continue
		}
		s := newState(it, r.db)
		// Restore the dynamically-registered client_id BEFORE setToken
		// so the refresh source (notion_mcp) picks it up via s.cfg.
		if clientID.Valid && clientID.String != "" {
			s.clientID = clientID.String
			s.cfg.ClientID = clientID.String
		}
		tok := &oauth2.Token{
			AccessToken:  access.String,
			TokenType:    typ.String,
			RefreshToken: refr.String,
		}
		if expiryNs.Valid && expiryNs.Int64 != 0 {
			tok.Expiry = time.Unix(0, expiryNs.Int64)
		}
		s.setToken(tok)
		s.displayName = displayName.String
		s.avatarURL = avatar.String
		r.states[id] = s
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("oauth registry: iterate credentials: %w", err)
	}
	return nil
}

type oauthSession struct {
	verifier string
	state    string
	cfg      *oauth2.Config
	id       string
	created  time.Time
	// dynClientID is the RFC 7591 client_id this session registered at
	// start time (notion_mcp). Empty for static-ClientID flows. Stamped
	// onto the credential row at exchange time so refresh can replay it.
	dynClientID string
}

// mergeExtraScopes appends user-selected scopes from the connect-time
// query param onto the integration's declared base scopes, deduped.
// Returns nil when there's nothing to add so the caller can keep the
// original slice. Each scope is constrained to the GitHub-style
// alphabet to keep this from being a vector for arbitrary OAuth
// parameter injection.
func mergeExtraScopes(base []string, raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	have := make(map[string]bool, len(base))
	for _, s := range base {
		have[s] = true
	}
	out := append([]string(nil), base...)
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" || have[s] || !validOAuthScope(s) {
			continue
		}
		have[s] = true
		out = append(out, s)
	}
	if len(out) == len(base) {
		return nil
	}
	return out
}

func validOAuthScope(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == ':' || r == '_':
		default:
			return false
		}
	}
	return true
}

func (w *webMux) apiOAuthStart(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	flow := lookupOAuthFlow(w.g.policy.Load(), id)
	if flow == nil {
		http.Error(rw, "no oauth integration: "+id, 400)
		return
	}
	// User may opt into additional scopes (e.g. SSH/GPG key management
	// for github_oauth) at connect time. Merge into base scopes so the
	// declared defaults remain mandatory — narrowing scope at the UI
	// layer would silently break dependent functionality.
	mergedFlow := *flow
	if extra := mergeExtraScopes(flow.OAuth.Scopes, r.URL.Query().Get("extra_scopes")); extra != nil {
		mergedFlow.OAuth.Scopes = extra
	}
	flow = &mergedFlow
	// Branch: device flow vs auth-code+PKCE.
	if flow.Flow == "device" {
		w.startDeviceFlow(rw, r, id, flow)
		return
	}
	if flow.Flow == "openai_device" {
		w.startOpenAIDeviceFlow(rw, r, id, flow)
		return
	}
	if flow.Flow == "notion_mcp" {
		w.startNotionMCPFlow(rw, r, id, flow)
		return
	}

	verifier := randomString(64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomString(32)
	cfg := &oauth2.Config{
		ClientID:     resolveTemplate(flow.OAuth.ClientID),
		ClientSecret: resolveTemplate(flow.OAuth.ClientSecret),
		Scopes:       flow.OAuth.Scopes,
		RedirectURL:  flow.OAuth.RedirectURI,
		Endpoint:     oauth2.Endpoint{AuthURL: flow.OAuth.AuthURL, TokenURL: flow.OAuth.TokenURL},
	}
	authURL := cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	w.mu.Lock()
	w.sessions[state] = &oauthSession{verifier: verifier, state: state, cfg: cfg, id: id, created: time.Now()}
	for k, s := range w.sessions {
		if time.Since(s.created) > 10*time.Minute {
			delete(w.sessions, k)
		}
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]string{"auth_url": authURL, "state": state})
}

// startNotionMCPFlow drives the mcp.notion.com auth-code flow with RFC
// 7591 dynamic client registration. Notion accepts arbitrary redirect
// URIs at registration, so we register the dashboard's own
// /oauth/callback page — the page auto-exchanges via /api/oauth/exchange
// when it loads, with copy-paste from the URL bar as a fallback.
func (w *webMux) startNotionMCPFlow(rw http.ResponseWriter, r *http.Request, id string, flow *OAuthIntegration) {
	redirectURI := w.dashboardRedirectURI(r, "/oauth/callback")
	clientID, err := registerOAuthClient(r.Context(), flow.OAuth.RegisterURL, redirectURI)
	if err != nil {
		http.Error(rw, "dynamic client registration: "+err.Error(), http.StatusBadGateway)
		return
	}
	verifier := randomString(64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomString(32)
	cfg := &oauth2.Config{
		ClientID:    clientID,
		Scopes:      flow.OAuth.Scopes,
		RedirectURL: redirectURI,
		Endpoint:    oauth2.Endpoint{AuthURL: flow.OAuth.AuthURL, TokenURL: flow.OAuth.TokenURL},
	}
	authURL := cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	w.mu.Lock()
	w.sessions[state] = &oauthSession{
		verifier:    verifier,
		state:       state,
		cfg:         cfg,
		id:          id,
		created:     time.Now(),
		dynClientID: clientID,
	}
	for k, s := range w.sessions {
		if time.Since(s.created) > 10*time.Minute {
			delete(w.sessions, k)
		}
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]string{"auth_url": authURL, "state": state})
}

// dashboardRedirectURI builds a same-origin URL on the dashboard host
// the browser used to hit /api/oauth/start. Used as the registered
// redirect_uri for dynamic-registration flows so the OAuth callback
// lands back on the dashboard the user is already authenticated to.
func (w *webMux) dashboardRedirectURI(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host + path
}

// registerOAuthClient performs RFC 7591 dynamic client registration
// against `registerURL`, asking for a public PKCE client bound to the
// given redirect URI. Returns the issued client_id.
func registerOAuthClient(ctx context.Context, registerURL, redirectURI string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"client_name":                "clawpatrol",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	req, err := http.NewRequestWithContext(ctx, "POST", registerURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("register %d: %s", resp.StatusCode, string(respBytes))
	}
	var rr struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(respBytes, &rr); err != nil {
		return "", err
	}
	if rr.ClientID == "" {
		return "", fmt.Errorf("register: empty client_id in response: %s", string(respBytes))
	}
	return rr.ClientID, nil
}

func (w *webMux) apiOAuthExchange(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		State string `json:"state"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	body.Code = strings.TrimSpace(body.Code)
	if body.Code == "" || body.State == "" {
		http.Error(rw, "missing code/state", 400)
		return
	}
	if i := strings.IndexAny(body.Code, "#&?"); i > 0 {
		body.Code = body.Code[:i]
	}

	w.mu.Lock()
	sess, ok := w.sessions[body.State]
	if ok {
		delete(w.sessions, body.State)
	}
	w.mu.Unlock()
	if !ok {
		http.Error(rw, "unknown state (expired or stale)", 400)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tok, err := exchangeOAuthCode(ctx, sess, body.Code, body.State)
	if err != nil {
		http.Error(rw, "token exchange: "+err.Error(), 400)
		return
	}
	if err := w.g.oauth.SetWithClient(r.Context(), sess.id, tok, sess.dynClientID); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"connected": true, "expires": tok.Expiry.Unix()})
}

// startDeviceFlow kicks off OAuth device flow (RFC 8628). Returns
// {user_code, verification_uri, device_code, interval} so the dashboard
// can prompt the user to enter the code at the verification URI.
func (w *webMux) startDeviceFlow(rw http.ResponseWriter, r *http.Request, id string, it *OAuthIntegration) {
	form := url.Values{}
	form.Set("client_id", resolveTemplate(it.OAuth.ClientID))
	if len(it.OAuth.Scopes) > 0 {
		form.Set("scope", strings.Join(it.OAuth.Scopes, " "))
	}
	ctx, cancel := context.WithTimeout(r.Context(), oauthUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", it.OAuth.DeviceURL, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(rw, "device-code: build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(rw, "device-code: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	if resp.StatusCode != 200 {
		http.Error(rw, fmt.Sprintf("device-code %d: %s", resp.StatusCode, string(body)), http.StatusBadGateway)
		return
	}
	var dr struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &dr); err != nil {
		http.Error(rw, "device-code parse: "+err.Error(), http.StatusBadGateway)
		return
	}
	state := randomString(32)
	w.mu.Lock()
	w.sessions[state] = &oauthSession{
		state:    state,
		id:       id,
		created:  time.Now(),
		verifier: dr.DeviceCode, // reuse field for device_code
		cfg: &oauth2.Config{
			ClientID: resolveTemplate(it.OAuth.ClientID),
			Endpoint: oauth2.Endpoint{TokenURL: it.OAuth.TokenURL},
		},
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]any{
		"flow":             "device",
		"state":            state,
		"user_code":        dr.UserCode,
		"verification_uri": dr.VerificationURI,
		"interval":         dr.Interval,
		"expires_in":       dr.ExpiresIn,
	})
}

// startOpenAIDeviceFlow drives the non-RFC-8628 device-code flow that
// auth.openai.com exposes for the codex CLI. Mirrors unclaw's
// src/plugins/openai-codex/index.ts: POST JSON to deviceauth/usercode,
// the resulting device_auth_id + user_code are persisted in the
// session and fed to the poll handler. Verification URL is hardcoded
// to https://auth.openai.com/codex/device since OpenAI's response
// doesn't include one.
func (w *webMux) startOpenAIDeviceFlow(rw http.ResponseWriter, r *http.Request, id string, it *OAuthIntegration) {
	clientID := resolveTemplate(it.OAuth.ClientID)
	body, _ := json.Marshal(map[string]string{"client_id": clientID})
	ctx, cancel := context.WithTimeout(r.Context(), oauthUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", it.OAuth.DeviceURL, bytes.NewReader(body))
	if err != nil {
		http.Error(rw, "openai deviceauth: build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "clawpatrol/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(rw, "openai deviceauth: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	if resp.StatusCode != 200 {
		http.Error(rw, fmt.Sprintf("openai deviceauth %d: %s", resp.StatusCode, string(respBody)), http.StatusBadGateway)
		return
	}
	// OpenAI ships `interval` as a quoted string ("5") rather than a
	// JSON number — pull it as json.Number to accept both shapes.
	var dr struct {
		DeviceAuthID string      `json:"device_auth_id"`
		UserCode     string      `json:"user_code"`
		Interval     json.Number `json:"interval"`
	}
	if err := json.Unmarshal(respBody, &dr); err != nil || dr.DeviceAuthID == "" || dr.UserCode == "" {
		http.Error(rw, "openai deviceauth parse: "+string(respBody), http.StatusBadGateway)
		return
	}
	state := randomString(32)
	w.mu.Lock()
	w.sessions[state] = &oauthSession{
		state:   state,
		id:      id,
		created: time.Now(),
		// Pack device_auth_id|user_code into verifier so pollDeviceFlow
		// can split them; cfg.RedirectURL carries the codex-specific
		// callback used in the auth-code exchange.
		verifier: dr.DeviceAuthID + "|" + dr.UserCode,
		cfg: &oauth2.Config{
			ClientID:    clientID,
			RedirectURL: it.OAuth.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  it.OAuth.AuthURL,  // poll endpoint
				TokenURL: it.OAuth.TokenURL, // exchange endpoint
			},
		},
	}
	w.mu.Unlock()
	interval, _ := dr.Interval.Int64()
	if interval <= 0 {
		interval = 5
	}
	// Tag as plain "device" in the response so the dashboard's
	// ConnectModal renders the user-code UI (it switches on
	// `flow === "device"`). The internal openai_device dispatch is
	// in the session-id lookup at poll time.
	writeJSON(rw, map[string]any{
		"flow":             "device",
		"state":            state,
		"user_code":        dr.UserCode,
		"verification_uri": "https://auth.openai.com/codex/device",
		"interval":         interval,
	})
}

// pollOpenAIDeviceFlow runs one iteration of the codex device-code
// poll. 202/204 = still pending; 200 with authorization_code +
// code_verifier triggers the /oauth/token exchange that returns the
// real access token bundle.
func (w *webMux) pollOpenAIDeviceFlow(rw http.ResponseWriter, r *http.Request, sess *oauthSession) {
	parts := strings.SplitN(sess.verifier, "|", 2)
	if len(parts) != 2 {
		http.Error(rw, "session corrupt", 500)
		return
	}
	deviceAuthID, userCode := parts[0], parts[1]
	pollBody, _ := json.Marshal(map[string]string{
		"device_auth_id": deviceAuthID,
		"user_code":      userCode,
	})
	ctx, cancel := context.WithTimeout(r.Context(), oauthUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", sess.cfg.Endpoint.AuthURL, bytes.NewReader(pollBody))
	if err != nil {
		http.Error(rw, "openai poll: build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "clawpatrol/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(rw, "openai poll: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == 202 || resp.StatusCode == 204 {
		writeJSON(rw, map[string]string{"error": "authorization_pending"})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	var pr struct {
		AuthorizationCode string `json:"authorization_code"`
		CodeVerifier      string `json:"code_verifier"`
	}
	if err := json.Unmarshal(body, &pr); err != nil || pr.AuthorizationCode == "" || pr.CodeVerifier == "" {
		writeJSON(rw, map[string]string{"error": "authorization_pending"})
		return
	}
	// Exchange auth code for tokens via the standard /oauth/token
	// endpoint (form-urlencoded body, PKCE code_verifier).
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", pr.AuthorizationCode)
	form.Set("code_verifier", pr.CodeVerifier)
	form.Set("client_id", sess.cfg.ClientID)
	form.Set("redirect_uri", sess.cfg.RedirectURL)
	exCtx, exCancel := context.WithTimeout(r.Context(), oauthUpstreamTimeout)
	defer exCancel()
	exReq, err := http.NewRequestWithContext(exCtx, "POST", sess.cfg.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(rw, "openai exchange: build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	exReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	exReq.Header.Set("Accept", "application/json")
	exResp, err := http.DefaultClient.Do(exReq)
	if err != nil {
		http.Error(rw, "openai exchange: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = exResp.Body.Close() }()
	exBody, _ := io.ReadAll(io.LimitReader(exResp.Body, oauthResponseLimit))
	if exResp.StatusCode != 200 {
		http.Error(rw, fmt.Sprintf("openai exchange %d: %s", exResp.StatusCode, string(exBody)), http.StatusBadGateway)
		return
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(exBody, &tr); err != nil || tr.AccessToken == "" {
		http.Error(rw, "openai exchange parse", http.StatusBadGateway)
		return
	}
	tok := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	w.mu.Lock()
	delete(w.sessions, sess.state)
	w.mu.Unlock()
	if err := w.g.oauth.Set(r.Context(), sess.id, tok); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"connected": true})
}

// pollDeviceFlow exchanges device_code for a token. Called by the
// frontend on a timer until success / denial / expiration.
func (w *webMux) pollDeviceFlow(rw http.ResponseWriter, r *http.Request, sess *oauthSession) {
	form := url.Values{}
	form.Set("client_id", sess.cfg.ClientID)
	form.Set("device_code", sess.verifier)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	ctx, cancel := context.WithTimeout(r.Context(), oauthUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", sess.cfg.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(rw, "device poll: build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(rw, "device poll: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	// Don't log the body verbatim — on success it carries access_token.
	var tr struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		RefreshToken     string `json:"refresh_token"`
		Scope            string `json:"scope"`
		ExpiresIn        int64  `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Interval         int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		http.Error(rw, "device poll parse: "+err.Error(), http.StatusBadGateway)
		return
	}
	if tr.Error != "" {
		// `slow_down` carries an updated interval (RFC 8628). Surface
		// it to the dashboard so the polling loop respects the new
		// cadence; otherwise the client keeps hitting at the original
		// interval and GitHub never returns the token.
		out := map[string]any{"error": tr.Error, "detail": tr.ErrorDescription}
		if tr.Interval > 0 {
			out["interval"] = tr.Interval
		}
		writeJSON(rw, out)
		return
	}
	if tr.AccessToken == "" {
		writeJSON(rw, map[string]string{"error": "authorization_pending"})
		return
	}
	tok := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	w.mu.Lock()
	delete(w.sessions, sess.state)
	w.mu.Unlock()
	if err := w.g.oauth.Set(r.Context(), sess.id, tok); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"connected": true})
}

// exchangeOAuthCode finalizes an OAuth PKCE flow. Anthropic's token
// endpoint requires a JSON body (returns "Invalid request format" for
// the standard form-urlencoded body), so we hand-roll the request for
// claude integration. Other providers use the stdlib oauth2.Exchange.
func exchangeOAuthCode(ctx context.Context, sess *oauthSession, code, state string) (*oauth2.Token, error) {
	if isAnthropicTokenURL(sess.cfg.Endpoint.TokenURL) {
		return exchangeAnthropicCode(ctx, sess, code, state)
	}
	return sess.cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", sess.verifier),
		oauth2.SetAuthURLParam("redirect_uri", sess.cfg.RedirectURL),
	)
}

func isAnthropicTokenURL(u string) bool {
	return strings.Contains(u, "anthropic.com/")
}

func isNotionMCPTokenURL(u string) bool {
	return strings.Contains(u, "mcp.notion.com/")
}

// notionMCPRefreshSource refreshes Notion MCP OAuth tokens via the
// form-urlencoded body the spec mandates. The client_id is read from
// cfg.ClientID, which the registry restores from the persisted
// credentials.client_id column on boot. Stateful: holds the current
// token (with refresh_token) and rotates it on each refresh.
type notionMCPRefreshSource struct {
	mu      sync.Mutex
	cfg     *oauth2.Config
	current *oauth2.Token
}

func (n *notionMCPRefreshSource) Token() (*oauth2.Token, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.current.Valid() {
		return n.current, nil
	}
	if n.current.RefreshToken == "" {
		return nil, fmt.Errorf("notion_mcp refresh: no refresh_token")
	}
	if n.cfg.ClientID == "" {
		return nil, fmt.Errorf("notion_mcp refresh: no client_id (dynamic registration was never persisted)")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", n.current.RefreshToken)
	form.Set("client_id", n.cfg.ClientID)
	// See anthropicRefreshSource.Token: oauth2 has no ctx on Token(),
	// so we bound the upstream round-trip here so n.mu stays available
	// even if Notion's token endpoint hangs.
	ctx, cancel := context.WithTimeout(context.Background(), oauthUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", n.cfg.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("notion_mcp refresh: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notion_mcp refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("notion_mcp refresh %d: %s", resp.StatusCode, string(respBytes))
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(respBytes, &tr); err != nil {
		return nil, err
	}
	t := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if t.RefreshToken == "" {
		t.RefreshToken = n.current.RefreshToken
	}
	if tr.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	n.current = t
	return t, nil
}

func exchangeAnthropicCode(ctx context.Context, sess *oauthSession, code, state string) (*oauth2.Token, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  sess.cfg.RedirectURL,
		"client_id":     sess.cfg.ClientID,
		"code_verifier": sess.verifier,
		"state":         state,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", sess.cfg.Endpoint.TokenURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(respBytes))
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(respBytes, &tr); err != nil {
		return nil, err
	}
	tok := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return tok, nil
}

func (w *webMux) apiOAuthDevicePoll(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	state := r.URL.Query().Get("state")
	w.mu.Lock()
	sess := w.sessions[state]
	w.mu.Unlock()
	if sess == nil {
		http.Error(rw, "unknown state (expired)", 400)
		return
	}
	// Dispatch by integration's flow type. openai_device uses the
	// codex deviceauth/token endpoint shape (JSON body, returns
	// authorization_code + code_verifier instead of a token); the
	// stdlib RFC-8628 path covers github.
	if it := w.g.oauth.Integration(sess.id); it != nil && it.Flow == "openai_device" {
		w.pollOpenAIDeviceFlow(rw, r, sess)
		return
	}
	w.pollDeviceFlow(rw, r, sess)
}

func (w *webMux) apiOAuthRevoke(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.ID == "" {
		http.Error(rw, "missing id", 400)
		return
	}
	w.g.oauth.Revoke(body.ID)
	writeJSON(rw, map[string]bool{"ok": true})
}

// oauthCallbackHTML is served at GET /oauth/callback for
// dynamic-registration flows that redirect back to the dashboard
// (notion_mcp). The inline JS extracts ?code & ?state, POSTs them to
// /api/oauth/exchange so the original ConnectModal sees the credential
// connect itself, and shows the code prominently as a copy-paste
// fallback if the auto-exchange fails (e.g. dashboard secret expired,
// state already consumed, etc.).
const oauthCallbackHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>OAuth callback — clawpatrol</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh;
         display: flex; align-items: center; justify-content: center;
         background: #f7f5f0; color: #1a1a1a; }
  .box { max-width: 480px; padding: 2rem; background: white;
         border: 2px solid #1a1a1a; border-radius: 6px;
         box-shadow: 4px 4px 0 #1a1a1a; }
  h1 { font-size: 1rem; text-transform: uppercase; letter-spacing: .1em;
       margin: 0 0 1rem; }
  .status { font-size: .85rem; margin-bottom: 1rem; line-height: 1.5; }
  .code { font-family: ui-monospace, monospace; font-size: .8rem;
          word-break: break-all; padding: .75rem; background: #f0ebe0;
          border: 1px solid #1a1a1a; border-radius: 3px; user-select: all; }
  .err { color: #a8482e; }
  .ok { color: #2b6630; }
  button { font-family: inherit; font-size: .8rem; padding: .4rem .8rem;
           background: #1a1a1a; color: white; border: none; cursor: pointer;
           border-radius: 3px; margin-top: .75rem; }
  button:hover { background: #333; }
  details { margin-top: 1rem; font-size: .8rem; }
  details summary { cursor: pointer; color: #666; }
  details p { margin: .5rem 0 0; line-height: 1.5; color: #444; }
</style>
</head>
<body>
<div class="box">
  <h1 id="title">Completing sign-in…</h1>
  <div id="status" class="status">Exchanging authorization code.</div>
  <div id="fallback" style="display:none">
    <p class="status">Auto-exchange failed. Copy this code and paste it
    into the dashboard's connect dialog:</p>
    <div id="code" class="code"></div>
    <button onclick="navigator.clipboard.writeText(document.getElementById('code').textContent)">copy code</button>
  </div>
  <details id="details" style="display:none">
    <summary>error detail</summary>
    <p id="detail"></p>
  </details>
</div>
<script>
(async () => {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  const err = params.get('error');
  const errDesc = params.get('error_description');
  const $ = (id) => document.getElementById(id);

  if (err) {
    $('title').textContent = 'Authorization denied';
    $('title').classList.add('err');
    $('status').textContent = errDesc || err;
    return;
  }
  if (!code || !state) {
    $('title').textContent = 'Missing code or state';
    $('title').classList.add('err');
    $('status').textContent = 'This page expects ?code= and ?state= query parameters.';
    return;
  }

  try {
    const resp = await fetch('/api/oauth/exchange', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin',
      body: JSON.stringify({code, state}),
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error('HTTP ' + resp.status + ': ' + text);
    }
    $('title').textContent = 'Connected';
    $('title').classList.add('ok');
    $('status').textContent = 'You can close this tab.';
    // Nudge any open dashboard tab to refresh — same-origin BroadcastChannel.
    try { new BroadcastChannel('oauth').postMessage({type: 'connected', state}); } catch (_) {}
    setTimeout(() => window.close(), 1500);
  } catch (e) {
    $('title').textContent = 'Auto-exchange failed';
    $('title').classList.add('err');
    $('status').style.display = 'none';
    $('fallback').style.display = 'block';
    $('code').textContent = code;
    $('details').style.display = 'block';
    $('detail').textContent = String(e && e.message ? e.message : e);
  }
})();
</script>
</body>
</html>
`

// serveOAuthCallback renders the dynamic-registration redirect-uri page
// (see oauthCallbackHTML). Same dashboard-secret gating as everything
// else — the user is already authenticated to the dashboard when the
// browser follows the OAuth redirect here (SameSite=Lax cookie rides
// along), so no special handling is needed.
func (w *webMux) serveOAuthCallback(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	_, _ = rw.Write([]byte(oauthCallbackHTML))
}
