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

	"github.com/denoland/clawpatrol/config"
)

const ScopeUser = "user"

// OAuthConfig + OAuthIntegration moved to config/oauth.go so credential
// plugins can ship their own OAuth flow data without import cycles.
// Aliased here so existing call sites in this package don't churn.
type (
	OAuthConfig      = config.OAuthConfig
	OAuthIntegration = config.OAuthIntegration
)

type tokenStore struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

// oauthState is one credential: tokens for a single (integration, owner).
// Persisted in the credentials table; one row per (id, owner).
type oauthState struct {
	cfg    *oauth2.Config
	source oauth2.TokenSource
	header string
	prefix string
	id     string
	owner  string
	db     *sql.DB
	mu     sync.Mutex
}

// OAuthRegistry holds all configured OAuth integrations and a per-owner
// state map. Keyed by (integration_id, owner-string).
type OAuthRegistry struct {
	mu           sync.RWMutex
	integrations map[string]*OAuthIntegration
	states       map[string]*oauthState // key: id + "|" + owner
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

func stateKey(id, owner string) string { return id + "|" + owner }

func (r *OAuthRegistry) get(id, owner string) *oauthState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.states[stateKey(id, owner)]
}

func (r *OAuthRegistry) Owners(id string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []string{}
	for k, s := range r.states {
		if s.id == id && s.source != nil {
			_ = k
			out = append(out, s.owner)
		}
	}
	return out
}

// Inject sets the auth header on req using the (id, owner) credential.
// Returns (overrode, err). overrode=false means no token yet; caller
// may pass agent's existing header through, or fail.
func (r *OAuthRegistry) Inject(id, owner string, req *http.Request) (bool, error) {
	if id == "" {
		return false, nil
	}
	s := r.get(id, owner)
	if s == nil || s.source == nil {
		return false, nil
	}
	t, err := s.source.Token()
	if err != nil {
		return false, err
	}
	req.Header.Set(s.header, s.prefix+t.AccessToken)
	return true, nil
}

// Token returns the current access token for (id, owner) — refreshing
// it through the underlying oauth2.TokenSource if it's stale. Empty
// string + nil error means no token has been captured yet for this
// owner; the caller decides between fail-closed and pass-through.
//
// Used by the runtime SecretStore bridge so credential plugins
// (which know how to format Authorization / x-api-key / cookie)
// can stamp the bytes onto the request — OAuthRegistry.Inject
// hardcodes the header shape and predates the per-credential plugin
// model.
func (r *OAuthRegistry) Token(id, owner string) (string, error) {
	if id == "" {
		return "", nil
	}
	s := r.get(id, owner)
	if s == nil || s.source == nil {
		return "", nil
	}
	t, err := s.source.Token()
	if err != nil {
		return "", err
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

// Status returns connected info for a given (id, owner).
func (r *OAuthRegistry) Status(id, owner string) (connected bool, expiry time.Time) {
	s := r.get(id, owner)
	if s == nil || s.source == nil {
		return false, time.Time{}
	}
	t, err := s.source.Token()
	if err != nil || t.AccessToken == "" {
		return false, time.Time{}
	}
	return true, t.Expiry
}

// Revoke deletes the (id, owner) credential and its DB row.
func (r *OAuthRegistry) Revoke(id, owner string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.states[stateKey(id, owner)]; !ok {
		return
	}
	if r.db != nil {
		_, _ = r.db.Exec("DELETE FROM credentials WHERE id=? AND profile=?", id, owner)
	}
	delete(r.states, stateKey(id, owner))
}

// Set stores tokens captured externally (browser auth flow callback).
func (r *OAuthRegistry) Set(id, owner string, tok *oauth2.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	it, ok := r.integrations[id]
	if !ok {
		return fmt.Errorf("unknown integration: %s", id)
	}
	s := r.states[stateKey(id, owner)]
	if s == nil {
		s = newState(it, owner, r.db)
		r.states[stateKey(id, owner)] = s
	}
	s.setToken(tok)
	return nil
}

func newState(it *OAuthIntegration, owner string, db *sql.DB) *oauthState {
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
		owner:  owner,
		db:     db,
	}
}

func (s *oauthState) setToken(tok *oauth2.Token) {
	var base oauth2.TokenSource
	switch s.id {
	case "claude":
		// Anthropic's token endpoint requires a JSON body for refresh
		// (returns "Invalid request format" otherwise). Stdlib oauth2
		// only sends form-urlencoded.
		base = &anthropicRefreshSource{cfg: s.cfg, current: tok}
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
	req, err := http.NewRequest("POST", a.cfg.Endpoint.TokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
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
		INSERT INTO credentials (id, profile, access_token, token_type, refresh_token, expiry_ns, updated_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id, profile) DO UPDATE SET
			access_token  = excluded.access_token,
			token_type    = excluded.token_type,
			refresh_token = excluded.refresh_token,
			expiry_ns     = excluded.expiry_ns,
			updated_ns    = excluded.updated_ns
	`, s.id, s.owner, t.AccessToken, t.TokenType, t.RefreshToken, expiryNs, time.Now().UnixNano())
}

// LoadFromDB rehydrates every (id, owner) credential row whose
// integration is currently registered. Safe to call repeatedly —
// re-running after registerOAuthCredentials picks up tokens for IDs
// that were registered after NewOAuthRegistry's initial pass.
// Idempotent: existing in-memory state for an (id, owner) is
// overwritten with the DB-stored token.
func (r *OAuthRegistry) LoadFromDB() error {
	return r.loadFromDB()
}

// loadFromDB rehydrates every (id, owner) credential row whose
// integration is still declared in r.integrations.
func (r *OAuthRegistry) loadFromDB() error {
	if r.db == nil {
		return nil
	}
	rows, err := r.db.Query("SELECT id, profile, access_token, token_type, refresh_token, expiry_ns FROM credentials")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id, owner         string
			access, typ, refr sql.NullString
			expiryNs          sql.NullInt64
		)
		if err := rows.Scan(&id, &owner, &access, &typ, &refr, &expiryNs); err != nil {
			return err
		}
		it, ok := r.integrations[id]
		if !ok {
			continue
		}
		s := newState(it, owner, r.db)
		tok := &oauth2.Token{
			AccessToken:  access.String,
			TokenType:    typ.String,
			RefreshToken: refr.String,
		}
		if expiryNs.Valid && expiryNs.Int64 != 0 {
			tok.Expiry = time.Unix(0, expiryNs.Int64)
		}
		s.setToken(tok)
		r.states[stateKey(id, owner)] = s
	}
	return rows.Err()
}

type oauthSession struct {
	verifier string
	state    string
	cfg      *oauth2.Config
	id       string
	owner    string
	created  time.Time
}

func (w *webMux) apiOAuthStart(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	id := r.URL.Query().Get("id")
	flow := lookupOAuthFlow(w.g.policy.Load(), id)
	if flow == nil {
		http.Error(rw, "no oauth integration: "+id, 400)
		return
	}
	owner, ownerLabel := w.ownerForCaller(r)
	if owner == "" {
		http.Error(rw, "could not determine owner identity (tailscale whois failed)", 400)
		return
	}
	// Branch: device flow vs auth-code+PKCE.
	if flow.Flow == "device" {
		w.startDeviceFlow(rw, id, flow, owner, ownerLabel)
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
	w.sessions[state] = &oauthSession{verifier: verifier, state: state, cfg: cfg, id: id, owner: owner, created: time.Now()}
	for k, s := range w.sessions {
		if time.Since(s.created) > 10*time.Minute {
			delete(w.sessions, k)
		}
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]string{"auth_url": authURL, "state": state, "owner": ownerLabel})
}

func (w *webMux) apiOAuthExchange(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
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
	if err := w.g.oauth.Set(sess.id, sess.owner, tok); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"connected": true, "owner": sess.owner, "expires": tok.Expiry.Unix()})
}

// startDeviceFlow kicks off OAuth device flow (RFC 8628). Returns
// {user_code, verification_uri, device_code, interval} so the dashboard
// can prompt the user to enter the code at the verification URI.
func (w *webMux) startDeviceFlow(rw http.ResponseWriter, id string, it *OAuthIntegration, owner, ownerLabel string) {
	form := url.Values{}
	form.Set("client_id", resolveTemplate(it.OAuth.ClientID))
	if len(it.OAuth.Scopes) > 0 {
		form.Set("scope", strings.Join(it.OAuth.Scopes, " "))
	}
	req, _ := http.NewRequest("POST", it.OAuth.DeviceURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(rw, "device-code: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		http.Error(rw, fmt.Sprintf("device-code %d: %s", resp.StatusCode, string(body)), 502)
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
		http.Error(rw, "device-code parse: "+err.Error(), 502)
		return
	}
	state := randomString(32)
	w.mu.Lock()
	w.sessions[state] = &oauthSession{
		state:    state,
		id:       id,
		owner:    owner,
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
		"owner":            ownerLabel,
	})
}

// pollDeviceFlow exchanges device_code for a token. Called by the
// frontend on a timer until success / denial / expiration.
func (w *webMux) pollDeviceFlow(rw http.ResponseWriter, sess *oauthSession) {
	form := url.Values{}
	form.Set("client_id", sess.cfg.ClientID)
	form.Set("device_code", sess.verifier)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	req, _ := http.NewRequest("POST", sess.cfg.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(rw, "device poll: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
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
		http.Error(rw, "device poll parse: "+err.Error(), 502)
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
	if err := w.g.oauth.Set(sess.id, sess.owner, tok); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	writeJSON(rw, map[string]any{"connected": true, "owner": sess.owner})
}

// exchangeOAuthCode finalizes an OAuth PKCE flow. Anthropic's token
// endpoint requires a JSON body (returns "Invalid request format" for
// the standard form-urlencoded body), so we hand-roll the request for
// claude integration. Other providers use the stdlib oauth2.Exchange.
func exchangeOAuthCode(ctx context.Context, sess *oauthSession, code, state string) (*oauth2.Token, error) {
	if sess.id == "claude" {
		return exchangeAnthropicCode(ctx, sess, code, state)
	}
	return sess.cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", sess.verifier),
		oauth2.SetAuthURLParam("redirect_uri", sess.cfg.RedirectURL),
	)
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
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
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
		http.Error(rw, "POST", 405)
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
	w.pollDeviceFlow(rw, sess)
}

func (w *webMux) apiOAuthRevoke(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	var body struct {
		ID    string `json:"id"`
		Owner string `json:"owner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	if body.ID == "" || body.Owner == "" {
		http.Error(rw, "missing id or owner", 400)
		return
	}
	w.g.oauth.Revoke(body.ID, body.Owner)
	writeJSON(rw, map[string]bool{"ok": true})
}
