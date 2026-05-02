package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const ScopeUser = "user"

type OAuthConfig struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	AuthURL      string   `yaml:"auth_url"`
	TokenURL     string   `yaml:"token_url"`
	DeviceURL    string   `yaml:"device_url"` // used by Flow="device"
	RedirectURI  string   `yaml:"redirect_uri"`
	Scopes       []string `yaml:"scopes"`
	RefreshToken string   `yaml:"refresh_token"` // bootstrap; per-owner tokens override
}

type OAuthIntegration struct {
	ID     string      `yaml:"id"`
	Type   string      `yaml:"type"`
	Header string      `yaml:"header"`
	Prefix string      `yaml:"prefix"`
	Flow   string      `yaml:"flow"` // "auth_code" (default) | "device"
	OAuth  OAuthConfig `yaml:"oauth"`
}

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
		_, _ = r.db.Exec("DELETE FROM credentials WHERE id=? AND owner=?", id, owner)
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
		INSERT INTO credentials (id, owner, access_token, token_type, refresh_token, expiry_ns, updated_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id, owner) DO UPDATE SET
			access_token  = excluded.access_token,
			token_type    = excluded.token_type,
			refresh_token = excluded.refresh_token,
			expiry_ns     = excluded.expiry_ns,
			updated_ns    = excluded.updated_ns
	`, s.id, s.owner, t.AccessToken, t.TokenType, t.RefreshToken, expiryNs, time.Now().UnixNano())
}

// loadFromDB rehydrates every (id, owner) credential row whose
// integration is still declared in r.integrations.
func (r *OAuthRegistry) loadFromDB() error {
	if r.db == nil {
		return nil
	}
	rows, err := r.db.Query("SELECT id, owner, access_token, token_type, refresh_token, expiry_ns FROM credentials")
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
