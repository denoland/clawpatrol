package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
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

// oauthReuseEarlyExpiry is how long before a token's stated expiry the
// reuse source stops handing it out and refreshes. Every refresh in the
// process funnels through that source, so it is also the window the
// background refresher works in: a Token() call made outside it is
// answered from the cache and renews nothing.
const oauthReuseEarlyExpiry = 60 * time.Second

// oauthRefreshInterval is how often the background refresher sweeps for
// credentials inside the reuse source's early-expiry window. Well under
// oauthReuseEarlyExpiry so a token entering that window is renewed with
// time to spare rather than on the tick that expires it, and so the
// status path reports a live expiry rather than one just gone by.
const oauthRefreshInterval = 15 * time.Second

// oauthRefreshBackoffBase / oauthRefreshBackoffMax bound the retry
// schedule after a transient refresh failure. See refreshBackoff.
const (
	oauthRefreshBackoffBase = 30 * time.Second
	oauthRefreshBackoffMax  = 15 * time.Minute
)

// errNoRefreshToken and errNoDynamicClientID are the two refresh
// failures the gateway diagnoses itself. Both are terminal: without a
// refresh token to present, or without the dynamically registered
// client_id the provider issued it against, no retry can produce a
// token and only a new authorisation flow can.
var (
	errNoRefreshToken    = errors.New("no refresh token is stored")
	errNoDynamicClientID = errors.New("dynamic client registration was never persisted")
)

// knownOAuthErrorCodes is the set of token-endpoint error codes the
// gateway recognises, mapped to whether the code is terminal — the
// grant, the client registration or the requested scope was rejected
// outright, so a retry presents the provider with the identical request
// and earns the identical answer. A terminal code latches the credential
// into "needs re-authorisation".
//
// `server_error`, `temporarily_unavailable` and `slow_down` are
// transient because they say outright that a retry is the right move.
// `invalid_request` is transient by judgement: a mangling proxy or a
// provider bug produces it as readily as a genuinely malformed request,
// and the cost of guessing wrong is asymmetric — a wrongly transient
// verdict costs one more background attempt, a wrongly terminal one
// parks a working credential until an operator re-authorises it.
//
// The map doubles as the allow-list for what reaches the dashboard. The
// `error` member of a token-endpoint reply is provider-controlled free
// text, so a code outside this set is dropped rather than rendered and
// the HTTP status stands in for it.
var knownOAuthErrorCodes = map[string]bool{
	"invalid_grant":             true,
	"invalid_client":            true,
	"unauthorized_client":       true,
	"unsupported_grant_type":    true,
	"invalid_scope":             true,
	"access_denied":             true,
	"expired_token":             true,
	"invalid_request":           false,
	"unsupported_response_type": false,
	"server_error":              false,
	"temporarily_unavailable":   false,
	"slow_down":                 false,
	"authorization_pending":     false,
}

// classifyRefreshError turns a refresh failure into the verdict the
// status path remembers and a reason string safe to render on the
// dashboard.
//
// The reason never embeds the error text: a provider's token-endpoint
// body is free-form and can echo the credentials it was sent. The one
// provider-supplied fragment that survives is the error code, and only
// when it is one knownOAuthErrorCodes lists — otherwise the HTTP status
// stands in for it.
func classifyRefreshError(err error) (refreshState, string) {
	switch {
	case errors.Is(err, errNoRefreshToken):
		return refreshTerminal, errNoRefreshToken.Error()
	case errors.Is(err, errNoDynamicClientID):
		return refreshTerminal, errNoDynamicClientID.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return refreshTransient, "refresh timed out"
	case errors.Is(err, context.Canceled):
		return refreshTransient, "refresh cancelled"
	}
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		return refreshTransient, "refresh failed: could not reach the provider"
	}
	status := 0
	if re.Response != nil {
		status = re.Response.StatusCode
	}
	terminal, known := knownOAuthErrorCodes[re.ErrorCode]
	if terminal && known && rejectionStatus(status) {
		return refreshTerminal, "the provider rejected the refresh: " + re.ErrorCode
	}
	if known {
		return refreshTransient, "refresh failed: " + re.ErrorCode
	}
	if status != 0 {
		return refreshTransient, fmt.Sprintf("refresh failed: provider answered HTTP %d", status)
	}
	return refreshTransient, "refresh failed: unrecognised provider response"
}

// rejectionStatus reports whether a token endpoint used this status to
// reject the request itself, which is the only place RFC 6749 §5.2 puts
// a grant rejection. A 5xx, a 429 or a 408 carrying the same error code
// is far more likely to be a proxy or an edge answering for the
// provider, and latching on one would park a working credential for the
// length of an outage.
func rejectionStatus(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return true
	}
	return false
}

// refreshLogDetail is what the refresh-failure log line carries
// alongside the classified reason. A token-endpoint reply is
// provider-controlled and can echo back the credentials it was sent,
// error_description included, so a classified HTTP failure is logged as
// its status and nothing more. A transport failure carries no provider
// body, and its text — DNS, TLS, proxy — is the most useful thing in the
// line, so that one is kept whole.
func refreshLogDetail(err error) string {
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		return err.Error()
	}
	if re.Response != nil {
		return fmt.Sprintf("HTTP %d", re.Response.StatusCode)
	}
	return "provider rejected the refresh"
}

// retrieveError wraps a non-200 token-endpoint reply in the stdlib's
// structured form, so classifyRefreshError reads the RFC 6749 error
// code out of one type whichever of the three refresh sources produced
// the failure. The body rides along for the log; the classifier never
// renders it.
func retrieveError(resp *http.Response, body []byte) *oauth2.RetrieveError {
	var e struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI         string `json:"error_uri"`
	}
	// A provider that answers an error with something other than the
	// RFC's JSON object leaves the codes empty, which classifies on the
	// HTTP status alone.
	_ = json.Unmarshal(body, &e)
	return &oauth2.RetrieveError{
		Response:         resp,
		Body:             body,
		ErrorCode:        e.Error,
		ErrorDescription: e.ErrorDescription,
		ErrorURI:         e.ErrorURI,
	}
}

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
	// that use RFC 7591 (notion_mcp/dynamic_mcp). Static-ClientID flows
	// (github, anthropic, codex) leave this empty and use cfg.ClientID.
	// Persisted in the credentials table alongside the tokens so refresh
	// works across gateway restarts.
	clientID string
	flow     string
	db       *sql.DB
	mu       sync.Mutex
	// writeMu serialises this credential's own writes to the credentials
	// table and orders them against the generation check that decides
	// whether a write still applies. Separate from mu because the status
	// path waits on mu, and the point of reporting from memory is that it
	// waits on nothing slow.
	writeMu sync.Mutex
	// current is the token this credential last persisted — the one the
	// reuse source was seeded with, or the one the most recent refresh
	// produced. Status reports from it so rendering the credential list
	// costs no provider round trips; the token source stays the only
	// thing a request-path injection consults.
	current *oauth2.Token
	// refresh is the remembered outcome of the last refresh attempt on
	// this credential, and refreshReason its operator-readable summary.
	// refreshTerminal means the provider rejected the grant itself and
	// only a new authorisation flow restores the credential, so neither
	// the dashboard nor the background refresher asks the provider
	// again.
	refresh       refreshState
	refreshReason string
	// refreshing is true while a background refresh is in flight, so
	// successive ticks hand off one attempt at a time instead of piling
	// goroutines up behind the reuse source's mutex.
	refreshing bool
	// retryAfter is the earliest time the background refresher retries
	// following a transient failure, and failures the consecutive count
	// that sets the backoff step. A provider outage therefore costs one
	// attempt per credential per step rather than one per tick.
	retryAfter time.Time
	failures   int
	// gen counts the tokens this credential has held. setToken bumps it
	// and stamps the new value on the source it installs, so a refresh
	// still in flight against a superseded source is recognised when it
	// settles: its verdict describes a token the credential no longer
	// holds, and recording it would either re-latch a credential that
	// was just re-authorised or persist the token it replaced. Revoke
	// bumps it for the same reason, so a late refresh cannot resurrect
	// a deleted credential's row.
	gen uint64
}

// refreshState is the remembered verdict on a credential's last
// refresh attempt. It is what lets the status path answer without a
// network call: the expiry comes from the persisted token, the
// re-authorisation prompt from this.
type refreshState int

const (
	// refreshUnknown means no attempt has settled against the token
	// currently held — the state a freshly stored or rehydrated
	// credential starts in.
	refreshUnknown refreshState = iota
	// refreshOK means the last attempt produced a token.
	refreshOK
	// refreshTransient means the last attempt failed for a reason a
	// retry can clear: a timeout, a transport error, a 5xx, a 429, or
	// any response the provider did not shape as a grant rejection.
	refreshTransient
	// refreshTerminal means the provider rejected the grant, the client
	// or the scope outright, or there is no refresh token to present.
	// Nothing but a new authorisation flow changes the answer.
	refreshTerminal
)

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
	if s == nil {
		return false, nil
	}
	src := s.tokenSource()
	if src == nil {
		return false, nil
	}
	t, err := src.Token()
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
	if s == nil {
		return "", nil
	}
	src := s.tokenSource()
	if src == nil {
		return "", nil
	}
	t, err := src.Token()
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

// OAuthStatus is the dashboard-facing view of one OAuth credential.
// Every field comes from state already in memory — the persisted token
// and the remembered refresh verdict — so building it performs no I/O
// and cannot block on a provider.
//
// NeedsReauth is the terminal verdict: the stored refresh token no
// longer buys an access token and only re-running the OAuth flow
// restores the credential. Connected is false whenever it is set.
// Reason is an operator-readable summary of the last refresh failure —
// an RFC 6749 error code or a transport class, never a provider
// response body and never token material.
type OAuthStatus struct {
	Connected   bool
	Expiry      time.Time
	NeedsReauth bool
	Reason      string
}

// Status reports the named credential's connection state from the
// persisted token's expiry plus the remembered outcome of the last
// refresh attempt. It never calls the token source: a dashboard load
// that forced a refresh paid a provider round trip per stale
// credential, and for one whose refresh token the provider had revoked
// it paid that round trip on every load. The background refresher
// (refreshExpiring) renews tokens ahead of expiry, and the request
// path still refreshes on demand through Inject / Token.
func (r *OAuthRegistry) Status(id string) OAuthStatus {
	s := r.get(id)
	if s == nil {
		return OAuthStatus{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.source == nil || s.current == nil || s.current.AccessToken == "" {
		return OAuthStatus{}
	}
	switch {
	// An expired access token with no refresh token to trade is the one
	// dead state readable without having asked the provider anything.
	// Reporting it keeps the answer identical to the one the refreshing
	// Status gave, which failed on exactly this case.
	case tokenExpired(s.current, time.Now()) && s.current.RefreshToken == "":
		return OAuthStatus{
			Expiry:      s.current.Expiry,
			NeedsReauth: true,
			Reason:      "the access token has expired and " + errNoRefreshToken.Error(),
		}
	case s.refresh == refreshTerminal:
		return OAuthStatus{
			Expiry:      s.current.Expiry,
			NeedsReauth: true,
			Reason:      s.refreshReason,
		}
	// An expired token whose last refresh failed transiently authorises
	// nothing right now, so it does not read connected — but the failure
	// is not the grant's, so NeedsReauth stays clear and the reason names
	// the outage. The next sweep flips it back without anyone touching
	// the credential.
	case s.refresh == refreshTransient && tokenExpired(s.current, time.Now()):
		return OAuthStatus{Expiry: s.current.Expiry, Reason: s.refreshReason}
	}
	// A credential still inside its token's lifetime reads connected even
	// when the last refresh failed, with the reason carried alongside: it
	// can authorise requests until the token runs out, and the sweep has
	// until then to succeed.
	return OAuthStatus{
		Connected: true,
		Expiry:    s.current.Expiry,
		Reason:    s.refreshReason,
	}
}

// tokenExpired reports whether t's stated expiry has passed. A zero
// Expiry means the provider issued a token with no stated lifetime, so
// nothing is known to have expired.
func tokenExpired(t *oauth2.Token, now time.Time) bool {
	return !t.Expiry.IsZero() && !t.Expiry.After(now)
}

// RunRefresher renews access tokens ahead of expiry for the life of the
// gateway. It is what keeps the non-blocking Status honest: the expiry
// it reports is the one the credential actually holds, so a token has to
// be renewed before anything can observe it stale. Runs until the
// process exits.
func (r *OAuthRegistry) RunRefresher() {
	t := time.NewTicker(oauthRefreshInterval)
	defer t.Stop()
	// Sweep before the first tick: every credential rehydrated from the
	// credentials table arrives with whatever expiry it had when the
	// gateway last ran, so boot is exactly when the most tokens are
	// stale and the reported expiry furthest from the truth.
	for {
		r.refreshExpiring(time.Now())
		<-t.C
	}
}

// refreshExpiring renews every credential that has entered the reuse
// source's early-expiry window, one goroutine per credential so a
// wedged provider delays only its own.
//
// The provider sees at most one in-flight refresh per credential: the
// reuse source serialises concurrent callers behind its own mutex, and
// the claim below keeps successive ticks from queueing goroutines there.
// Credentials latched terminal, still inside their backoff, holding no
// refresh token, or not yet near expiry are skipped — which is why a
// revoked refresh token costs one provider call rather than one per
// sweep.
func (r *OAuthRegistry) refreshExpiring(now time.Time) {
	r.mu.RLock()
	states := make([]*oauthState, 0, len(r.states))
	for _, s := range r.states {
		states = append(states, s)
	}
	r.mu.RUnlock()
	for _, s := range states {
		src, ok := s.claimRefresh(now)
		if !ok {
			continue
		}
		go func() {
			defer s.releaseRefresh()
			// Errors are recorded by persistingSource; nothing here
			// waits on the result.
			_, _ = src.Token()
		}()
	}
}

// claimRefresh decides whether the background refresher should renew
// this credential now and, if so, hands back the source to renew it
// through while marking the attempt in flight.
func (s *oauthState) claimRefresh(now time.Time) (oauth2.TokenSource, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.refreshing, s.source == nil, s.current == nil:
		return nil, false
	case s.refresh == refreshTerminal:
		// Asking again would present the provider with the identical
		// request. The two things that do change the answer clear the
		// latch themselves: a new authorisation flow through setToken,
		// and a request-path refresh that unexpectedly succeeds.
		return nil, false
	case s.current.RefreshToken == "":
		return nil, false
	case now.Before(s.retryAfter):
		return nil, false
	case s.current.Expiry.IsZero():
		// No stated lifetime: nothing to renew ahead of.
		return nil, false
	case s.current.Expiry.After(now.Add(oauthReuseEarlyExpiry)):
		// Outside the reuse source's window a Token() call is answered
		// from its cache and would renew nothing.
		return nil, false
	}
	s.refreshing = true
	return s.source, true
}

func (s *oauthState) releaseRefresh() {
	s.mu.Lock()
	s.refreshing = false
	s.mu.Unlock()
}

// retire supersedes whatever generation the state is on, so a refresh
// still in flight against it settles into nothing: no verdict recorded,
// no row written.
func (s *oauthState) retire() {
	s.mu.Lock()
	s.gen++
	s.mu.Unlock()
}

// sameFlowConfig reports whether two states resolve to the same OAuth
// client and token endpoint. A remembered rejection of the client or the
// scope says nothing about a credential whose operator has since
// corrected one of them in the config.
func sameFlowConfig(a, b *oauth2.Config) bool {
	return a.ClientID == b.ClientID &&
		a.ClientSecret == b.ClientSecret &&
		a.Endpoint.TokenURL == b.Endpoint.TokenURL &&
		slices.Equal(a.Scopes, b.Scopes)
}

// inheritRefreshState copies prev's remembered refresh verdict onto s,
// but only when the verdict still describes what s will present to the
// provider: the same access and refresh token, and the same client and
// token endpoint to present them to. Anything else means the credential
// was re-authorised, refreshed, or reconfigured since, and the old
// verdict says nothing about the new attempt.
func (s *oauthState) inheritRefreshState(prev *oauthState, tok *oauth2.Token) {
	prev.mu.Lock()
	same := prev.current != nil &&
		prev.current.AccessToken == tok.AccessToken &&
		prev.current.RefreshToken == tok.RefreshToken &&
		sameFlowConfig(prev.cfg, s.cfg)
	state, reason, retryAfter, failures := prev.refresh, prev.refreshReason, prev.retryAfter, prev.failures
	prev.mu.Unlock()
	if !same {
		return
	}
	s.mu.Lock()
	s.refresh = state
	s.refreshReason = reason
	s.retryAfter = retryAfter
	s.failures = failures
	s.mu.Unlock()
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
	s, ok := r.states[id]
	if !ok {
		r.mu.Unlock()
		return
	}
	delete(r.states, id)
	r.mu.Unlock()

	// Retire the generation before the DELETE, under the same lock the
	// row writes take: a refresh already in flight either wrote before
	// the DELETE removes its row, or finds its generation superseded and
	// writes nothing. Either way it cannot re-insert the credential this
	// call is removing.
	s.retire()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if r.db != nil {
		_, _ = r.db.Exec("DELETE FROM credentials WHERE id=?", id)
	}
}

// Set stores tokens captured externally (browser auth flow callback).
func (r *OAuthRegistry) Set(ctx context.Context, id string, tok *oauth2.Token) error {
	return r.SetWithClient(ctx, id, tok, "")
}

// SetWithClient is Set + a dynamically registered client_id. Pass empty
// clientID for static-ClientID flows; pass the per-credential client_id
// for RFC 7591 dynamic registration flows (notion_mcp/dynamic_mcp). The
// clientID is stamped onto the in-memory state and persisted alongside the tokens so
// refresh continues to work after restart.
//
// The registry lock covers only the state lookup. Both slow steps — the
// token write and the userinfo round-trip — run outside it, so a wedged
// provider or a contended sqlite write cannot hold up Status, Inject or
// Revoke on any other credential.
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
	r.mu.Unlock()

	if clientID != "" {
		s.mu.Lock()
		s.clientID = clientID
		s.cfg.ClientID = clientID
		s.mu.Unlock()
	}
	gen := s.setToken(tok)

	// Network call is best-effort and decorative; failure is logged
	// inside fetchOAuthProfile and the credential row stays usable
	// without display_name/avatar_url populated.
	name, avatar := fetchOAuthProfile(ctx, id, tok.AccessToken)
	if name != "" || avatar != "" {
		s.persistProfile(gen, name, avatar)
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
		flow:   it.Flow,
		db:     db,
	}
}

// setToken installs tok as the credential's current token, builds the
// source that refreshes it, and returns the generation both belong to.
func (s *oauthState) setToken(tok *oauth2.Token) uint64 {
	// The sources below keep the config for the life of the source, and a
	// connect on a dynamic-registration flow rewrites s.cfg.ClientID.
	// s.mu guards that field, so the snapshot is taken under it, and the
	// sources are handed the copy — neither this read nor a refresh
	// already in flight can observe the field mid-write.
	s.mu.Lock()
	cfg := *s.cfg
	s.mu.Unlock()
	var base oauth2.TokenSource
	switch {
	case isAnthropicTokenURL(cfg.Endpoint.TokenURL):
		// Anthropic's token endpoint requires a JSON body for refresh
		// (returns "Invalid request format" otherwise). Stdlib oauth2
		// only sends form-urlencoded.
		base = &anthropicRefreshSource{cfg: &cfg, current: tok}
	case s.flow == "dynamic_mcp" || s.flow == "notion_mcp":
		// Hosted MCP token endpoints refresh via form-urlencoded body and
		// expect the dynamically registered client_id (no static
		// ClientSecret — PKCE-only public client). The flow, not the
		// provider hostname, selects this behavior so external credential
		// plugins can supply their own MCP OAuth endpoints.
		base = &dynamicMCPRefreshSource{cfg: &cfg, current: tok}
	default:
		// Bound the round trip the way the two sources above bound
		// theirs. oauth2's own source takes its HTTP client from the
		// context, and an unbounded one pins the reuse source's mutex —
		// and every caller queued on it — for as long as a wedged
		// provider holds the connection open.
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient,
			&http.Client{Timeout: oauthUpstreamTimeout})
		base = cfg.TokenSource(ctx, tok)
	}
	// A token arriving here is either freshly minted by a completed
	// authorisation flow or rehydrated from the credentials table, so
	// whatever the previous one's refreshes concluded no longer applies:
	// this is the path that clears a remembered "needs re-authorisation"
	// after an operator reconnects.
	s.mu.Lock()
	s.gen++
	s.source = oauth2.ReuseTokenSourceWithExpiry(
		tok,
		&persistingSource{base: base, state: s, gen: s.gen},
		oauthReuseEarlyExpiry,
	)
	s.current = tok
	s.refresh = refreshUnknown
	s.refreshReason = ""
	s.retryAfter = time.Time{}
	s.failures = 0
	gen := s.gen
	s.mu.Unlock()
	s.persist(gen, tok)
	return gen
}

// tokenSource returns the credential's token source, or nil when no
// token has been captured yet. Read under the state lock because
// setToken replaces the source on every completed flow and on every
// policy reload's rehydrate.
func (s *oauthState) tokenSource() oauth2.TokenSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.source
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
		return nil, fmt.Errorf("anthropic refresh: %w", errNoRefreshToken)
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
		return nil, fmt.Errorf("anthropic refresh %d: %w", resp.StatusCode, retrieveError(resp, respBytes))
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
	if tr.AccessToken == "" {
		// A reply carrying no access_token is a failure whatever it was
		// statused with. Without this the empty string became the
		// credential's access token: every injection stamped a bearer
		// with nothing behind it, and the refresh verdict read as a
		// success.
		return nil, fmt.Errorf("anthropic refresh %d: %w", resp.StatusCode, retrieveError(resp, respBytes))
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

// persistingSource is the single funnel every refresh in the process
// goes through — request-path injection, the SecretStore bridge and the
// background refresher all reach the provider through it. It is
// therefore also where the refresh verdict the status path reports is
// recorded.
type persistingSource struct {
	base  oauth2.TokenSource
	state *oauthState
	// gen is the credential's token generation this source refreshes
	// for. A result that settles after the credential moved on is
	// reported to the caller but not recorded.
	gen uint64
}

func (p *persistingSource) Token() (*oauth2.Token, error) {
	t, err := p.base.Token()
	if err != nil {
		p.state.noteRefreshFailure(p.gen, err)
		return nil, err
	}
	p.state.noteRefreshSuccess(p.gen, t)
	return t, nil
}

// noteRefreshSuccess records a token the provider accepted us for and
// persists it. It clears any remembered failure, including a terminal
// one: a credential that hands back a token is connected whatever the
// last attempt concluded.
func (s *oauthState) noteRefreshSuccess(gen uint64, t *oauth2.Token) {
	s.mu.Lock()
	if gen != s.gen {
		s.mu.Unlock()
		return
	}
	changed := s.refresh != refreshOK
	s.current = t
	s.refresh = refreshOK
	s.refreshReason = ""
	s.retryAfter = time.Time{}
	s.failures = 0
	s.mu.Unlock()
	if changed {
		log.Printf("oauth %q: refresh ok, token valid until %s", s.id, expiryLabel(t))
	}
	s.persist(gen, t)
}

// noteRefreshFailure classifies err and remembers the verdict. Only a
// grant-level rejection latches the credential into "needs
// re-authorisation"; every other failure stays retryable and leaves the
// credential reading connected on its still-persisted token, so a
// provider blip cannot park a healthy credential.
//
// The failure is logged on a verdict change only, so a credential the
// provider keeps rejecting costs one line rather than one per attempt.
func (s *oauthState) noteRefreshFailure(gen uint64, err error) {
	state, reason := classifyRefreshError(err)
	s.mu.Lock()
	if gen != s.gen {
		s.mu.Unlock()
		return
	}
	// A credential holding no refresh token cannot be retried into
	// health whatever the provider answered, and the stdlib source
	// reports that condition as an unstructured error, so the verdict is
	// taken from the state rather than from the message.
	if s.current != nil && s.current.RefreshToken == "" {
		state, reason = refreshTerminal, errNoRefreshToken.Error()
	}
	changed := s.refresh != state || s.refreshReason != reason
	s.refresh = state
	s.refreshReason = reason
	if state == refreshTransient {
		s.failures++
		s.retryAfter = time.Now().Add(refreshBackoff(s.failures))
	}
	s.mu.Unlock()
	if changed {
		log.Printf("oauth %q: refresh failed (%s): %s", s.id, reason, refreshLogDetail(err))
	}
}

// expiryLabel renders a token's expiry for the log without touching the
// token bytes. Tokens with no stated lifetime read as "never".
func expiryLabel(t *oauth2.Token) string {
	if t == nil || t.Expiry.IsZero() {
		return "never"
	}
	return t.Expiry.UTC().Format(time.RFC3339)
}

// refreshBackoff is the delay before the background refresher retries a
// credential whose refresh failed transiently, doubling per consecutive
// failure up to a ceiling. Bounded so a provider outage across many
// credentials settles into a slow heartbeat instead of one attempt per
// credential per tick.
func refreshBackoff(failures int) time.Duration {
	d := oauthRefreshBackoffBase
	for i := 1; i < failures && d < oauthRefreshBackoffMax; i++ {
		d *= 2
	}
	return min(d, oauthRefreshBackoffMax)
}

// persistProfile updates the human-identity columns for this
// credential's row. Called after fetchOAuthProfile populates them
// post-exchange. UPDATE-only — relies on persist() having INSERTed
// the row first. Best-effort: a failed write surfaces only as
// missing avatar on the dashboard.
//
// Carries the generation for the same reason persist does: two
// overlapping connect flows must not leave the row holding one
// identity and memory the other, and a userinfo fetch that returns
// after the credential was revoked or replaced must not write to the
// row that took its place.
func (s *oauthState) persistProfile(gen uint64, displayName, avatarURL string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	db, id, stale := s.db, s.id, gen != s.gen
	if !stale {
		s.displayName = displayName
		s.avatarURL = avatarURL
	}
	s.mu.Unlock()
	if db == nil || stale {
		return
	}
	_, _ = db.Exec(`
		UPDATE credentials
		   SET display_name = ?, avatar_url = ?
		 WHERE id = ?
	`, displayName, avatarURL, id)
}

// persist writes the token to the credentials table. The state lock is
// held only long enough to read the fields the write needs, never across
// the write itself: the status path waits on that lock, and the whole
// point of reporting from memory is that it waits on nothing slow.
//
// A write for a superseded generation is dropped rather than applied,
// so a refresh that settles after the credential was re-authorised or
// revoked cannot overwrite the row with the token it replaced. The
// generation is read inside writeMu, which is what makes that check
// decide the outcome rather than merely narrow the window: a write that
// passes it is already holding the lock the superseding write has to
// take, so the later generation always lands last.
func (s *oauthState) persist(gen uint64, t *oauth2.Token) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	db, id, clientID, stale := s.db, s.id, s.clientID, gen != s.gen
	s.mu.Unlock()
	if db == nil || stale {
		return
	}
	var expiryNs int64
	if !t.Expiry.IsZero() {
		expiryNs = t.Expiry.UnixNano()
	}
	_, _ = db.Exec(`
		INSERT INTO credentials (id, access_token, token_type, refresh_token, expiry_ns, updated_ns, client_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			access_token  = excluded.access_token,
			token_type    = excluded.token_type,
			refresh_token = excluded.refresh_token,
			expiry_ns     = excluded.expiry_ns,
			updated_ns    = excluded.updated_ns,
			client_id     = excluded.client_id
	`, id, t.AccessToken, t.TokenType, t.RefreshToken, expiryNs, time.Now().UnixNano(), nullableString(clientID))
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
		it := r.Integration(id)
		if it == nil {
			continue
		}
		s := newState(it, r.db)
		// Restore the dynamically-registered client_id BEFORE setToken
		// so dynamic MCP refresh sources pick it up via s.cfg.
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
		// setToken writes through to the credentials table, so the state
		// is built before the registry lock is taken: holding that lock
		// across a DB write would put the status path behind sqlite,
		// which is the latency this whole path exists to avoid.
		s.setToken(tok)
		// setToken starts the rebuilt state with no remembered refresh
		// verdict. Carry the old one over when the row holds the same
		// token the replaced state did, so a policy reload doesn't send
		// the gateway back to the provider for every credential whose
		// grant it already knows is revoked. A re-authorisation writes a
		// new token, so it does not match and does not carry over.
		if prev := r.get(id); prev != nil {
			s.inheritRefreshState(prev, tok)
		}
		s.displayName = displayName.String
		s.avatarURL = avatar.String
		r.putState(id, s)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("oauth registry: iterate credentials: %w", err)
	}
	return nil
}

// putState installs a rehydrated credential state. Every other reader
// of r.states goes through the registry lock, and a policy reload runs
// concurrently with live dashboard and request traffic, so the install
// does too.
func (r *OAuthRegistry) putState(id string, s *oauthState) {
	r.mu.Lock()
	prev := r.states[id]
	r.states[id] = s
	r.mu.Unlock()
	// The displaced state may still have a refresh in flight. Retire it:
	// the row is now the installed state's to write, and a late result
	// from the state that no longer backs this credential must not land
	// on it.
	if prev != nil && prev != s {
		prev.retire()
	}
}

type oauthSession struct {
	verifier string
	state    string
	cfg      *oauth2.Config
	id       string
	created  time.Time
	// dynClientID is the RFC 7591 client_id this session registered at
	// start time (dynamic MCP flows). Empty for static-ClientID flows.
	// Stamped onto the credential row at exchange time so refresh can
	// replay it.
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
	if flow.Flow == "notion_mcp" || flow.Flow == "dynamic_mcp" {
		w.startDynamicMCPFlow(rw, r, id, flow)
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

// startDynamicMCPFlow drives auth-code OAuth flows with RFC 7591
// dynamic client registration. Plugins may pin a provider-accepted
// redirect URI (e.g. a localhost loopback URI for providers that reject
// the dashboard's redirect); otherwise we register the dashboard's own
// /oauth/callback page, which auto-exchanges via /api/oauth/exchange
// when it loads, with copy-paste from the URL bar as a fallback.
func (w *webMux) startDynamicMCPFlow(rw http.ResponseWriter, r *http.Request, id string, flow *OAuthIntegration) {
	redirectURI := strings.TrimSpace(flow.OAuth.RedirectURI)
	if redirectURI == "" {
		redirectURI = w.dashboardRedirectURI(r, "/oauth/callback")
	}
	clientID, err := registerOAuthClient(r.Context(), flow.OAuth.RegisterURL, redirectURI, flow.OAuth.Scopes)
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
		Endpoint: oauth2.Endpoint{
			AuthURL:   flow.OAuth.AuthURL,
			TokenURL:  flow.OAuth.TokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
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
func registerOAuthClient(ctx context.Context, registerURL, redirectURI string, scopes []string) (string, error) {
	bodyMap := map[string]any{
		"client_name":                "clawpatrol",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	if len(scopes) > 0 {
		bodyMap["scope"] = strings.Join(scopes, " ")
	}
	body, _ := json.Marshal(bodyMap)
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

func normalizeOAuthExchangeInput(input string) string {
	code, _ := parseOAuthExchangeInput(input)
	return code
}

func parseOAuthExchangeInput(input string) (code, oauthErr string) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", ""
	}

	// Operators often paste the whole callback URL after providers
	// redirect to a loopback URI (for example
	// localhost:8900/callback?code=...&state=...) or just its raw query
	// string, with parameters in any order. Try query-shaped inputs
	// first, then fall back to a bare opaque code.
	if code, oauthErr, ok := parseOAuthRawQuery(s); ok {
		return code, oauthErr
	}
	if strings.Contains(s, "?") {
		candidate := s
		if !strings.Contains(candidate, "://") && !strings.HasPrefix(candidate, "/") {
			// Browsers omit the scheme when the URL is copied from the
			// address bar; url.Parse needs one to find the query.
			candidate = "http://" + candidate
		}
		if u, err := url.Parse(candidate); err == nil {
			if code, oauthErr := oauthCodeOrError(u.Query()); code != "" || oauthErr != "" {
				return code, oauthErr
			}
		}
	}

	// Otherwise treat the input as a bare code. Preserve '&' and '=' because
	// opaque provider codes may contain them; only strip fragment/query suffixes.
	if i := strings.IndexAny(s, "#?"); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s), ""
}

func parseOAuthRawQuery(input string) (code, oauthErr string, ok bool) {
	raw := strings.TrimPrefix(input, "?")
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return "", "", false
	}
	code, oauthErr = oauthCodeOrError(vals)
	return code, oauthErr, code != "" || oauthErr != ""
}

func oauthCodeOrError(vals url.Values) (code, oauthErr string) {
	if code := strings.TrimSpace(vals.Get("code")); code != "" {
		return code, ""
	}
	if errCode := strings.TrimSpace(vals.Get("error")); errCode != "" {
		if desc := strings.TrimSpace(vals.Get("error_description")); desc != "" {
			return "", fmt.Sprintf("%s: %s", errCode, desc)
		}
		return "", errCode
	}
	return "", ""
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
	var oauthErr string
	body.Code, oauthErr = parseOAuthExchangeInput(body.Code)
	if oauthErr != "" {
		http.Error(rw, "oauth error: "+oauthErr, 400)
		return
	}
	if body.Code == "" || body.State == "" {
		http.Error(rw, "missing code/state", 400)
		return
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

// dynamicMCPRefreshSource refreshes hosted MCP OAuth tokens via the
// form-urlencoded body the spec mandates. The client_id is read from
// cfg.ClientID, which the registry restores from the persisted
// credentials.client_id column on boot. Stateful: holds the current
// token (with refresh_token) and rotates it on each refresh.
type dynamicMCPRefreshSource struct {
	mu      sync.Mutex
	cfg     *oauth2.Config
	current *oauth2.Token
}

func (d *dynamicMCPRefreshSource) Token() (*oauth2.Token, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.current.Valid() {
		return d.current, nil
	}
	if d.current.RefreshToken == "" {
		return nil, fmt.Errorf("dynamic_mcp refresh: %w", errNoRefreshToken)
	}
	if d.cfg.ClientID == "" {
		return nil, fmt.Errorf("dynamic_mcp refresh: %w", errNoDynamicClientID)
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", d.current.RefreshToken)
	form.Set("client_id", d.cfg.ClientID)
	// See anthropicRefreshSource.Token: oauth2 has no ctx on Token(),
	// so we bound the upstream round-trip here so d.mu stays available
	// even if the MCP token endpoint hangs.
	ctx, cancel := context.WithTimeout(context.Background(), oauthUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", d.cfg.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("dynamic_mcp refresh: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dynamic_mcp refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("dynamic_mcp refresh %d: %w", resp.StatusCode, retrieveError(resp, respBytes))
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
	if tr.AccessToken == "" {
		// A reply carrying no access_token is a failure whatever it was
		// statused with. Without this the empty string became the
		// credential's access token: every injection stamped a bearer
		// with nothing behind it, and the refresh verdict read as a
		// success.
		return nil, fmt.Errorf("dynamic_mcp refresh %d: %w", resp.StatusCode, retrieveError(resp, respBytes))
	}
	t := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if t.RefreshToken == "" {
		t.RefreshToken = d.current.RefreshToken
	}
	if tr.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	d.current = t
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
// (notion_mcp/dynamic_mcp). The inline JS extracts ?code & ?state, POSTs them to
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
