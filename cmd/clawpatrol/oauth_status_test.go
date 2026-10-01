package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/denoland/clawpatrol/internal/config"
)

// tokenEndpoint is a stand-in provider token endpoint that counts the
// refresh calls it receives and answers with whatever the test's
// current reply function returns.
type tokenEndpoint struct {
	srv   *httptest.Server
	calls atomic.Int64
	mu    sync.Mutex
	reply func(w http.ResponseWriter)
}

func newTokenEndpoint(t *testing.T, reply func(w http.ResponseWriter)) *tokenEndpoint {
	t.Helper()
	e := &tokenEndpoint{reply: reply}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		e.calls.Add(1)
		e.mu.Lock()
		fn := e.reply
		e.mu.Unlock()
		fn(w)
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *tokenEndpoint) setReply(fn func(w http.ResponseWriter)) {
	e.mu.Lock()
	e.reply = fn
	e.mu.Unlock()
}

func replyInvalidGrant(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`{"error":"invalid_grant",` +
		`"error_description":"refresh token rt-SECRET-material was revoked"}`))
}

func replyUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
}

func replyFreshToken(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"fresh-access","refresh_token":"fresh-refresh",` +
		`"token_type":"Bearer","expires_in":3600}`))
}

// seedStaleCredential builds a registry holding one credential whose
// access token has already expired but which still carries a refresh
// token — the shape every credential in the reporting bug is in by the
// time a dashboard load reaches it.
func seedStaleCredential(t *testing.T, e *tokenEndpoint) *OAuthRegistry {
	t.Helper()
	r := &OAuthRegistry{
		integrations: map[string]*OAuthIntegration{
			"custom": {
				ID:   "custom",
				Type: "custom",
				OAuth: config.OAuthConfig{
					ClientID: "cid",
					TokenURL: e.srv.URL + "/token",
				},
			},
		},
		states: map[string]*oauthState{},
	}
	tok := &oauth2.Token{
		AccessToken:  "stale-access",
		RefreshToken: "stale-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Hour),
	}
	if err := r.Set(context.Background(), "custom", tok); err != nil {
		t.Fatalf("seed Set: %v", err)
	}
	if n := e.calls.Load(); n != 0 {
		t.Fatalf("seeding made %d provider call(s)", n)
	}
	return r
}

// TestStatusMakesNoProviderCall is the latency fix: reporting on a
// credential whose access token is expired — and whose refresh token the
// provider has revoked — must not touch the network, before or after the
// failure is known. The refreshing Status paid a full round trip per
// stale credential on every dashboard load.
func TestStatusMakesNoProviderCall(t *testing.T) {
	e := newTokenEndpoint(t, replyInvalidGrant)
	r := seedStaleCredential(t, e)

	for i := 0; i < 5; i++ {
		if st := r.Status("custom"); !st.Connected {
			t.Fatalf("Status before any refresh attempt: %+v, want connected", st)
		}
	}
	if n := e.calls.Load(); n != 0 {
		t.Fatalf("Status made %d provider call(s), want 0", n)
	}

	// A request that genuinely needs the token still refreshes, and the
	// revocation surfaces there.
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token on a revoked credential: want error, got nil")
	}
	spent := e.calls.Load()
	if spent == 0 {
		t.Fatal("Token made no provider call on an expired token")
	}

	// Every later status load reads the remembered verdict.
	for i := 0; i < 5; i++ {
		st := r.Status("custom")
		if !st.NeedsReauth || st.Connected {
			t.Fatalf("Status after revocation: %+v, want needs-reauth and not connected", st)
		}
	}
	if n := e.calls.Load(); n != spent {
		t.Fatalf("status loads added %d provider call(s), want 0", n-spent)
	}
}

// TestStatusRemembersTerminalFailure pins the reported shape of a
// revoked grant: not connected, needs re-authorisation, and a reason
// naming the RFC 6749 code.
func TestStatusRemembersTerminalFailure(t *testing.T) {
	e := newTokenEndpoint(t, replyInvalidGrant)
	r := seedStaleCredential(t, e)
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from invalid_grant")
	}
	st := r.Status("custom")
	switch {
	case st.Connected:
		t.Error("Connected = true, want false for a revoked grant")
	case !st.NeedsReauth:
		t.Error("NeedsReauth = false, want true")
	case !strings.Contains(st.Reason, "invalid_grant"):
		t.Errorf("Reason = %q, want it to name invalid_grant", st.Reason)
	}
}

// TestStatusReasonCarriesNoTokenMaterial pins that the dashboard-facing
// reason never relays the provider's response body. The body the test
// provider sends echoes the refresh token back in error_description,
// which is exactly the leak a verbatim reason would produce.
func TestStatusReasonCarriesNoTokenMaterial(t *testing.T) {
	e := newTokenEndpoint(t, replyInvalidGrant)
	r := seedStaleCredential(t, e)
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from invalid_grant")
	}
	st := r.Status("custom")
	for _, leak := range []string{
		"SECRET", "stale-access", "stale-refresh", "was revoked", "error_description",
	} {
		if strings.Contains(st.Reason, leak) {
			t.Errorf("Reason %q contains %q", st.Reason, leak)
		}
	}
}

// TestSuccessfulRefreshClearsTerminalFailure covers the first way a
// remembered "needs re-authorisation" goes away: the provider starts
// honouring the refresh token again.
func TestSuccessfulRefreshClearsTerminalFailure(t *testing.T) {
	e := newTokenEndpoint(t, replyInvalidGrant)
	r := seedStaleCredential(t, e)
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from invalid_grant")
	}
	if st := r.Status("custom"); !st.NeedsReauth {
		t.Fatalf("Status = %+v, want the failure remembered", st)
	}

	e.setReply(replyFreshToken)
	tok, err := r.Token("custom")
	if err != nil {
		t.Fatalf("Token after the provider recovered: %v", err)
	}
	if tok != "fresh-access" {
		t.Fatalf("access token = %q, want fresh-access", tok)
	}
	st := r.Status("custom")
	switch {
	case !st.Connected:
		t.Error("Connected = false after a successful refresh")
	case st.NeedsReauth:
		t.Error("NeedsReauth stayed set after a successful refresh")
	case st.Reason != "":
		t.Errorf("Reason = %q, want it cleared", st.Reason)
	case !st.Expiry.After(time.Now()):
		t.Errorf("Expiry = %v, want the refreshed token's future expiry", st.Expiry)
	}
}

// TestReauthorisationClearsTerminalFailure covers the other way it goes
// away: the operator re-runs the OAuth flow, which lands on Set. Without
// this the card would read "needs re-authorisation" for the life of the
// process after the credential was already fixed.
func TestReauthorisationClearsTerminalFailure(t *testing.T) {
	e := newTokenEndpoint(t, replyInvalidGrant)
	r := seedStaleCredential(t, e)
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from invalid_grant")
	}
	if st := r.Status("custom"); !st.NeedsReauth {
		t.Fatalf("Status = %+v, want the failure remembered", st)
	}

	reauthorised := &oauth2.Token{
		AccessToken:  "reauth-access",
		RefreshToken: "reauth-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	if err := r.Set(context.Background(), "custom", reauthorised); err != nil {
		t.Fatalf("Set: %v", err)
	}
	st := r.Status("custom")
	switch {
	case !st.Connected:
		t.Error("Connected = false after re-authorisation")
	case st.NeedsReauth:
		t.Error("NeedsReauth stayed set after re-authorisation")
	case st.Reason != "":
		t.Errorf("Reason = %q, want it cleared", st.Reason)
	}
	// The re-authorised credential is a refresh candidate again rather
	// than one the background refresher skips forever.
	if _, ok := r.states["custom"].claimRefresh(time.Now().Add(2 * time.Hour)); !ok {
		t.Error("claimRefresh declined a re-authorised credential")
	}
}

// TestTransientFailureDoesNotLatch pins the other half of the
// classification: a provider that is merely unwell leaves the
// credential connected on the token it still holds, so an outage cannot
// present itself to the operator as a revoked grant.
func TestTransientFailureDoesNotLatch(t *testing.T) {
	e := newTokenEndpoint(t, replyUnavailable)
	r := seedStaleCredential(t, e)
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from a 503")
	}
	st := r.Status("custom")
	switch {
	case st.NeedsReauth:
		t.Error("NeedsReauth = true for a 503, want false — the grant was not rejected")
	case st.Connected:
		t.Error("Connected = true for an expired token the provider would not renew")
	case !strings.Contains(st.Reason, "temporarily_unavailable"):
		t.Errorf("Reason = %q, want it to name the transient code", st.Reason)
	}
	// Transient means retryable: the credential is still a refresh
	// candidate once its backoff elapses.
	s := r.states["custom"]
	if _, ok := s.claimRefresh(time.Now()); ok {
		t.Error("claimRefresh ignored the transient backoff")
	}
	if _, ok := s.claimRefresh(time.Now().Add(oauthRefreshBackoffMax + time.Minute)); !ok {
		t.Error("claimRefresh declined a transient credential after its backoff")
	}
}

// TestTransientFailureKeepsLiveTokenConnected pins the other side of the
// same split. A credential still inside its token's lifetime authorises
// requests regardless of what the last refresh did, so it reads
// connected with the failure named alongside — an outage mid-lifetime is
// not an outage the operator has to act on yet.
func TestTransientFailureKeepsLiveTokenConnected(t *testing.T) {
	e := newTokenEndpoint(t, replyUnavailable)
	r := seedStaleCredential(t, e)
	s := r.states["custom"]

	// A token that is inside the reuse source's early-expiry window, so
	// a refresh is attempted, but not yet past its own expiry.
	s.setToken(&oauth2.Token{
		AccessToken:  "live-access",
		RefreshToken: "live-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(oauthReuseEarlyExpiry / 2),
	})
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from a 503")
	}
	st := r.Status("custom")
	switch {
	case !st.Connected:
		t.Error("Connected = false for a token still inside its lifetime")
	case st.NeedsReauth:
		t.Error("NeedsReauth = true for a 503, want false")
	case !strings.Contains(st.Reason, "temporarily_unavailable"):
		t.Errorf("Reason = %q, want it to name the transient code", st.Reason)
	}
}

// TestBackgroundRefresherRetriesTransientNotTerminal pins the sweep's
// side of the same split: a transient failure comes back for another
// attempt, a terminal one never does. The second half is the cost fix —
// a revoked credential is asked once, not once per sweep.
func TestBackgroundRefresherRetriesTransientNotTerminal(t *testing.T) {
	e := newTokenEndpoint(t, replyUnavailable)
	r := seedStaleCredential(t, e)

	r.refreshExpiring(time.Now())
	first := waitForNewCalls(t, e, 0)
	if st := r.Status("custom"); st.NeedsReauth {
		t.Fatalf("Status = %+v, want no latch on a 503", st)
	}
	// Inside the backoff the sweep leaves it alone.
	r.refreshExpiring(time.Now())
	settle()
	if n := e.calls.Load(); n != first {
		t.Fatalf("sweep ignored the transient backoff: %d extra call(s)", n-first)
	}
	// Past the backoff it tries again.
	r.refreshExpiring(time.Now().Add(oauthRefreshBackoffMax + time.Minute))
	second := waitForNewCalls(t, e, first)

	e.setReply(replyInvalidGrant)
	r.refreshExpiring(time.Now().Add(2 * oauthRefreshBackoffMax))
	final := waitForNewCalls(t, e, second)
	if st := r.Status("custom"); !st.NeedsReauth {
		t.Fatalf("Status = %+v, want the terminal verdict remembered", st)
	}
	// However long the gateway runs, the revoked grant is not asked again.
	for i := 0; i < 10; i++ {
		r.refreshExpiring(time.Now().Add(time.Duration(i) * time.Hour))
	}
	settle()
	if n := e.calls.Load(); n != final {
		t.Fatalf("sweep made %d call(s) after the terminal verdict, want 0", n-final)
	}
}

// TestBackgroundRefresherRenewsBeforeExpiry pins that the sweep keeps
// the expiry Status reports live. Status no longer refreshes, so a token
// nobody renews would read as expired on the dashboard while still
// working for requests.
func TestBackgroundRefresherRenewsBeforeExpiry(t *testing.T) {
	e := newTokenEndpoint(t, replyFreshToken)
	r := seedStaleCredential(t, e)
	r.refreshExpiring(time.Now())
	renewed := waitForNewCalls(t, e, 0)
	deadline := time.Now().Add(2 * time.Second)
	for {
		st := r.Status("custom")
		if st.Connected && st.Expiry.After(time.Now()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Status = %+v, want a renewed future expiry", st)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A token comfortably inside its lifetime is left alone: a Token()
	// call there is answered from the reuse source's cache and would
	// renew nothing.
	r.refreshExpiring(time.Now())
	settle()
	if n := e.calls.Load(); n != renewed {
		t.Fatalf("sweep refreshed a token still inside its lifetime: %d extra call(s)", n-renewed)
	}
}

// TestConcurrentStatusDoesNotStampede pins that many simultaneous
// dashboard loads against a stale credential reach the provider zero
// times, and that a sweep running alongside them reaches it once.
func TestConcurrentStatusDoesNotStampede(t *testing.T) {
	slow := make(chan struct{})
	e := newTokenEndpoint(t, func(w http.ResponseWriter) {
		<-slow
		replyFreshToken(w)
	})
	r := seedStaleCredential(t, e)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = r.Status("custom")
				r.refreshExpiring(time.Now())
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(slow)
		t.Fatal("concurrent Status/sweep blocked on the provider")
	}
	if n := e.calls.Load(); n > 1 {
		t.Errorf("provider saw %d concurrent refresh(es), want at most 1", n)
	}
	close(slow)
}

// TestStatusReportsExpiredTokenWithNoRefreshToken pins the one dead
// state readable without asking the provider anything. The refreshing
// Status reported it as disconnected by failing the refresh; the
// reporting one has to reach the same verdict from the stored token.
func TestStatusReportsExpiredTokenWithNoRefreshToken(t *testing.T) {
	e := newTokenEndpoint(t, replyFreshToken)
	r := seedStaleCredential(t, e)
	expired := &oauth2.Token{
		AccessToken: "orphan-access",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-time.Hour),
	}
	if err := r.Set(context.Background(), "custom", expired); err != nil {
		t.Fatalf("Set: %v", err)
	}
	st := r.Status("custom")
	switch {
	case st.Connected:
		t.Error("Connected = true for an expired token with no refresh token")
	case !st.NeedsReauth:
		t.Error("NeedsReauth = false, want true")
	case !strings.Contains(st.Reason, "no refresh token"):
		t.Errorf("Reason = %q, want it to name the missing refresh token", st.Reason)
	}
	// Nothing to refresh with: the sweep leaves it alone.
	if _, ok := r.states["custom"].claimRefresh(time.Now()); ok {
		t.Error("claimRefresh accepted a credential with no refresh token")
	}
	if n := e.calls.Load(); n != 0 {
		t.Errorf("provider saw %d call(s), want 0", n)
	}
}

// TestLoadFromDBKeepsTerminalVerdictForSameToken pins that a policy
// reload — which rebuilds every credential state from the credentials
// table — does not forget a revoked grant and send the gateway back to
// the provider for it on the next sweep.
func TestLoadFromDBKeepsTerminalVerdictForSameToken(t *testing.T) {
	e := newTokenEndpoint(t, replyInvalidGrant)
	r := seedStaleCredential(t, e)
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from invalid_grant")
	}
	prev := r.states["custom"]
	same := &oauth2.Token{
		AccessToken:  "stale-access",
		RefreshToken: "stale-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Hour),
	}
	rebuilt := newState(r.integrations["custom"], nil)
	rebuilt.setToken(same)
	rebuilt.inheritRefreshState(prev, same)
	if rebuilt.refresh != refreshTerminal {
		t.Errorf("rebuilt state refresh = %v, want refreshTerminal", rebuilt.refresh)
	}

	// A token the operator re-authorised with is a different token, so
	// the verdict does not carry over onto it.
	fresh := &oauth2.Token{
		AccessToken:  "reauth-access",
		RefreshToken: "reauth-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	reloaded := newState(r.integrations["custom"], nil)
	reloaded.setToken(fresh)
	reloaded.inheritRefreshState(prev, fresh)
	if reloaded.refresh != refreshUnknown {
		t.Errorf("reloaded state refresh = %v, want refreshUnknown", reloaded.refresh)
	}
}

func TestClassifyRefreshError(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		want   refreshState
		reason string
	}{{
		name:   "revoked grant",
		err:    &oauth2.RetrieveError{Response: &http.Response{StatusCode: 400, Status: "400"}, ErrorCode: "invalid_grant"},
		want:   refreshTerminal,
		reason: "invalid_grant",
	}, {
		name:   "rejected client",
		err:    &oauth2.RetrieveError{Response: &http.Response{StatusCode: 401, Status: "401"}, ErrorCode: "invalid_client"},
		want:   refreshTerminal,
		reason: "invalid_client",
	}, {
		name:   "wrapped terminal",
		err:    fmt.Errorf("anthropic refresh 400: %w", &oauth2.RetrieveError{Response: &http.Response{StatusCode: 400, Status: "400"}, ErrorCode: "invalid_grant"}),
		want:   refreshTerminal,
		reason: "invalid_grant",
	}, {
		name:   "no refresh token",
		err:    fmt.Errorf("anthropic refresh: %w", errNoRefreshToken),
		want:   refreshTerminal,
		reason: "no refresh token",
	}, {
		name:   "unregistered dynamic client",
		err:    fmt.Errorf("dynamic_mcp refresh: %w", errNoDynamicClientID),
		want:   refreshTerminal,
		reason: "dynamic client registration",
	}, {
		name:   "provider overloaded",
		err:    &oauth2.RetrieveError{Response: &http.Response{StatusCode: 503, Status: "503"}, ErrorCode: "temporarily_unavailable"},
		want:   refreshTransient,
		reason: "temporarily_unavailable",
	}, {
		name:   "server error without a code",
		err:    &oauth2.RetrieveError{Response: &http.Response{StatusCode: 502, Status: "502"}},
		want:   refreshTransient,
		reason: "HTTP 502",
	}, {
		name:   "a grant rejection carried by a 5xx is not terminal",
		err:    &oauth2.RetrieveError{Response: &http.Response{StatusCode: 503, Status: "503"}, ErrorCode: "invalid_grant"},
		want:   refreshTransient,
		reason: "invalid_grant",
	}, {
		name:   "a grant rejection carried by a 429 is not terminal",
		err:    &oauth2.RetrieveError{Response: &http.Response{StatusCode: 429, Status: "429"}, ErrorCode: "invalid_grant"},
		want:   refreshTransient,
		reason: "invalid_grant",
	}, {
		name:   "malformed request is not assumed terminal",
		err:    &oauth2.RetrieveError{Response: &http.Response{StatusCode: 400, Status: "400"}, ErrorCode: "invalid_request"},
		want:   refreshTransient,
		reason: "invalid_request",
	}, {
		name:   "timeout",
		err:    fmt.Errorf("anthropic refresh: %w", context.DeadlineExceeded),
		want:   refreshTransient,
		reason: "timed out",
	}, {
		name:   "dns failure",
		err:    errors.New("Post \"https://idp.example/token\": dial tcp: lookup idp.example: no such host"),
		want:   refreshTransient,
		reason: "could not reach the provider",
	}, {
		name: "an unrecognised error code is not rendered",
		err: &oauth2.RetrieveError{
			Response:  &http.Response{StatusCode: 400, Status: "400"},
			ErrorCode: "<script>alert(1)</script> invalid_grant",
		},
		want:   refreshTransient,
		reason: "HTTP 400",
	}, {
		name: "a token-shaped error code is not rendered",
		err: &oauth2.RetrieveError{
			Response:  &http.Response{StatusCode: 400, Status: "400"},
			ErrorCode: "sk-ant-oat01.abc_def-123",
		},
		want:   refreshTransient,
		reason: "HTTP 400",
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := classifyRefreshError(tc.err)
			if got != tc.want {
				t.Errorf("state = %v, want %v", got, tc.want)
			}
			if !strings.Contains(reason, tc.reason) {
				t.Errorf("reason = %q, want it to contain %q", reason, tc.reason)
			}
		})
	}
}

func TestRefreshBackoffIsBounded(t *testing.T) {
	if got := refreshBackoff(1); got != oauthRefreshBackoffBase {
		t.Errorf("refreshBackoff(1) = %v, want %v", got, oauthRefreshBackoffBase)
	}
	if got := refreshBackoff(3); got != 4*oauthRefreshBackoffBase {
		t.Errorf("refreshBackoff(3) = %v, want %v", got, 4*oauthRefreshBackoffBase)
	}
	for _, n := range []int{10, 100, 1 << 20} {
		if got := refreshBackoff(n); got != oauthRefreshBackoffMax {
			t.Errorf("refreshBackoff(%d) = %v, want the %v ceiling", n, got, oauthRefreshBackoffMax)
		}
	}
}

// waitForNewCalls blocks until the provider has been called at least
// once beyond was, then returns the new count. Counts are compared in
// deltas rather than absolutes because oauth2 auto-detects the token
// endpoint's client-authentication style, so one logical refresh costs
// one or two HTTP requests depending on which style the provider
// accepts.
func waitForNewCalls(t *testing.T, e *tokenEndpoint, was int64) int64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for e.calls.Load() <= was {
		if time.Now().After(deadline) {
			t.Fatalf("provider saw no call beyond %d", was)
		}
		time.Sleep(2 * time.Millisecond)
	}
	settle()
	return e.calls.Load()
}

// settle gives any in-flight background refresh time to reach the test
// provider, so an assertion that no call was made is not just an
// assertion that none has arrived yet.
func settle() {
	time.Sleep(100 * time.Millisecond)
}

// TestRefreshFailureLogOmitsProviderText pins that the log line carries
// the classified reason and the HTTP status, not the provider's own
// words. The test provider echoes the refresh token back in
// error_description, which is what a verbatim log would publish into
// every bug report the journal is pasted into.
func TestRefreshFailureLogOmitsProviderText(t *testing.T) {
	var logged strings.Builder
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&logged)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	e := newTokenEndpoint(t, replyInvalidGrant)
	r := seedStaleCredential(t, e)
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from invalid_grant")
	}
	line := logged.String()
	if !strings.Contains(line, "invalid_grant") {
		t.Errorf("log %q does not name the rejection", line)
	}
	for _, leak := range []string{"SECRET", "stale-refresh", "was revoked", "error_description"} {
		if strings.Contains(line, leak) {
			t.Errorf("log %q contains %q", line, leak)
		}
	}
}

// TestSupersededRefreshResultIsIgnored pins the generation guard. A
// refresh in flight when the credential is re-authorised settles against
// a token the credential no longer holds: recording its verdict would
// re-latch a credential the operator just fixed, or overwrite the new
// token with the one it replaced.
func TestSupersededRefreshResultIsIgnored(t *testing.T) {
	s := &oauthState{id: "custom", cfg: &oauth2.Config{}}
	s.setToken(&oauth2.Token{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		Expiry:       time.Now().Add(-time.Hour),
	})
	superseded := s.gen

	// The operator re-runs the OAuth flow.
	s.setToken(&oauth2.Token{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		Expiry:       time.Now().Add(time.Hour),
	})

	s.noteRefreshFailure(superseded, &oauth2.RetrieveError{
		Response:  &http.Response{StatusCode: 400, Status: "400"},
		ErrorCode: "invalid_grant",
	})
	if s.refresh == refreshTerminal {
		t.Error("a superseded refresh re-latched the re-authorised credential")
	}
	s.noteRefreshSuccess(superseded, &oauth2.Token{AccessToken: "resurrected"})
	if s.current.AccessToken != "new-access" {
		t.Errorf("current access token = %q, want the re-authorised one", s.current.AccessToken)
	}
}

// TestRevokeRetiresInFlightRefresh pins that a refresh settling after a
// disconnect cannot write the credential back.
func TestRevokeRetiresInFlightRefresh(t *testing.T) {
	e := newTokenEndpoint(t, replyFreshToken)
	r := seedStaleCredential(t, e)
	s := r.states["custom"]
	inFlight := s.gen

	r.Revoke("custom")
	s.noteRefreshSuccess(inFlight, &oauth2.Token{
		AccessToken: "late-access",
		Expiry:      time.Now().Add(time.Hour),
	})
	if s.current.AccessToken == "late-access" {
		t.Error("a refresh that settled after Revoke rewrote the credential")
	}
	if st := r.Status("custom"); st.Connected {
		t.Errorf("Status after Revoke = %+v, want not connected", st)
	}
}

// TestRefreshRejectsReplyWithoutAccessToken pins that a 200 carrying no
// access_token is a failure. Treating it as success made the empty
// string the credential's access token and recorded the attempt as
// having worked.
func TestRefreshRejectsReplyWithoutAccessToken(t *testing.T) {
	e := newTokenEndpoint(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	})
	src := &anthropicRefreshSource{
		cfg: &oauth2.Config{
			ClientID: "cid",
			Endpoint: oauth2.Endpoint{TokenURL: e.srv.URL + "/anthropic.com/v1/oauth/token"},
		},
		current: &oauth2.Token{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			Expiry:       time.Now().Add(-time.Hour),
		},
	}
	tok, err := src.Token()
	if err == nil {
		t.Fatalf("Token = %+v, want an error for a reply with no access_token", tok)
	}
	// The refresh token is untouched, so a later attempt can still work.
	if src.current.RefreshToken != "old-refresh" {
		t.Errorf("refresh token = %q, want it preserved", src.current.RefreshToken)
	}
}

// TestLoadFromDBSkipsReprobingARevokedGrant drives the real rehydrate
// path — the one a policy reload runs — against a sqlite database, and
// pins that the verdict survives it. Without that, every config reload
// sent the gateway back to the provider for each credential whose grant
// it already knew was revoked.
func TestLoadFromDBSkipsReprobingARevokedGrant(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "clawpatrol.db"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	e := newTokenEndpoint(t, replyInvalidGrant)
	r := seedStaleCredential(t, e)
	r.db = db
	for _, s := range r.states {
		s.db = db
	}
	// Get the seeded token into the credentials table, then latch the
	// revocation.
	r.states["custom"].setToken(r.states["custom"].current)
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from invalid_grant")
	}
	if st := r.Status("custom"); !st.NeedsReauth {
		t.Fatalf("Status = %+v, want the revocation remembered", st)
	}
	spent := e.calls.Load()

	if err := r.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}
	if st := r.Status("custom"); !st.NeedsReauth {
		t.Errorf("Status after reload = %+v, want the revocation still remembered", st)
	}
	r.refreshExpiring(time.Now())
	settle()
	if n := e.calls.Load(); n != spent {
		t.Errorf("reload cost %d extra provider call(s), want 0", n-spent)
	}

	// A reload that finds a re-authorised token in the row does not carry
	// the verdict over onto it.
	reauthorised := &oauth2.Token{
		AccessToken:  "reauth-access",
		RefreshToken: "reauth-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	if err := r.Set(context.Background(), "custom", reauthorised); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := r.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}
	st := r.Status("custom")
	if st.NeedsReauth || !st.Connected {
		t.Errorf("Status after re-authorisation and reload = %+v, want connected", st)
	}
}

// TestReloadDoesNotInheritVerdictAcrossAConfigChange pins that a
// rejection of the client or the scope is not carried onto a credential
// whose operator has since corrected the config it was rejected for.
func TestReloadDoesNotInheritVerdictAcrossAConfigChange(t *testing.T) {
	e := newTokenEndpoint(t, replyInvalidGrant)
	r := seedStaleCredential(t, e)
	prev := r.states["custom"]
	if _, err := r.Token("custom"); err == nil {
		t.Fatal("Token: want error from invalid_grant")
	}

	tok := prev.current
	reconfigured := newState(&OAuthIntegration{
		ID:   "custom",
		Type: "custom",
		OAuth: config.OAuthConfig{
			ClientID: "corrected-cid",
			TokenURL: e.srv.URL + "/token",
		},
	}, nil)
	reconfigured.setToken(tok)
	reconfigured.inheritRefreshState(prev, tok)
	if reconfigured.refresh == refreshTerminal {
		t.Error("a corrected client id inherited the old rejection")
	}
}

// TestConcurrentSetWithClientIsRaceFree pins that the per-credential lock
// actually guards the flow config. Two connects completing for the same
// dynamic-registration credential — a double-clicked Connect button, the
// consent flow open in two tabs, a retried callback — have one writing
// s.cfg.ClientID while the other snapshots the config for the source it
// is about to build. Run under -race; without the snapshot taken under
// the lock the detector reports a write/read pair on s.cfg.
func TestConcurrentSetWithClientIsRaceFree(t *testing.T) {
	e := newTokenEndpoint(t, replyFreshToken)
	r := &OAuthRegistry{
		integrations: map[string]*OAuthIntegration{
			"mcp": {
				ID:   "mcp",
				Type: "custom",
				Flow: "dynamic_mcp",
				OAuth: config.OAuthConfig{
					TokenURL: e.srv.URL + "/token",
				},
			},
		},
		states: map[string]*oauthState{},
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				tok := &oauth2.Token{
					AccessToken:  fmt.Sprintf("access-%d-%d", i, j),
					RefreshToken: fmt.Sprintf("refresh-%d-%d", i, j),
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(time.Hour),
				}
				err := r.SetWithClient(context.Background(), "mcp", tok,
					fmt.Sprintf("dyn-client-%d-%d", i, j))
				if err != nil {
					t.Errorf("SetWithClient: %v", err)
					return
				}
				_ = r.Status("mcp")
				r.refreshExpiring(time.Now())
			}
		}(i)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent SetWithClient stalled")
	}

	// Whichever connect landed last, the credential is left coherent: the
	// client id the state reports is the one its config presents.
	s := r.states["mcp"]
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientID != s.cfg.ClientID {
		t.Errorf("clientID = %q but cfg.ClientID = %q", s.clientID, s.cfg.ClientID)
	}
}
