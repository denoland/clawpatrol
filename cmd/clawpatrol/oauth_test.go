package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestExchangeAnthropicSendsJSON(t *testing.T) {
	var gotCT string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotCT = r.Header.Get("Content-Type")
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok",
				"token_type":   "bearer",
				"expires_in":   3600,
			})
		}))
	defer srv.Close()

	sess := &oauthSession{
		verifier: "v",
		state:    "s",
		cfg: &oauth2.Config{
			ClientID: "cid",
			Endpoint: oauth2.Endpoint{
				TokenURL: srv.URL + "/v1/oauth/token",
			},
			RedirectURL: "https://example.com/cb",
		},
	}
	// Patch the URL to include anthropic.com so the
	// dispatch picks the JSON path.
	sess.cfg.Endpoint.TokenURL =
		srv.URL + "/anthropic.com/v1/oauth/token"

	tok, err := exchangeOAuthCode(
		context.Background(), sess, "code", "state",
	)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken != "tok" {
		t.Fatalf("got token %q", tok.AccessToken)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json",
			gotCT)
	}
	if gotBody["grant_type"] != "authorization_code" {
		t.Errorf("grant_type = %q", gotBody["grant_type"])
	}
	if gotBody["code"] != "code" {
		t.Errorf("code = %q", gotBody["code"])
	}
}

func TestExchangeNonAnthropicUsesFormEncoded(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotCT = r.Header.Get("Content-Type")
			// oauth2 stdlib parses JSON responses fine, but
			// the key assertion is what Content-Type the
			// *request* used.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok",
				"token_type":   "bearer",
				"expires_in":   3600,
			})
		}))
	defer srv.Close()

	sess := &oauthSession{
		verifier: "v",
		state:    "s",
		cfg: &oauth2.Config{
			ClientID: "cid",
			Endpoint: oauth2.Endpoint{
				TokenURL: srv.URL + "/oauth/token",
			},
			RedirectURL: "https://example.com/cb",
		},
	}

	_, err := exchangeOAuthCode(
		context.Background(), sess, "code", "state",
	)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	want := "application/x-www-form-urlencoded"
	if gotCT != want {
		t.Errorf("Content-Type = %q, want %q", gotCT, want)
	}
}

// TestSetWithClientRoundTripConcurrentWithStatus pins that the
// registry mutex is released between Set's state mutation and the
// userinfo round-trip — without the fix, Set held r.mu through the
// entire HTTP round-trip, and any concurrent Status / Inject /
// Profile call on the registry would block behind it for the duration
// of a wedged provider. We don't exercise the slow-fetch arm directly
// (fetchOAuthProfile hardcodes api.github.com), but a tight Set/Status
// race surfaces any accidental re-introduction of the holding pattern.
func TestSetWithClientRoundTripConcurrentWithStatus(t *testing.T) {
	r := &OAuthRegistry{
		integrations: map[string]*OAuthIntegration{
			"custom": {ID: "custom", Type: "custom"},
		},
		states: map[string]*oauthState{},
	}

	tok := &oauth2.Token{
		AccessToken: "at",
		Expiry:      time.Now().Add(time.Hour),
	}
	if err := r.Set(context.Background(), "custom", tok); err != nil {
		t.Fatalf("seed Set: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if err := r.Set(context.Background(), "custom", tok); err != nil {
				t.Errorf("Set: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if connected, _ := r.Status("custom"); !connected {
				t.Errorf("Status returned not-connected mid-race")
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Set/Status race deadlocked or stalled")
	}
}

// TestSetWithClientUnknownIntegration verifies the error path stays
// wrapped with an oauth-registry prefix so logs identify the
// component when a stale credential id makes it through.
func TestSetWithClientUnknownIntegration(t *testing.T) {
	r := &OAuthRegistry{
		integrations: map[string]*OAuthIntegration{},
		states:       map[string]*oauthState{},
	}
	err := r.Set(context.Background(), "missing", &oauth2.Token{AccessToken: "x"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if want := "oauth registry"; !contains(err.Error(), want) {
		t.Errorf("error %q missing %q prefix", err.Error(), want)
	}
}

// TestFetchOAuthProfileRespectsContextCancellation pins that a wedged
// github userinfo endpoint can't outlive its caller's context. Before
// the fix this function used http.DefaultClient with no timeout, so a
// slow/hung provider would tie up the OAuth callback handler
// indefinitely.
func TestFetchOAuthProfileRespectsContextCancellation(t *testing.T) {
	// fetchOAuthProfile hardcodes https://api.github.com/user so we
	// can't redirect it to a local server. Instead, exercise the
	// context-cancellation path: an already-cancelled context must
	// short-circuit the call without making a network request.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	name, avatar := fetchOAuthProfile(ctx, "github", "tok")
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("fetchOAuthProfile with cancelled ctx took %v — should return promptly", d)
	}
	if name != "" || avatar != "" {
		t.Errorf("cancelled ctx returned profile data: name=%q avatar=%q", name, avatar)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
