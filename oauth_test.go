package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

// Anthropic refresh sends grant_type=refresh_token with a JSON body —
// stdlib oauth2 would form-urlencode and Anthropic answers "Invalid
// request format". Closes the unchecked test-plan item from #82.
func TestAnthropicRefreshSendsJSON(t *testing.T) {
	var gotCT string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotCT = r.Header.Get("Content-Type")
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "new-access",
				"refresh_token": "new-refresh",
				"token_type":    "bearer",
				"expires_in":    3600,
			})
		}))
	defer srv.Close()

	src := &anthropicRefreshSource{
		cfg: &oauth2.Config{
			ClientID: "cid",
			Endpoint: oauth2.Endpoint{
				TokenURL: srv.URL + "/anthropic.com/v1/oauth/token",
			},
		},
		current: &oauth2.Token{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			Expiry:       time.Now().Add(-time.Minute),
		},
	}

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody["grant_type"] != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", gotBody["grant_type"])
	}
	if gotBody["refresh_token"] != "old-refresh" {
		t.Errorf("refresh_token = %q", gotBody["refresh_token"])
	}
	if gotBody["client_id"] != "cid" {
		t.Errorf("client_id = %q", gotBody["client_id"])
	}
	if tok.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q, want new-access", tok.AccessToken)
	}
	if tok.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken = %q, want new-refresh", tok.RefreshToken)
	}
	if !tok.Expiry.After(time.Now().Add(50 * time.Minute)) {
		t.Errorf("Expiry = %v, want roughly +1h", tok.Expiry)
	}
}

// Anthropic's refresh response sometimes omits a rotated refresh
// token; the source must retain the existing one rather than dropping
// it (which would break the next refresh).
func TestAnthropicRefreshKeepsExistingRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "new-access",
				"token_type":   "bearer",
				"expires_in":   3600,
			})
		}))
	defer srv.Close()

	src := &anthropicRefreshSource{
		cfg: &oauth2.Config{
			ClientID: "cid",
			Endpoint: oauth2.Endpoint{
				TokenURL: srv.URL + "/anthropic.com/v1/oauth/token",
			},
		},
		current: &oauth2.Token{
			AccessToken:  "old-access",
			RefreshToken: "keep-me",
			Expiry:       time.Now().Add(-time.Minute),
		},
	}

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tok.RefreshToken != "keep-me" {
		t.Errorf("RefreshToken = %q, want keep-me", tok.RefreshToken)
	}
}

// A still-valid token must not hit the server — the source caches.
func TestAnthropicRefreshSkipsServerWhenCurrentValid(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(500)
		}))
	defer srv.Close()

	want := &oauth2.Token{
		AccessToken:  "still-good",
		RefreshToken: "rt",
		Expiry:       time.Now().Add(time.Hour),
	}
	src := &anthropicRefreshSource{
		cfg: &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				TokenURL: srv.URL + "/anthropic.com/v1/oauth/token",
			},
		},
		current: want,
	}

	got, err := src.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got.AccessToken != "still-good" {
		t.Errorf("AccessToken = %q", got.AccessToken)
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("server hit %d times, want 0", n)
	}
}

// An error response surfaces as a Go error rather than a zero token —
// otherwise the upstream call quietly retries with an empty bearer.
func TestAnthropicRefreshErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
		}))
	defer srv.Close()

	src := &anthropicRefreshSource{
		cfg: &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				TokenURL: srv.URL + "/anthropic.com/v1/oauth/token",
			},
		},
		current: &oauth2.Token{
			RefreshToken: "rt",
			Expiry:       time.Now().Add(-time.Minute),
		},
	}

	if _, err := src.Token(); err == nil {
		t.Fatal("Token: expected error, got nil")
	}
}

// setToken must wire an Anthropic token endpoint through the JSON
// refresh source — the URL-based dispatch is the whole point of #82.
func TestSetTokenSelectsAnthropicSourceByURL(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotCT = r.Header.Get("Content-Type")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fresh",
				"token_type":   "bearer",
				"expires_in":   3600,
			})
		}))
	defer srv.Close()

	st := &oauthState{
		cfg: &oauth2.Config{
			ClientID: "cid",
			Endpoint: oauth2.Endpoint{
				TokenURL: srv.URL + "/anthropic.com/v1/oauth/token",
			},
		},
	}
	st.setToken(&oauth2.Token{
		AccessToken:  "stale",
		RefreshToken: "rt",
		Expiry:       time.Now().Add(-time.Hour),
	})

	tok, err := st.source.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != "fresh" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
}

// A non-Anthropic token URL must keep using the stdlib (form-urlencoded)
// refresh — otherwise generic OAuth providers regress.
func TestSetTokenNonAnthropicUsesStdlibRefresh(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotCT = r.Header.Get("Content-Type")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fresh",
				"token_type":   "bearer",
				"expires_in":   3600,
			})
		}))
	defer srv.Close()

	st := &oauthState{
		cfg: &oauth2.Config{
			ClientID: "cid",
			Endpoint: oauth2.Endpoint{
				TokenURL: srv.URL + "/oauth/token",
			},
		},
	}
	st.setToken(&oauth2.Token{
		AccessToken:  "stale",
		RefreshToken: "rt",
		Expiry:       time.Now().Add(-time.Hour),
	})

	if _, err := st.source.Token(); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want form-urlencoded", gotCT)
	}
}
