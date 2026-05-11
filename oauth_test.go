package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
