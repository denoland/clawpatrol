package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func failOAuthTestHandler(t *testing.T, w http.ResponseWriter, format string, args ...any) {
	t.Helper()
	t.Errorf(format, args...)
	http.Error(w, "test handler assertion failed", http.StatusInternalServerError)
}

func TestNormalizeOAuthExchangeInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "raw code", in: "abc123", want: "abc123"},
		{name: "raw code with suffix", in: "abc123?ignored=1", want: "abc123"},
		{name: "https callback url", in: "https://gateway.example/oauth/callback?code=url-code&state=s", want: "url-code"},
		{name: "localhost callback without scheme", in: "localhost:8900/callback?code=loopback-code&state=s", want: "loopback-code"},
		{name: "absolute path callback", in: "/callback?code=path-code&state=s", want: "path-code"},
		{name: "raw query", in: "code=query-code&state=s", want: "query-code"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeOAuthExchangeInput(tt.in); got != tt.want {
				t.Fatalf("normalizeOAuthExchangeInput(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDynamicMCPRefreshSelectedByFlowForAnyTokenURL(t *testing.T) {
	var sawRefresh bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRefresh = true
		if got := r.Header.Get("Authorization"); got != "" {
			failOAuthTestHandler(t, w, "Authorization = %q, want no client-auth header", got)
			return
		}
		if err := r.ParseForm(); err != nil {
			failOAuthTestHandler(t, w, "parse form: %v", err)
			return
		}
		if got := r.Form.Get("client_id"); got != "external-dynamic-client" {
			failOAuthTestHandler(t, w, "client_id = %q, want external-dynamic-client", got)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	state := newState(&OAuthIntegration{
		ID:   "external-mcp",
		Flow: "dynamic_mcp",
		OAuth: OAuthConfig{
			ClientID: "external-dynamic-client",
			TokenURL: ts.URL,
		},
	}, nil)
	state.setToken(&oauth2.Token{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Hour),
	})

	tok, err := state.source.Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !sawRefresh {
		t.Fatalf("token server was not called")
	}
	if tok.AccessToken != "new-access" || tok.RefreshToken != "new-refresh" {
		t.Fatalf("token = %#v, want refreshed access/refresh", tok)
	}
}

func TestDynamicMCPRefreshSourceSendsClientID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			failOAuthTestHandler(t, w, "method = %s, want POST", r.Method)
			return
		}
		if err := r.ParseForm(); err != nil {
			failOAuthTestHandler(t, w, "parse form: %v", err)
			return
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			failOAuthTestHandler(t, w, "grant_type = %q, want refresh_token", got)
			return
		}
		if got := r.Form.Get("client_id"); got != "dyn-client" {
			failOAuthTestHandler(t, w, "client_id = %q, want dyn-client", got)
			return
		}
		if got := r.Form.Get("refresh_token"); got != "old-refresh" {
			failOAuthTestHandler(t, w, "refresh_token = %q, want old-refresh", got)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	src := &dynamicMCPRefreshSource{
		cfg: &oauth2.Config{
			ClientID: "dyn-client",
			Endpoint: oauth2.Endpoint{TokenURL: ts.URL},
		},
		current: &oauth2.Token{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			TokenType:    "Bearer",
			Expiry:       time.Now().Add(-time.Hour),
		},
	}

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tok.AccessToken != "new-access" || tok.RefreshToken != "new-refresh" {
		t.Fatalf("token = %#v, want refreshed access/refresh", tok)
	}
}

func TestStartDynamicMCPFlowUsesConfiguredRedirectURI(t *testing.T) {
	registerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got struct {
			RedirectURIs []string `json:"redirect_uris"`
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			failOAuthTestHandler(t, w, "decode register body: %v", err)
			return
		}
		if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "http://localhost:8900/callback" {
			failOAuthTestHandler(t, w, "redirect_uris = %#v, want localhost callback", got.RedirectURIs)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"client-loopback"}`))
	}))
	defer registerServer.Close()

	w := &webMux{sessions: map[string]*oauthSession{}}
	req := httptest.NewRequest(http.MethodPost, "http://100.66.146.96:8080/api/oauth/start", nil)
	rr := httptest.NewRecorder()
	w.startDynamicMCPFlow(rr, req, "amplitude", &OAuthIntegration{
		OAuth: OAuthConfig{
			AuthURL:     "https://mcp.eu.amplitude.com/authorize",
			TokenURL:    "https://mcp.eu.amplitude.com/token",
			RegisterURL: registerServer.URL,
			RedirectURI: "http://localhost:8900/callback",
			Scopes:      []string{"mcp:read", "offline_access"},
		},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body struct {
		AuthURL string `json:"auth_url"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.State == "" {
		t.Fatalf("state is empty")
	}
	authURL, err := url.Parse(body.AuthURL)
	if err != nil {
		t.Fatalf("parse auth_url: %v", err)
	}
	if got := authURL.Query().Get("redirect_uri"); got != "http://localhost:8900/callback" {
		t.Fatalf("auth_url redirect_uri = %q, want localhost callback", got)
	}
}

func TestRegisterOAuthClientIncludesScopes(t *testing.T) {
	var got map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			failOAuthTestHandler(t, w, "method = %s, want POST", r.Method)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			failOAuthTestHandler(t, w, "decode body: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"client-123"}`))
	}))
	defer ts.Close()

	clientID, err := registerOAuthClient(t.Context(), ts.URL, "https://gateway.example/oauth/callback", []string{"mcp:read", "offline_access"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if clientID != "client-123" {
		t.Fatalf("clientID = %q, want client-123", clientID)
	}
	if got["scope"] != "mcp:read offline_access" {
		t.Fatalf("scope = %#v, want joined scopes", got["scope"])
	}
	if got["token_endpoint_auth_method"] != "none" {
		t.Fatalf("token_endpoint_auth_method = %#v, want none", got["token_endpoint_auth_method"])
	}
}
