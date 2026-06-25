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
		{name: "raw opaque code with ampersand and equals", in: "abc=def&ghi=jkl", want: "abc=def&ghi=jkl"},
		{name: "https callback url", in: "https://gateway.example/oauth/callback?code=url-code&state=s", want: "url-code"},
		{name: "localhost callback without scheme", in: "localhost:8900/callback?code=loopback-code&state=s", want: "loopback-code"},
		{name: "absolute path callback", in: "/callback?code=path-code&state=s", want: "path-code"},
		{name: "raw query", in: "code=query-code&state=s", want: "query-code"},
		{name: "raw query with state first", in: "state=s&code=query-code", want: "query-code"},
		{name: "raw query with leading question mark", in: "?code=query-code&state=s", want: "query-code"},
		{name: "raw query with slash in code", in: "code=ab/cd&state=s", want: "ab/cd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeOAuthExchangeInput(tt.in); got != tt.want {
				t.Fatalf("normalizeOAuthExchangeInput(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseOAuthExchangeInputReportsCallbackError(t *testing.T) {
	code, oauthErr := parseOAuthExchangeInput("?error=access_denied&error_description=user+cancelled")
	if code != "" {
		t.Fatalf("code = %q, want empty", code)
	}
	if oauthErr != "access_denied: user cancelled" {
		t.Fatalf("oauthErr = %q, want callback error", oauthErr)
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

func TestDynamicMCPCodeExchangeSendsClientIDInParams(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			failOAuthTestHandler(t, w, "Authorization = %q, want no client-auth header", got)
			return
		}
		if err := r.ParseForm(); err != nil {
			failOAuthTestHandler(t, w, "parse form: %v", err)
			return
		}
		if got := r.Form.Get("grant_type"); got != "authorization_code" {
			failOAuthTestHandler(t, w, "grant_type = %q, want authorization_code", got)
			return
		}
		if got := r.Form.Get("client_id"); got != "dyn-client" {
			failOAuthTestHandler(t, w, "client_id = %q, want dyn-client", got)
			return
		}
		if got := r.Form.Get("code"); got != "auth-code" {
			failOAuthTestHandler(t, w, "code = %q, want auth-code", got)
			return
		}
		if got := r.Form.Get("code_verifier"); got != "verifier" {
			failOAuthTestHandler(t, w, "code_verifier = %q, want verifier", got)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	sess := &oauthSession{
		verifier: "verifier",
		state:    "state",
		cfg: &oauth2.Config{
			ClientID:    "dyn-client",
			RedirectURL: "http://localhost:8900/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL:  ts.URL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
	}
	tok, err := exchangeOAuthCode(t.Context(), sess, "auth-code", "state")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken != "access" || tok.RefreshToken != "refresh" {
		t.Fatalf("token = %#v", tok)
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
	w.mu.Lock()
	sess := w.sessions[body.State]
	w.mu.Unlock()
	if sess == nil {
		t.Fatalf("missing session for state %q", body.State)
	}
	if got := sess.cfg.Endpoint.AuthStyle; got != oauth2.AuthStyleInParams {
		t.Fatalf("token endpoint AuthStyle = %v, want AuthStyleInParams", got)
	}
}

func TestStartDynamicMCPFlowFallsBackToLoopbackForHTTPDashboard(t *testing.T) {
	registerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got struct {
			RedirectURIs []string `json:"redirect_uris"`
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			failOAuthTestHandler(t, w, "decode register body: %v", err)
			return
		}
		if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "http://127.0.0.1:39173/oauth/callback" {
			failOAuthTestHandler(t, w, "redirect_uris = %#v, want loopback callback", got.RedirectURIs)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"client-loopback-fallback"}`))
	}))
	defer registerServer.Close()

	w := &webMux{sessions: map[string]*oauthSession{}}
	req := httptest.NewRequest(http.MethodPost, "http://clawpatrol-gateway:8080/api/oauth/start", nil)
	rr := httptest.NewRecorder()
	w.startDynamicMCPFlow(rr, req, "notion", &OAuthIntegration{
		OAuth: OAuthConfig{
			AuthURL:     "https://mcp.notion.com/authorize",
			TokenURL:    "https://mcp.notion.com/token",
			RegisterURL: registerServer.URL,
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
	authURL, err := url.Parse(body.AuthURL)
	if err != nil {
		t.Fatalf("parse auth_url: %v", err)
	}
	if got := authURL.Query().Get("redirect_uri"); got != "http://127.0.0.1:39173/oauth/callback" {
		t.Fatalf("auth_url redirect_uri = %q, want loopback callback", got)
	}
	w.mu.Lock()
	sess := w.sessions[body.State]
	w.mu.Unlock()
	if sess == nil {
		t.Fatalf("missing session for state %q", body.State)
	}
	if got := sess.cfg.RedirectURL; got != "http://127.0.0.1:39173/oauth/callback" {
		t.Fatalf("session redirect URL = %q, want loopback callback", got)
	}
}

func TestStartDynamicMCPFlowUsesDashboardRedirectForHTTPS(t *testing.T) {
	registerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got struct {
			RedirectURIs []string `json:"redirect_uris"`
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			failOAuthTestHandler(t, w, "decode register body: %v", err)
			return
		}
		if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://clawpatrol-gateway:8080/oauth/callback" {
			failOAuthTestHandler(t, w, "redirect_uris = %#v, want HTTPS dashboard callback", got.RedirectURIs)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"client-https"}`))
	}))
	defer registerServer.Close()

	w := &webMux{sessions: map[string]*oauthSession{}}
	req := httptest.NewRequest(http.MethodPost, "http://clawpatrol-gateway:8080/api/oauth/start", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	w.startDynamicMCPFlow(rr, req, "notion", &OAuthIntegration{
		OAuth: OAuthConfig{
			AuthURL:     "https://mcp.notion.com/authorize",
			TokenURL:    "https://mcp.notion.com/token",
			RegisterURL: registerServer.URL,
		},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body struct {
		AuthURL string `json:"auth_url"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	authURL, err := url.Parse(body.AuthURL)
	if err != nil {
		t.Fatalf("parse auth_url: %v", err)
	}
	if got := authURL.Query().Get("redirect_uri"); got != "https://clawpatrol-gateway:8080/oauth/callback" {
		t.Fatalf("auth_url redirect_uri = %q, want HTTPS dashboard callback", got)
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
