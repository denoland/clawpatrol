package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/denoland/clawpatrol/internal/config"
)

// asMetadataJSON writes a minimal RFC 8414 authorization server metadata
// document with the given endpoints.
func asMetadataJSON(issuer, authz, token, register string) string {
	doc := map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": authz,
		"token_endpoint":         token,
	}
	if register != "" {
		doc["registration_endpoint"] = register
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

func TestDiscoverRemoteMCPMetaHappyPath(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"` + srv.URL + `/mcp","authorization_servers":["` + srv.URL + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(asMetadataJSON(srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/register")))
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	meta, err := discoverRemoteMCPMeta(t.Context(), srv.Client(), srv.URL+"/mcp", []string{"mcp:read"})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if meta.Issuer != srv.URL {
		t.Errorf("issuer = %q, want %q", meta.Issuer, srv.URL)
	}
	if meta.TokenEndpoint != srv.URL+"/token" {
		t.Errorf("token_endpoint = %q", meta.TokenEndpoint)
	}
	if meta.AuthorizationEndpoint != srv.URL+"/authorize" {
		t.Errorf("authorization_endpoint = %q", meta.AuthorizationEndpoint)
	}
	if meta.RegistrationEndpoint != srv.URL+"/register" {
		t.Errorf("registration_endpoint = %q", meta.RegistrationEndpoint)
	}
	if meta.Resource != srv.URL+"/mcp" {
		t.Errorf("resource = %q", meta.Resource)
	}
	if len(meta.Scopes) != 1 || meta.Scopes[0] != "mcp:read" {
		t.Errorf("scopes = %#v", meta.Scopes)
	}
}

func TestDiscoverRemoteMCPMetaRejectsMultipleAuthServers(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"` + srv.URL + `/mcp","authorization_servers":["` + srv.URL + `","https://other.example.test"]}`))
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := discoverRemoteMCPMeta(t.Context(), srv.Client(), srv.URL+"/mcp", nil)
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("err = %v, want ambiguous-authorization-server rejection", err)
	}
}

func TestDiscoverRemoteMCPMetaRejectsIssuerMismatch(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource":"` + srv.URL + `/mcp","authorization_servers":["` + srv.URL + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		// Metadata claims a different issuer than the one we discovered it from.
		_, _ = w.Write([]byte(asMetadataJSON("https://evil.example.test", srv.URL+"/authorize", srv.URL+"/token", "")))
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := discoverRemoteMCPMeta(t.Context(), srv.Client(), srv.URL+"/mcp", nil)
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("err = %v, want issuer mismatch rejection", err)
	}
}

func TestDiscoverRemoteMCPMetaRejectsTokenEndpointSubstitution(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource":"` + srv.URL + `/mcp","authorization_servers":["` + srv.URL + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		// authorization_endpoint is on-issuer, but token_endpoint points at
		// an attacker-controlled host — must be rejected.
		_, _ = w.Write([]byte(asMetadataJSON(srv.URL, srv.URL+"/authorize", "https://evil.example.test/token", "")))
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := discoverRemoteMCPMeta(t.Context(), srv.Client(), srv.URL+"/mcp", nil)
	if err == nil || !strings.Contains(err.Error(), "substitution") {
		t.Fatalf("err = %v, want token-endpoint substitution rejection", err)
	}
}

func TestStartRemoteMCPOAuthFlow(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blobs := newGatewayBlobStore(db)

	var srv *httptest.Server
	var registerHits int
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource":"` + srv.URL + `/mcp","authorization_servers":["` + srv.URL + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(asMetadataJSON(srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/register")))
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		registerHits++
		var body struct {
			RedirectURIs            []string `json:"redirect_uris"`
			TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.TokenEndpointAuthMethod != "none" {
			failOAuthTestHandler(t, w, "token_endpoint_auth_method = %q, want none", body.TokenEndpointAuthMethod)
			return
		}
		if len(body.RedirectURIs) != 1 || body.RedirectURIs[0] != "http://dash.example:8080/oauth/callback" {
			failOAuthTestHandler(t, w, "redirect_uris = %#v", body.RedirectURIs)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"dcr-client-xyz"}`))
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	g := &Gateway{blobs: blobs}
	w := &webMux{g: g, sessions: map[string]*oauthSession{}, httpClient: srv.Client()}
	flow := &OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		Flow:   "remote_mcp_oauth",
		OAuth: OAuthConfig{
			ResourceURL: srv.URL + "/mcp",
			Scopes:      []string{"mcp:read"},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "http://dash.example:8080/api/oauth/start", nil)
	rr := httptest.NewRecorder()
	w.startRemoteMCPOAuthFlow(rr, req, "acme-mcp", flow)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if registerHits != 1 {
		t.Fatalf("register hits = %d, want 1", registerHits)
	}
	var resp struct {
		AuthURL string `json:"auth_url"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.State == "" {
		t.Fatal("empty state")
	}
	au, err := url.Parse(resp.AuthURL)
	if err != nil {
		t.Fatalf("parse auth_url: %v", err)
	}
	q := au.Query()
	if got := q.Get("client_id"); got != "dcr-client-xyz" {
		t.Errorf("auth_url client_id = %q, want dcr-client-xyz", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if q.Get("code_challenge") == "" {
		t.Error("auth_url missing code_challenge")
	}
	if got := q.Get("resource"); got != srv.URL+"/mcp" {
		t.Errorf("auth_url resource = %q, want %q", got, srv.URL+"/mcp")
	}
	if got := q.Get("redirect_uri"); got != "http://dash.example:8080/oauth/callback" {
		t.Errorf("auth_url redirect_uri = %q", got)
	}

	// Session captured with the resource indicator + dynamic client id.
	w.mu.Lock()
	sess := w.sessions[resp.State]
	w.mu.Unlock()
	if sess == nil {
		t.Fatalf("missing session for state %q", resp.State)
	}
	if sess.resource != srv.URL+"/mcp" {
		t.Errorf("session resource = %q", sess.resource)
	}
	if sess.dynClientID != "dcr-client-xyz" {
		t.Errorf("session dynClientID = %q", sess.dynClientID)
	}
	if _, ok := loadRemoteMCPMeta(blobs, "acme-mcp"); ok {
		t.Fatal("metadata blob persisted before successful token exchange")
	}
}

func TestRemoteMCPOAuthExchangeSendsResource(t *testing.T) {
	var gotResource, gotGrant, gotClient, gotVerifier string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			failOAuthTestHandler(t, w, "parse form: %v", err)
			return
		}
		gotResource = r.Form.Get("resource")
		gotGrant = r.Form.Get("grant_type")
		gotClient = r.Form.Get("client_id")
		gotVerifier = r.Form.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	sess := &oauthSession{
		verifier: "the-verifier",
		state:    "s",
		resource: "https://mcp.example.test/mcp",
		cfg: &oauth2.Config{
			ClientID:    "dcr-client",
			RedirectURL: "http://dash.example/oauth/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL:  ts.URL + "/token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client())
	tok, err := exchangeOAuthCode(ctx, sess, "auth-code", "s")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken != "at" {
		t.Errorf("access token = %q", tok.AccessToken)
	}
	if gotResource != "https://mcp.example.test/mcp" {
		t.Errorf("resource = %q, want the canonical mcp resource", gotResource)
	}
	if gotGrant != "authorization_code" {
		t.Errorf("grant_type = %q", gotGrant)
	}
	if gotClient != "dcr-client" {
		t.Errorf("client_id = %q", gotClient)
	}
	if gotVerifier != "the-verifier" {
		t.Errorf("code_verifier = %q", gotVerifier)
	}
}

func TestRemoteMCPRefreshSourceSendsResource(t *testing.T) {
	var gotResource, gotGrant, gotClient string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			failOAuthTestHandler(t, w, "parse form: %v", err)
			return
		}
		gotResource = r.Form.Get("resource")
		gotGrant = r.Form.Get("grant_type")
		gotClient = r.Form.Get("client_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-at","refresh_token":"new-rt","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	src := &dynamicMCPRefreshSource{
		cfg: &oauth2.Config{
			ClientID: "dcr-client",
			Endpoint: oauth2.Endpoint{TokenURL: ts.URL},
		},
		current: &oauth2.Token{
			AccessToken:  "old-at",
			RefreshToken: "old-rt",
			TokenType:    "Bearer",
			Expiry:       time.Now().Add(-time.Hour),
		},
		resource: "https://mcp.example.test/mcp",
	}
	tok, err := src.Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tok.AccessToken != "new-at" {
		t.Errorf("access token = %q", tok.AccessToken)
	}
	if gotResource != "https://mcp.example.test/mcp" {
		t.Errorf("resource = %q", gotResource)
	}
	if gotGrant != "refresh_token" {
		t.Errorf("grant_type = %q", gotGrant)
	}
	if gotClient != "dcr-client" {
		t.Errorf("client_id = %q", gotClient)
	}
}

// TestRemoteMCPOAuthRefreshAfterFirstConnect pins that a token captured
// on the very first connect (when the boot-time integration still has no
// token endpoint) can refresh against the discovered endpoint, because
// the exchange path stamps it onto the registry via SetDiscoveredEndpoints.
func TestRemoteMCPOAuthRefreshAfterFirstConnect(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var gotResource, gotClient string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotResource = r.Form.Get("resource")
		gotClient = r.Form.Get("client_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"refreshed-at","refresh_token":"rotated-rt","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	reg, err := NewOAuthRegistry(nil, db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	// Boot-time registration: no discovered endpoints yet (no blob).
	reg.Register("acme-mcp", OAuthIntegration{
		Flow:   "remote_mcp_oauth",
		Header: "Authorization",
		Prefix: "Bearer ",
	})
	// Exchange path atomically stamps the discovered endpoints and stores the token.
	if err := reg.SetRemoteMCPWithClient(t.Context(), "acme-mcp", &oauth2.Token{
		AccessToken:  "first-at",
		RefreshToken: "first-rt",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Hour),
	}, "dcr-client", "https://auth.example.test/authorize", ts.URL+"/token", "https://mcp.example.test/mcp", nil); err != nil {
		t.Fatalf("set: %v", err)
	}

	tok, err := reg.Token("acme-mcp")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != "refreshed-at" {
		t.Errorf("token = %q, want refreshed-at", tok)
	}
	if gotResource != "https://mcp.example.test/mcp" {
		t.Errorf("refresh resource = %q", gotResource)
	}
	if gotClient != "dcr-client" {
		t.Errorf("refresh client_id = %q", gotClient)
	}
}

// fakeRemoteMCPProvider is a minimal credential body implementing
// config.OAuthFlowProvider as a strict remote_mcp_oauth credential, used
// to drive registerOAuthCredentials without standing up the full plugin
// machinery.
type fakeRemoteMCPProvider struct{ scopes []string }

type fakeRemoteMCPEndpoint struct{ url string }

func (f fakeRemoteMCPEndpoint) RemoteMCPURL() string { return f.url }

func (f fakeRemoteMCPProvider) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		Flow:   "remote_mcp_oauth",
		OAuth:  config.OAuthConfig{Scopes: f.scopes},
	}
}

// TestRemoteMCPRefreshAfterRestartUsesPersistedTokenEndpoint simulates a
// gateway restart: tokens live in the credentials table, discovery
// metadata lives in gateway_blobs, and registerOAuthCredentials must
// rebuild a refresh source that hits the *persisted* token endpoint with
// the resource indicator — never re-discovering it.
func TestRemoteMCPRefreshAfterRestartUsesPersistedTokenEndpoint(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blobs := newGatewayBlobStore(db)

	var gotResource, gotClient, gotRefresh string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			failOAuthTestHandler(t, w, "parse form: %v", err)
			return
		}
		gotResource = r.Form.Get("resource")
		gotClient = r.Form.Get("client_id")
		gotRefresh = r.Form.Get("refresh_token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"refreshed-at","refresh_token":"rotated-rt","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	// Persist discovery metadata (non-secret) as a prior connect would.
	if err := saveRemoteMCPMeta(blobs, "acme-mcp", remoteMCPMeta{
		Issuer:                "https://auth.example.test",
		AuthorizationEndpoint: "https://auth.example.test/authorize",
		TokenEndpoint:         ts.URL + "/token",
		Resource:              "https://mcp.example.test/mcp",
		ClientID:              "dcr-client",
		RedirectURI:           "http://dash.example/oauth/callback",
	}); err != nil {
		t.Fatalf("persist meta: %v", err)
	}
	// Seed an expired token row, as the credentials table would hold it.
	if _, err := db.Exec(`
		INSERT INTO credentials (id, access_token, token_type, refresh_token, expiry_ns, updated_ns, client_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"acme-mcp", "old-at", "Bearer", "stored-rt",
		time.Now().Add(-time.Hour).UnixNano(), time.Now().UnixNano(), "dcr-client",
	); err != nil {
		t.Fatalf("seed credentials: %v", err)
	}

	policy := &config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{
			"acme": {Body: fakeRemoteMCPEndpoint{url: "https://mcp.example.test/mcp"}},
		},
		Credentials: map[string]*config.Entity{
			"acme-mcp": {
				Body:      fakeRemoteMCPProvider{scopes: []string{"mcp:read"}},
				Framework: config.FrameworkAttrs{Refs: map[string]string{"endpoint": "acme"}},
			},
		},
	}

	reg, err := NewOAuthRegistry(nil, db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	registerOAuthCredentials(reg, policy, blobs)

	tok, err := reg.Token("acme-mcp")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != "refreshed-at" {
		t.Errorf("access token = %q, want refreshed-at", tok)
	}
	if gotResource != "https://mcp.example.test/mcp" {
		t.Errorf("refresh resource = %q", gotResource)
	}
	if gotClient != "dcr-client" {
		t.Errorf("refresh client_id = %q", gotClient)
	}
	if gotRefresh != "stored-rt" {
		t.Errorf("refresh_token = %q, want stored-rt", gotRefresh)
	}
}

func TestRemoteMCPOAuthDoesNotFollowDiscoveryRedirect(t *testing.T) {
	evilHit := false
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHit = true
		_, _ = w.Write([]byte(`{"resource":"https://evil.example/mcp","authorization_servers":["https://evil.example"]}`))
	}))
	defer evil.Close()

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/metadata", http.StatusTemporaryRedirect)
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := discoverRemoteMCPMeta(t.Context(), noRedirectOAuthHTTPClient(srv.Client()), srv.URL+"/mcp", nil)
	if err == nil {
		t.Fatal("discovery succeeded through redirect; want failure")
	}
	if evilHit {
		t.Fatal("redirect target was contacted; OAuth metadata redirects must not be followed")
	}
}

func TestRemoteMCPOAuthDoesNotFollowDCRRedirect(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	evilHit := false
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHit = true
		_, _ = w.Write([]byte(`{"client_id":"evil"}`))
	}))
	defer evil.Close()

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource":"` + srv.URL + `/mcp","authorization_servers":["` + srv.URL + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(asMetadataJSON(srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/register")))
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/register", http.StatusTemporaryRedirect)
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	w := &webMux{g: &Gateway{blobs: newGatewayBlobStore(db)}, sessions: map[string]*oauthSession{}, httpClient: srv.Client()}
	flow := &OAuthIntegration{Flow: "remote_mcp_oauth", OAuth: OAuthConfig{ResourceURL: srv.URL + "/mcp"}}
	rr := httptest.NewRecorder()
	w.startRemoteMCPOAuthFlow(rr, httptest.NewRequest(http.MethodPost, "http://dash.example:8080/api/oauth/start", nil), "acme-mcp", flow)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if evilHit {
		t.Fatal("DCR redirect target was contacted; OAuth registration redirects must not be followed")
	}
}

func TestRemoteMCPOAuthDoesNotFollowExchangeRedirect(t *testing.T) {
	evilHit := false
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHit = true
		_, _ = w.Write([]byte(`{"access_token":"evil","token_type":"Bearer"}`))
	}))
	defer evil.Close()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer ts.Close()

	sess := &oauthSession{
		verifier:   "the-verifier",
		state:      "s",
		resource:   "https://mcp.example.test/mcp",
		httpClient: noRedirectOAuthHTTPClient(ts.Client()),
		cfg: &oauth2.Config{
			ClientID:    "dcr-client",
			RedirectURL: "http://dash.example/oauth/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL:  ts.URL + "/token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
	}
	_, err := exchangeOAuthCode(context.Background(), sess, "auth-code", "s")
	if err == nil {
		t.Fatal("exchange succeeded through token redirect; want failure")
	}
	if evilHit {
		t.Fatal("token redirect target was contacted; OAuth exchange redirects must not be followed")
	}
}

func TestRemoteMCPOAuthDoesNotFollowRefreshRedirect(t *testing.T) {
	evilHit := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHit = true
		_, _ = w.Write([]byte(`{"access_token":"evil","token_type":"Bearer"}`))
	}))
	defer evil.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer ts.Close()

	src := &dynamicMCPRefreshSource{
		cfg: &oauth2.Config{
			ClientID: "dcr-client",
			Endpoint: oauth2.Endpoint{TokenURL: ts.URL},
		},
		current: &oauth2.Token{
			AccessToken:  "old-at",
			RefreshToken: "old-rt",
			TokenType:    "Bearer",
			Expiry:       time.Now().Add(-time.Hour),
		},
		resource:   "https://mcp.example.test/mcp",
		httpClient: noRedirectOAuthHTTPClient(ts.Client()),
	}
	_, err := src.Token()
	if err == nil {
		t.Fatal("refresh succeeded through token redirect; want failure")
	}
	if evilHit {
		t.Fatal("refresh redirect target was contacted; OAuth refresh redirects must not be followed")
	}
}

func TestRemoteMCPOAuthExchangePersistsMetaOnlyAfterSuccess(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blobs := newGatewayBlobStore(db)

	var tokenHit bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenHit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	reg, err := NewOAuthRegistry([]OAuthIntegration{{
		ID:     "acme-mcp",
		Flow:   "remote_mcp_oauth",
		Header: "Authorization",
		Prefix: "Bearer ",
		OAuth:  OAuthConfig{ResourceURL: "https://mcp.example.test/mcp"},
	}}, db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	w := &webMux{g: &Gateway{oauth: reg, blobs: blobs}, sessions: map[string]*oauthSession{}}
	w.sessions["state-1"] = &oauthSession{
		verifier:    "verifier",
		state:       "state-1",
		id:          "acme-mcp",
		created:     time.Now(),
		dynClientID: "dcr-client",
		resource:    "https://mcp.example.test/mcp",
		httpClient:  noRedirectOAuthHTTPClient(ts.Client()),
		cfg: &oauth2.Config{
			ClientID:    "dcr-client",
			RedirectURL: "http://dash.example/oauth/callback",
			Endpoint:    oauth2.Endpoint{TokenURL: ts.URL + "/token", AuthStyle: oauth2.AuthStyleInParams},
		},
		remoteMCPMeta: &remoteMCPMeta{
			Issuer:                ts.URL,
			AuthorizationEndpoint: ts.URL + "/authorize",
			TokenEndpoint:         ts.URL + "/token",
			Resource:              "https://mcp.example.test/mcp",
			ClientID:              "dcr-client",
			RedirectURI:           "http://dash.example/oauth/callback",
			Scopes:                []string{"mcp:read"},
		},
	}
	if _, ok := loadRemoteMCPMeta(blobs, "acme-mcp"); ok {
		t.Fatal("metadata unexpectedly present before exchange")
	}
	rr := httptest.NewRecorder()
	w.apiOAuthExchange(rr, httptest.NewRequest(http.MethodPost, "/api/oauth/exchange", strings.NewReader(`{"state":"state-1","code":"code"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("exchange status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if !tokenHit {
		t.Fatal("token endpoint was not called")
	}
	meta, ok := loadRemoteMCPMeta(blobs, "acme-mcp")
	if !ok {
		t.Fatal("metadata not persisted after successful exchange")
	}
	if meta.TokenEndpoint != ts.URL+"/token" || meta.ClientID != "dcr-client" || meta.RedirectURI != "http://dash.example/oauth/callback" {
		t.Fatalf("persisted meta = %#v", meta)
	}
}

func TestRemoteMCPOAuthStartReregistersWhenRedirectOrScopesChange(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blobs := newGatewayBlobStore(db)

	var srv *httptest.Server
	registerHits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource":"` + srv.URL + `/mcp","authorization_servers":["` + srv.URL + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(asMetadataJSON(srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/register")))
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		registerHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"client-new"}`))
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	baseMeta := remoteMCPMeta{
		Issuer:                srv.URL,
		AuthorizationEndpoint: srv.URL + "/authorize",
		TokenEndpoint:         srv.URL + "/token",
		RegistrationEndpoint:  srv.URL + "/register",
		Resource:              srv.URL + "/mcp",
		ClientID:              "client-old",
		RedirectURI:           "http://old.example/oauth/callback",
		Scopes:                []string{"mcp:read"},
	}
	if err := saveRemoteMCPMeta(blobs, "acme-mcp", baseMeta); err != nil {
		t.Fatalf("save meta: %v", err)
	}
	w := &webMux{g: &Gateway{blobs: blobs}, sessions: map[string]*oauthSession{}, httpClient: srv.Client()}
	flow := &OAuthIntegration{Flow: "remote_mcp_oauth", OAuth: OAuthConfig{ResourceURL: srv.URL + "/mcp", Scopes: []string{"mcp:read"}}}
	rr := httptest.NewRecorder()
	w.startRemoteMCPOAuthFlow(rr, httptest.NewRequest(http.MethodPost, "http://new.example/api/oauth/start", nil), "acme-mcp", flow)
	if rr.Code != http.StatusOK {
		t.Fatalf("redirect-change start status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if registerHits != 1 {
		t.Fatalf("register hits after redirect change = %d, want 1", registerHits)
	}

	baseMeta.RedirectURI = "http://same.example/oauth/callback"
	baseMeta.Scopes = []string{"mcp:read"}
	baseMeta.ClientID = "client-old"
	if err := saveRemoteMCPMeta(blobs, "acme-mcp", baseMeta); err != nil {
		t.Fatalf("save meta: %v", err)
	}
	flow.OAuth.Scopes = []string{"mcp:read", "mcp:write"}
	rr = httptest.NewRecorder()
	w.startRemoteMCPOAuthFlow(rr, httptest.NewRequest(http.MethodPost, "http://same.example/api/oauth/start", nil), "acme-mcp", flow)
	if rr.Code != http.StatusOK {
		t.Fatalf("scope-change start status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if registerHits != 2 {
		t.Fatalf("register hits after scope change = %d, want 2", registerHits)
	}
}

func TestRemoteMCPOAuthDoesNotLoadStoredTokenWithoutMatchingMetadata(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`
		INSERT INTO credentials (id, access_token, token_type, refresh_token, expiry_ns, updated_ns, client_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"acme-mcp", "old-at", "Bearer", "old-rt", time.Now().Add(time.Hour).UnixNano(), time.Now().UnixNano(), "old-client",
	); err != nil {
		t.Fatalf("seed credentials: %v", err)
	}
	reg, err := NewOAuthRegistry([]OAuthIntegration{{
		ID:   "acme-mcp",
		Flow: "remote_mcp_oauth",
		OAuth: OAuthConfig{
			ResourceURL: "https://new-resource.example.test/mcp",
			// Empty TokenURL models boot after endpoint rebinding or metadata
			// mismatch: enrichRemoteMCPOAuthFlow refused the stale blob.
		},
	}}, db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	tok, err := reg.Token("acme-mcp")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != "" {
		t.Fatalf("loaded stale token %q for remote_mcp_oauth without matching metadata", tok)
	}
}

func TestRemoteMCPOAuthDoesNotLoadStoredTokenForSameOriginDifferentResource(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blobs := newGatewayBlobStore(db)
	if err := saveRemoteMCPMeta(blobs, "acme-mcp", remoteMCPMeta{
		Issuer:                "https://auth.example.test",
		AuthorizationEndpoint: "https://auth.example.test/authorize",
		TokenEndpoint:         "https://auth.example.test/token",
		Resource:              "https://mcp.example.test/old",
		ClientID:              "old-client",
	}); err != nil {
		t.Fatalf("persist meta: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO credentials (id, access_token, token_type, refresh_token, expiry_ns, updated_ns, client_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"acme-mcp", "old-at", "Bearer", "old-rt", time.Now().Add(time.Hour).UnixNano(), time.Now().UnixNano(), "old-client",
	); err != nil {
		t.Fatalf("seed credentials: %v", err)
	}
	policy := &config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{
			"acme": {Body: fakeRemoteMCPEndpoint{url: "https://mcp.example.test/new"}},
		},
		Credentials: map[string]*config.Entity{
			"acme-mcp": {
				Body:      fakeRemoteMCPProvider{scopes: []string{"mcp:read"}},
				Framework: config.FrameworkAttrs{Refs: map[string]string{"endpoint": "acme"}},
			},
		},
	}
	reg, err := NewOAuthRegistry(nil, db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	registerOAuthCredentials(reg, policy, blobs)
	tok, err := reg.Token("acme-mcp")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != "" {
		t.Fatalf("loaded same-origin stale token %q for different resource path", tok)
	}
}

func TestRemoteMCPOAuthRegisterClearsLiveStateWhenMetadataNoLongerMatches(t *testing.T) {
	reg, err := NewOAuthRegistry([]OAuthIntegration{{
		ID:   "acme-mcp",
		Flow: "remote_mcp_oauth",
		OAuth: OAuthConfig{
			AuthURL:     "https://auth.example.test/authorize",
			TokenURL:    "https://auth.example.test/token",
			ResourceURL: "https://mcp.example.test/old",
		},
	}}, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if err := reg.SetRemoteMCPWithClient(t.Context(), "acme-mcp", &oauth2.Token{
		AccessToken: "old-at",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}, "old-client", "https://auth.example.test/authorize", "https://auth.example.test/token", "https://mcp.example.test/old", nil); err != nil {
		t.Fatalf("set token: %v", err)
	}
	if tok, err := reg.Token("acme-mcp"); err != nil || tok != "old-at" {
		t.Fatalf("precondition token = %q, err = %v", tok, err)
	}
	reg.Register("acme-mcp", OAuthIntegration{
		ID:   "acme-mcp",
		Flow: "remote_mcp_oauth",
		OAuth: OAuthConfig{
			ResourceURL: "https://mcp.example.test/new",
			// Empty TokenURL models a reload where persisted metadata did not
			// match the currently bound remote_mcp endpoint.
		},
	})
	if tok, err := reg.Token("acme-mcp"); err != nil || tok != "" {
		t.Fatalf("stale live token after metadata mismatch reload = %q, err = %v", tok, err)
	}
}

func TestDiscoverRemoteMCPMetaRejectsResourceQueryMismatch(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource":"` + srv.URL + `/mcp?tenant=other","authorization_servers":["` + srv.URL + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(asMetadataJSON(srv.URL, srv.URL+"/authorize", srv.URL+"/token", "")))
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := discoverRemoteMCPMeta(t.Context(), srv.Client(), srv.URL+"/mcp?tenant=prod", nil)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v, want query-sensitive resource mismatch rejection", err)
	}
}

func TestDiscoverRemoteMCPMetaFallbackResourcePreservesQuery(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_servers":["` + srv.URL + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(asMetadataJSON(srv.URL, srv.URL+"/authorize", srv.URL+"/token", "")))
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	meta, err := discoverRemoteMCPMeta(t.Context(), srv.Client(), srv.URL+"/mcp?tenant=prod", nil)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if meta.Resource != srv.URL+"/mcp?tenant=prod" {
		t.Fatalf("resource = %q, want query preserved", meta.Resource)
	}
}

func TestRemoteMCPOAuthExchangeRejectsStaleSessionResource(t *testing.T) {
	var tokenHits int
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"old-at","refresh_token":"old-rt","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()
	reg, err := NewOAuthRegistry([]OAuthIntegration{{
		ID:   "acme-mcp",
		Flow: "remote_mcp_oauth",
		OAuth: OAuthConfig{
			ResourceURL: "https://mcp.example.test/new",
			TokenURL:    ts.URL + "/token",
		},
	}}, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	w := &webMux{g: &Gateway{oauth: reg}, sessions: map[string]*oauthSession{}}
	w.sessions["state-1"] = &oauthSession{
		verifier: "verifier",
		state:    "state-1",
		id:       "acme-mcp",
		created:  time.Now(),
		resource: "https://mcp.example.test/old",
		cfg: &oauth2.Config{
			ClientID:    "client",
			RedirectURL: "http://dash.example/oauth/callback",
			Endpoint:    oauth2.Endpoint{TokenURL: ts.URL + "/token", AuthStyle: oauth2.AuthStyleInParams},
		},
		httpClient: noRedirectOAuthHTTPClient(ts.Client()),
		remoteMCPMeta: &remoteMCPMeta{
			TokenEndpoint: ts.URL + "/token",
			Resource:      "https://mcp.example.test/old",
			ClientID:      "client",
		},
	}
	rr := httptest.NewRecorder()
	w.apiOAuthExchange(rr, httptest.NewRequest(http.MethodPost, "/api/oauth/exchange", strings.NewReader(`{"state":"state-1","code":"code"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("exchange status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if tokenHits != 0 {
		t.Fatalf("token endpoint hits = %d, want 0", tokenHits)
	}
	if tok, err := reg.Token("acme-mcp"); err != nil || tok != "" {
		t.Fatalf("stale session installed token = %q, err = %v", tok, err)
	}
}

func TestDiscoverRemoteMCPMetaRejectsResourceTrailingSlashMismatch(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/tenant", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource":"` + srv.URL + `/tenant/","authorization_servers":["` + srv.URL + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(asMetadataJSON(srv.URL, srv.URL+"/authorize", srv.URL+"/token", "")))
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := discoverRemoteMCPMeta(t.Context(), srv.Client(), srv.URL+"/tenant", nil)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v, want trailing-slash-sensitive resource mismatch rejection", err)
	}
}
