package endpoints

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// TestCodexEndpointHosts confirms EndpointHosts always claims
// auth.openai.com (so codex >= 0.142 task-registration is MITM'd without
// an HCL edit), and that it doesn't duplicate the host when an operator
// already listed it.
func TestCodexEndpointHosts(t *testing.T) {
	got := (&OpenAICodexHTTPSEndpoint{Hosts: []string{"chatgpt.com"}}).EndpointHosts()
	if !slices.Contains(got, "chatgpt.com") {
		t.Errorf("missing configured host chatgpt.com: %v", got)
	}
	if !slices.Contains(got, codexAuthAPIHost) {
		t.Errorf("EndpointHosts did not auto-claim %s: %v", codexAuthAPIHost, got)
	}

	already := (&OpenAICodexHTTPSEndpoint{Hosts: []string{"chatgpt.com", codexAuthAPIHost}}).EndpointHosts()
	n := 0
	for _, h := range already {
		if h == codexAuthAPIHost {
			n++
		}
	}
	if n != 1 {
		t.Errorf("auth host duplicated: %v", already)
	}
}

// fakeBlobs is an in-memory runtime.BlobStore for tests. Plugins read
// / write blobs through this in place of the production sqlite-backed
// store. Keyed by (kind, name) like the real one.
type fakeBlobs struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newFakeBlobs() *fakeBlobs { return &fakeBlobs{m: map[string][]byte{}} }

func (f *fakeBlobs) key(kind, name string) string { return kind + "\x00" + name }

func (f *fakeBlobs) Get(kind, name string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[f.key(kind, name)]
	return v, ok, nil
}

func (f *fakeBlobs) Put(kind, name string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	f.m[f.key(kind, name)] = cp
	return nil
}

// resetCodexKeys clears the sync.Once-cached keypair so a test gets a
// fresh BlobStore-backed mint without inheriting state from earlier
// tests in the same process.
func resetCodexKeys(t *testing.T, b *fakeBlobs) {
	t.Helper()
	codexKeysOnce = sync.Once{}
	codexKeys = nil
	codexKeysErr = nil
	SetBlobStore(b)
}

// TestCodexJWTRoundTrip mints a JWT and verifies its RS256 signature
// using the public key extracted from the JWKS the gateway would
// serve. This is the exact property codex's
// decode_agent_identity_jwt enforces (see
// codex-rs/agent-identity/src/lib.rs:147-171). If this passes, codex
// will accept the JWT.
func TestCodexJWTRoundTrip(t *testing.T) {
	b := newFakeBlobs()
	resetCodexKeys(t, b)

	jwt, err := mintCodexAccessToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, found, _ := b.Get(CodexJWTKeysKind, ""); !found {
		t.Fatalf("keys blob not persisted")
	}

	jwksJSON, err := codexJWKSResponse()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr struct{ Alg, Typ, Kid string }
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if hdr.Alg != "RS256" || hdr.Typ != "JWT" || hdr.Kid == "" {
		t.Fatalf("unexpected header: %+v", hdr)
	}

	var jwks struct {
		Keys []struct{ Kty, Kid, Use, Alg, N, E string }
	}
	if err := json.Unmarshal(jwksJSON, &jwks); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	var match *rsa.PublicKey
	for _, k := range jwks.Keys {
		if k.Kid != hdr.Kid {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			t.Fatalf("decode N: %v", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			t.Fatalf("decode E: %v", err)
		}
		match = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
	}
	if match == nil {
		t.Fatalf("kid %q not in JWKS", hdr.Kid)
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(match, crypto.SHA256, hash[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims struct {
		Iss, Aud, AgentRuntimeID, AgentPrivateKey, AccountID string
		Iat, Exp                                             int64
	}
	if err := json.Unmarshal(claimsJSON, &struct {
		Iss             *string `json:"iss"`
		Aud             *string `json:"aud"`
		Iat             *int64  `json:"iat"`
		Exp             *int64  `json:"exp"`
		AgentRuntimeID  *string `json:"agent_runtime_id"`
		AgentPrivateKey *string `json:"agent_private_key"`
		AccountID       *string `json:"account_id"`
	}{
		&claims.Iss, &claims.Aud, &claims.Iat, &claims.Exp,
		&claims.AgentRuntimeID, &claims.AgentPrivateKey, &claims.AccountID,
	}); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.Iss != "https://chatgpt.com/codex-backend/agent-identity" {
		t.Errorf("iss = %q", claims.Iss)
	}
	if claims.Aud != "codex-app-server" {
		t.Errorf("aud = %q", claims.Aud)
	}
	if claims.AgentRuntimeID == "" || claims.AgentPrivateKey == "" {
		t.Errorf("missing agent_runtime_id / agent_private_key")
	}
}

// TestCodexEndpointEnvVars verifies the endpoint plugin emits the
// CODEX_ACCESS_TOKEN / CODEX_AGENT_IDENTITY env vars (both for cross-
// version codex compat) plus the auth-API base URL override.
func TestCodexEndpointEnvVars(t *testing.T) {
	resetCodexKeys(t, newFakeBlobs())

	got := (&OpenAICodexHTTPSEndpoint{}).EnvVars()
	want := map[string]bool{
		"CODEX_ACCESS_TOKEN":                    false,
		"CODEX_AGENT_IDENTITY":                  false,
		"CODEX_AGENT_IDENTITY_AUTHAPI_BASE_URL": false,
	}
	for _, ev := range got {
		if _, ok := want[ev.Name]; !ok {
			t.Errorf("unexpected env var: %s", ev.Name)
			continue
		}
		want[ev.Name] = true
		if ev.Value == "" {
			t.Errorf("%s has empty value", ev.Name)
		}
	}
	for n, ok := range want {
		if !ok {
			t.Errorf("missing env var: %s", n)
		}
	}
}

// TestCodexRespondHTTP exercises the synthetic-response paths the
// endpoint runtime handles: JWKS fetch + agent task registration.
// Both must return 200 with parseable JSON; non-matching paths must
// fall through.
func TestCodexRespondHTTP(t *testing.T) {
	resetCodexKeys(t, newFakeBlobs())

	rt := OpenAICodexHTTPSEndpointRuntime{}
	cases := []struct {
		name    string
		method  string
		urlStr  string
		want    int
		handled bool
	}{
		{"jwks", "GET", "https://chatgpt.com/backend-api/wham/agent-identities/jwks", 200, true},
		{"register legacy wham (<=0.141)", "POST", "https://chatgpt.com/backend-api/wham/v1/agent/clawpatrol-codex/task/register", 200, true},
		{"register 0.142 auth.openai.com", "POST", "https://auth.openai.com/api/accounts/v1/agent/clawpatrol-codex/task/register", 200, true},
		{"auth login passthrough", "POST", "https://auth.openai.com/api/accounts/deviceauth/token", 0, false},
		{"auth oauth token passthrough", "POST", "https://auth.openai.com/oauth/token", 0, false},
		{"agent-register not stubbed", "POST", "https://auth.openai.com/api/accounts/v1/agent/register", 0, false},
		{"real-identity register forwarded", "POST", "https://auth.openai.com/api/accounts/v1/agent/some-real-id/task/register", 0, false},
		{"forward responses", "POST", "https://chatgpt.com/backend-api/codex/responses", 0, false},
		{"unrelated path", "GET", "https://chatgpt.com/", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := url.Parse(c.urlStr)
			if err != nil {
				t.Fatalf("url: %v", err)
			}
			req := &http.Request{Method: c.method, URL: u, Host: u.Host, Header: http.Header{}}
			resp, handled, err := rt.RespondHTTP(context.Background(), req)
			if err != nil {
				t.Fatalf("respond: %v", err)
			}
			if handled != c.handled {
				t.Fatalf("handled=%v want %v", handled, c.handled)
			}
			if !handled {
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != c.want {
				t.Fatalf("status=%d want %d", resp.StatusCode, c.want)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("body: %v", err)
			}
			var anyMap map[string]any
			if err := json.Unmarshal(body, &anyMap); err != nil {
				t.Fatalf("parse body %q: %v", body, err)
			}
		})
	}
}

// TestCodexSynthRoundTripOverHTTP wires the synthetic responder
// through net/http/httptest so we can issue a real HTTP GET and
// confirm the bytes the agent sees are what we serve. Closest thing
// to an integration test without standing up the full MITM gateway.
func TestCodexSynthRoundTripOverHTTP(t *testing.T) {
	resetCodexKeys(t, newFakeBlobs())

	rt := OpenAICodexHTTPSEndpointRuntime{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, handled, err := rt.RespondHTTP(r.Context(), r)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !handled {
			http.NotFound(w, r)
			return
		}
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/backend-api/wham/agent-identities/jwks")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"keys"`) || !strings.Contains(string(body), `"RSA"`) {
		t.Fatalf("unexpected jwks body: %s", body)
	}
}
