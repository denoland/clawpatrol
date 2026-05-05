package credentials

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/denoland/clawpatrol/config/runtime"
)

// TestCodexJWTRoundTrip mints a JWT and verifies its RS256 signature
// using the public key extracted from the JWKS the gateway would
// serve. This is the exact property codex's
// decode_agent_identity_jwt enforces (see
// codex-rs/agent-identity/src/lib.rs:147-171). If this passes, codex
// will accept the JWT.
func TestCodexJWTRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLAWPATROL_DIR", dir)

	// Reset the package-level once so the test gets fresh keys in a
	// clean tempdir. The init runs once per process; the production
	// API caches via sync.Once so we have to break out of it here.
	codexKeysOnce = sync.Once{}
	codexKeys = nil
	codexKeysErr = nil

	jwt, err := MintCodexAccessToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !strings.HasSuffix(filepath.Dir(codexJWTKeysPath()), filepath.Base(dir)) {
		t.Fatalf("CLAWPATROL_DIR not honored: %s", codexJWTKeysPath())
	}
	if _, err := os.Stat(codexJWTKeysPath()); err != nil {
		t.Fatalf("keys file missing: %v", err)
	}

	jwksJSON, err := CodexJWKSResponse()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}

	// Parse JWT into segments
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3", len(parts))
	}

	// Verify the kid in the JWT header is in the JWKS we serve.
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

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(match, crypto.SHA256, hash[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Verify required claims
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

// TestCodexRespondHTTP exercises the synthetic-response paths the
// codex plugin handles: JWKS fetch + agent task registration. Both
// must return 200 with parseable JSON; non-matching paths must fall
// through. We also confirm a request on a non-chatgpt host (the
// api.openai.com side of the binding) is left for normal forwarding.
func TestCodexRespondHTTP(t *testing.T) {
	t.Setenv("CLAWPATROL_DIR", t.TempDir())
	codexKeysOnce = sync.Once{}
	codexKeys = nil
	codexKeysErr = nil

	plugin := &OpenAICodexOAuth{}
	cases := []struct {
		name    string
		method  string
		urlStr  string
		want    int
		handled bool
	}{
		{"jwks", "GET", "https://chatgpt.com/backend-api/wham/agent-identities/jwks", 200, true},
		{"register", "POST", "https://chatgpt.com/backend-api/wham/v1/agent/clawpatrol-codex/task/register", 200, true},
		{"forward responses", "POST", "https://chatgpt.com/backend-api/codex/responses", 0, false},
		{"openai api", "POST", "https://api.openai.com/v1/responses", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := url.Parse(c.urlStr)
			if err != nil {
				t.Fatalf("url: %v", err)
			}
			req := &http.Request{Method: c.method, URL: u, Host: u.Host, Header: http.Header{}}
			resp, handled, err := plugin.RespondHTTP(context.Background(), req, runtime.Secret{})
			if err != nil {
				t.Fatalf("respond: %v", err)
			}
			if handled != c.handled {
				t.Fatalf("handled=%v want %v", handled, c.handled)
			}
			if !handled {
				return
			}
			if resp.StatusCode != c.want {
				t.Fatalf("status=%d want %d", resp.StatusCode, c.want)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("body: %v", err)
			}
			var any map[string]any
			if err := json.Unmarshal(body, &any); err != nil {
				t.Fatalf("parse body %q: %v", body, err)
			}
		})
	}
}

// TestCodexInjectOverridesAgentAssertion confirms the auth swap path:
// codex in Agent Identity mode sends `Authorization: AgentAssertion …`
// signed with the per-task ed25519 key from the synthetic JWT we
// minted. The MITM must overwrite that with `Bearer <real subscription
// token>` plus the real account-id from the bearer's JWT claims, so
// chatgpt.com sees a request indistinguishable from native ChatGPT
// auth. Without this swap, the upstream rejects with 403 "Unknown
// agent runtime for AgentAssertion" (verified live against funk).
func TestCodexInjectOverridesAgentAssertion(t *testing.T) {
	plugin := &OpenAICodexOAuth{}

	// A real-shaped chatgpt access_token JWT carrying chatgpt_account_id
	// in the auth namespace claim — same form as
	// ~/.codex/auth.json's tokens.access_token.
	headerJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claimsJSON, _ := json.Marshal(map[string]any{
		"https://api.openai.com/auth": map[string]string{
			"chatgpt_account_id": "real-acct-7b415a8c",
		},
	})
	bearer := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("sig"))

	req, err := http.NewRequest("POST", "https://chatgpt.com/backend-api/codex/responses", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	// What codex (Agent Identity mode) would have sent
	req.Header.Set("Authorization", "AgentAssertion eyJhZ2VudF9ydW50aW1lX2lkIjoiY2xhd3BhdHJvbC1jb2RleCIsInNpZ25hdHVyZSI6Im9wYXF1ZSJ9")
	req.Header.Set("Chatgpt-Account-Id", "clawpatrol")

	if err := plugin.InjectHTTP(req.Context(), req, runtime.Secret{Bytes: []byte(bearer)}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+bearer {
		t.Errorf("Authorization not swapped to bearer: got %q", got)
	}
	if got := req.Header.Get("Chatgpt-Account-Id"); got != "real-acct-7b415a8c" {
		t.Errorf("Chatgpt-Account-Id not overwritten with bearer claim: got %q", got)
	}
}

// TestCodexSynthRoundTripOverHTTP wires the synthetic responder
// through net/http/httptest so we can issue a real HTTP GET and
// confirm the bytes the agent sees are what we serve. This is the
// closest thing to an integration test without standing up the full
// MITM gateway.
func TestCodexSynthRoundTripOverHTTP(t *testing.T) {
	t.Setenv("CLAWPATROL_DIR", t.TempDir())
	codexKeysOnce = sync.Once{}
	codexKeys = nil
	codexKeysErr = nil

	plugin := &OpenAICodexOAuth{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// httptest serves under 127.0.0.1; rewrite Host so the plugin's
		// chatgpt.com guard fires.
		r.Host = "chatgpt.com"
		r.URL.Host = "chatgpt.com"
		resp, handled, err := plugin.RespondHTTP(r.Context(), r, runtime.Secret{})
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
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/backend-api/wham/agent-identities/jwks")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"keys"`) || !strings.Contains(string(body), `"RSA"`) {
		t.Fatalf("unexpected jwks body: %s", body)
	}
}
