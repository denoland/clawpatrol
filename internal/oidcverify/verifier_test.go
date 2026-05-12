package oidcverify_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/oidcverify"
)

func TestVerifierAcceptsValidGitHubLikeJWT(t *testing.T) {
	issuer := newTestIssuer(t)
	policy := testPolicy(issuer.URL, "https://gateway.example.com")
	verifier := oidcverify.New(oidcverify.Options{HTTPClient: issuer.Client(), Now: fixedNow})

	got, err := verifier.Verify(context.Background(), policy, issuer.Sign(t, map[string]any{
		"iss":           issuer.URL,
		"sub":           "repo:denoland/clawpatrol:ref:refs/heads/main",
		"aud":           "https://gateway.example.com",
		"exp":           fixedNow().Add(10 * time.Minute).Unix(),
		"nbf":           fixedNow().Add(-time.Minute).Unix(),
		"iat":           fixedNow().Add(-time.Minute).Unix(),
		"jti":           "run-123",
		"repository_id": "123456",
		"workflow_ref":  "denoland/clawpatrol/.github/workflows/ci.yml@refs/heads/main",
	}))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Issuer != issuer.URL || got.Subject != "repo:denoland/clawpatrol:ref:refs/heads/main" {
		t.Fatalf("issuer/subject = %q/%q", got.Issuer, got.Subject)
	}
	if !got.Expiry.Equal(fixedNow().Add(10 * time.Minute)) {
		t.Fatalf("expiry = %v", got.Expiry)
	}
	if got.ReplayKey == "" || got.TokenHash == "" {
		t.Fatalf("missing replay key/hash: %+v", got)
	}
	if got.Claims.Issuer != issuer.URL || len(got.Claims.Audience) != 1 || got.Claims.Audience[0] != "https://gateway.example.com" {
		t.Fatalf("claim request = %+v", got.Claims)
	}
	if got.Claims.Claims["repository_id"] != "123456" {
		t.Fatalf("repository_id claim = %#v", got.Claims.Claims["repository_id"])
	}
}

func TestVerifierRejectsWrongIssuerAudienceAndAlgNone(t *testing.T) {
	issuer := newTestIssuer(t)
	policy := testPolicy(issuer.URL, "https://gateway.example.com")
	verifier := oidcverify.New(oidcverify.Options{HTTPClient: issuer.Client(), Now: fixedNow})

	cases := []struct {
		name  string
		token string
	}{
		{
			name: "wrong issuer",
			token: issuer.Sign(t, map[string]any{
				"iss": "https://evil.example.com", "sub": "s", "aud": "https://gateway.example.com", "exp": fixedNow().Add(time.Minute).Unix(),
			}),
		},
		{
			name: "wrong audience",
			token: issuer.Sign(t, map[string]any{
				"iss": issuer.URL, "sub": "s", "aud": "https://other.example.com", "exp": fixedNow().Add(time.Minute).Unix(),
			}),
		},
		{
			name: "alg none",
			token: unsignedJWT(t, map[string]any{
				"iss": issuer.URL, "sub": "s", "aud": "https://gateway.example.com", "exp": fixedNow().Add(time.Minute).Unix(),
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), policy, tc.token); err == nil {
				t.Fatal("expected verification error")
			}
		})
	}
}

func TestVerifierRequiresAuthorizedPartyForMultiAudience(t *testing.T) {
	issuer := newTestIssuer(t)
	policy := testPolicy(issuer.URL, "https://gateway.example.com")
	verifier := oidcverify.New(oidcverify.Options{HTTPClient: issuer.Client(), Now: fixedNow})

	withoutAZP := issuer.Sign(t, map[string]any{
		"iss": issuer.URL, "sub": "s", "aud": []string{"https://gateway.example.com", "https://other.example.com"}, "exp": fixedNow().Add(time.Minute).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), policy, withoutAZP); err == nil {
		t.Fatal("expected multi-audience token without azp to fail")
	}
	withAZP := issuer.Sign(t, map[string]any{
		"iss": issuer.URL, "sub": "s", "aud": []string{"https://gateway.example.com", "https://other.example.com"}, "azp": "https://gateway.example.com", "exp": fixedNow().Add(time.Minute).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), policy, withAZP); err != nil {
		t.Fatalf("verify with azp: %v", err)
	}
}

func TestVerifierRejectsExpiredFutureAndOversizedTokens(t *testing.T) {
	issuer := newTestIssuer(t)
	policy := testPolicy(issuer.URL, "https://gateway.example.com")
	verifier := oidcverify.New(oidcverify.Options{HTTPClient: issuer.Client(), Now: fixedNow, MaxTokenBytes: 256})

	for name, claims := range map[string]map[string]any{
		"expired":    {"iss": issuer.URL, "sub": "s", "aud": "https://gateway.example.com", "exp": fixedNow().Add(-time.Minute).Unix()},
		"future nbf": {"iss": issuer.URL, "sub": "s", "aud": "https://gateway.example.com", "exp": fixedNow().Add(time.Hour).Unix(), "nbf": fixedNow().Add(time.Hour).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), policy, issuer.Sign(t, claims)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := verifier.Verify(context.Background(), policy, issuer.Sign(t, map[string]any{
		"iss": issuer.URL, "sub": "s", "aud": "https://gateway.example.com", "exp": fixedNow().Add(time.Hour).Unix(), "padding": string(make([]byte, 1024)),
	})); err == nil {
		t.Fatal("expected oversized token error")
	}
}

func fixedNow() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func testPolicy(issuer, audience string) *config.CompiledPolicy {
	profile := &config.CompiledProfile{Name: "ci", AllowEphemeralOIDC: true}
	enr := &config.CompiledOIDCEnrollment{Name: "gha", Issuer: issuer, Profile: profile, Match: map[string]any{"repository_id": "123456"}}
	return &config.CompiledPolicy{
		OIDCAudience:            audience,
		Profiles:                map[string]*config.CompiledProfile{"ci": profile},
		OIDCEnrollments:         []*config.CompiledOIDCEnrollment{enr},
		OIDCEnrollmentsByIssuer: map[string][]*config.CompiledOIDCEnrollment{issuer: []*config.CompiledOIDCEnrollment{enr}},
	}
}

type testIssuer struct {
	URL string
	key *rsa.PrivateKey
	kid string
	ts  *httptest.Server
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := &testIssuer{key: key, kid: "test-key"}
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	iss.URL = ts.URL
	iss.ts = ts
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"issuer": iss.URL, "jwks_uri": iss.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"keys": []any{rsaJWK(&key.PublicKey, iss.kid)}})
	})
	t.Cleanup(ts.Close)
	return iss
}

func (i *testIssuer) Client() *http.Client {
	return i.ts.Client()
}

func (i *testIssuer) Sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return signedJWT(t, i.key, i.kid, claims)
}

func signedJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	payload := encodeJSON(t, claims)
	signingInput := encodeJSON(t, header) + "." + payload
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	return encodeJSON(t, map[string]any{"alg": "none", "typ": "JWT"}) + "." + encodeJSON(t, claims) + "."
}

func encodeJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func rsaJWK(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}
