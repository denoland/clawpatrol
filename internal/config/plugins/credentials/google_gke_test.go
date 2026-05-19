package credentials

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestGoogleGKECredentialMissingSAKey covers the most common
// misconfiguration: the credential exists in HCL but the dashboard
// paste / env var was never filled in. The error must name `sa_key`
// so the operator can find the right slot to fix.
func TestGoogleGKECredentialMissingSAKey(t *testing.T) {
	cred := &GoogleGKECredential{}
	req, _ := http.NewRequest("GET", "https://k8s.example", nil)
	err := cred.SignHTTPRequest(context.Background(), req, runtime.Secret{}, nil)
	if err == nil || !strings.Contains(err.Error(), "missing sa_key") {
		t.Fatalf("want missing sa_key error, got %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Errorf("Authorization header set on error: %q", req.Header.Get("Authorization"))
	}
}

// TestGoogleGKECredentialMalformedSAKey makes sure a paste error
// surfaces as a parse failure, not as a confusing token-mint error
// downstream.
func TestGoogleGKECredentialMalformedSAKey(t *testing.T) {
	cred := &GoogleGKECredential{}
	req, _ := http.NewRequest("GET", "https://k8s.example", nil)
	sec := runtime.Secret{Extras: map[string]string{"sa_key": "{not json"}}
	err := cred.SignHTTPRequest(context.Background(), req, sec, nil)
	if err == nil || !strings.Contains(err.Error(), "parse sa_key") {
		t.Fatalf("want parse sa_key error, got %v", err)
	}
}

// TestGoogleGKECredentialTokenSourceCachedBySAKey exercises the
// per-SA-key cache: the same JSON paste yields the same TokenSource
// pointer across calls, but a different JSON (different RSA key →
// different SHA-256) yields a separate source.
func TestGoogleGKECredentialTokenSourceCachedBySAKey(t *testing.T) {
	keyA := buildTestSAKey(t)
	keyB := buildTestSAKey(t)
	if keyA == keyB {
		t.Fatal("test SA keys collided — RSA generator returned identical material")
	}
	tsA1, err := tokenSourceForSAKey([]byte(keyA))
	if err != nil {
		t.Fatalf("first call A: %v", err)
	}
	tsA2, err := tokenSourceForSAKey([]byte(keyA))
	if err != nil {
		t.Fatalf("second call A: %v", err)
	}
	if tsA1 != tsA2 {
		t.Errorf("same SA key did not return the cached source: %p vs %p", tsA1, tsA2)
	}
	tsB, err := tokenSourceForSAKey([]byte(keyB))
	if err != nil {
		t.Fatalf("call B: %v", err)
	}
	if tsA1 == tsB {
		t.Errorf("different SA keys returned the same cached source: %p", tsA1)
	}
}

// TestGoogleGKECredentialSecretSlots locks the single sa_key slot
// shape down; the dashboard reads this to render the credential
// card.
func TestGoogleGKECredentialSecretSlots(t *testing.T) {
	slots := (&GoogleGKECredential{}).SecretSlots()
	if len(slots) != 1 {
		t.Fatalf("want 1 slot, got %d", len(slots))
	}
	if slots[0].Name != "sa_key" {
		t.Errorf("slot name = %q, want sa_key", slots[0].Name)
	}
	if slots[0].Label == "" || slots[0].Description == "" {
		t.Errorf("slot missing label/description: %+v", slots[0])
	}
}

// buildTestSAKey builds a structurally valid GCP service-account
// JSON with a fresh RSA private key. The key cannot mint a real
// access token (Google's token endpoint doesn't know about it), but
// it parses through google.JWTConfigFromJSON the same way a real key
// does — enough to exercise the parse + cache path without a
// network round-trip.
func buildTestSAKey(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	sa := map[string]string{
		"type":         "service_account",
		"project_id":   "test-project",
		"client_email": "test-sa@test-project.iam.gserviceaccount.com",
		"private_key":  string(pemBytes),
		"token_uri":    "https://oauth2.googleapis.com/token",
	}
	b, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal sa json: %v", err)
	}
	return string(b)
}
