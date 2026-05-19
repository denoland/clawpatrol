package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

// generated CA fingerprints are 32 bytes of SHA-256 → 64 hex chars
// → 32 colon-separated pairs, all uppercase. Matches the shape
// `openssl x509 -fingerprint -sha256` produces.
var fingerprintShape = regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2}){31}$`)

// inMemoryCertCache mints a throwaway CA suitable for handler tests.
// Mirrors mintAndStoreCA's shape but skips the database round-trip so
// tests don't need a sqlite fixture.
func inMemoryCertCache(t *testing.T) (*CertCache, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "clawpatrol test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	cc, err := parseCertCache(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertCache: %v", err)
	}
	return cc, certPEM
}

func TestServeCAServesInMemoryPEM(t *testing.T) {
	cc, certPEM := inMemoryCertCache(t)
	w := &webMux{g: &Gateway{certs: cc}}

	rr := httptest.NewRecorder()
	w.serveCA(rr, httptest.NewRequest(http.MethodGet, "/ca.crt", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/x-pem-file" {
		t.Fatalf("Content-Type = %q", got)
	}
	if !bytes.Equal(rr.Body.Bytes(), certPEM) {
		t.Fatalf("body mismatch\n got: %q\nwant: %q", rr.Body.Bytes(), certPEM)
	}
}

func TestServeCAUnavailableBeforeMint(t *testing.T) {
	// An empty CertCache (no minted material yet) should not 200 with
	// an empty body — clients expect to write the bytes to disk and
	// trust them.
	w := &webMux{g: &Gateway{certs: &CertCache{}}}

	rr := httptest.NewRecorder()
	w.serveCA(rr, httptest.NewRequest(http.MethodGet, "/ca.crt", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestCAFingerprintFromPEMShapeAndStability(t *testing.T) {
	_, certPEM := inMemoryCertCache(t)
	fp, err := caFingerprintFromPEM(certPEM)
	if err != nil {
		t.Fatalf("caFingerprintFromPEM: %v", err)
	}
	if !fingerprintShape.MatchString(fp) {
		t.Fatalf("fingerprint %q does not match expected shape", fp)
	}
	// Re-running over the same bytes must yield the same string;
	// the fingerprint is what we tell the operator to compare
	// against the dashboard, so a non-deterministic value would
	// silently break the visual check.
	fp2, err := caFingerprintFromPEM(certPEM)
	if err != nil {
		t.Fatalf("caFingerprintFromPEM (second): %v", err)
	}
	if fp != fp2 {
		t.Fatalf("fingerprint not stable: %q vs %q", fp, fp2)
	}
}

func TestCAFingerprintFromPEMRejectsNonCert(t *testing.T) {
	if _, err := caFingerprintFromPEM([]byte("not a pem block")); err == nil {
		t.Fatal("expected error for bogus pem, got nil")
	}
	wrongType := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	if _, err := caFingerprintFromPEM([]byte(wrongType)); err == nil {
		t.Fatal("expected error for non-CERTIFICATE pem, got nil")
	}
}

func TestTwoCAsHaveDifferentFingerprints(t *testing.T) {
	_, a := inMemoryCertCache(t)
	_, b := inMemoryCertCache(t)
	fa, err := caFingerprintFromPEM(a)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	fb, err := caFingerprintFromPEM(b)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if fa == fb {
		t.Fatalf("freshly generated CAs share a fingerprint: %s", fa)
	}
}
