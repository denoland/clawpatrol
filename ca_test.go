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
	"testing"
	"time"
)

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
