package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFetchCAHTTPRejectsAppendedCA (round-6 #1): a payload of
// `legitimate-CA || attacker-CA` must be rejected — otherwise the operator
// confirms the legitimate first-cert fingerprint out-of-band while the appended
// attacker CA is silently written and trusted (a TOFU bypass).
func TestFetchCAHTTPRejectsAppendedCA(t *testing.T) {
	_, legitPEM := inMemoryCertCache(t)
	_, attackerPEM := inMemoryCertCache(t)
	payload := append(append([]byte{}, legitPEM...), attackerPEM...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	if _, _, err := fetchCAHTTP(srv.URL, nil); err == nil {
		t.Fatal("expected fetchCAHTTP to reject an appended second CA")
	}
}

// TestFetchCAHTTPReturnsCanonicalSingleCert: a valid single-CA payload is
// returned as the canonical certificate the fingerprint was computed over.
func TestFetchCAHTTPReturnsCanonicalSingleCert(t *testing.T) {
	_, certPEM := inMemoryCertCache(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(certPEM)
	}))
	defer srv.Close()

	got, _, err := fetchCAHTTP(srv.URL, nil)
	if err != nil {
		t.Fatalf("fetchCAHTTP: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(certPEM)) {
		t.Error("returned CA is not the canonical single certificate")
	}
}

func TestFetchCAHTTPReturnsFingerprintAndCert(t *testing.T) {
	_, certPEM := inMemoryCertCache(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(certPEM)
	}))
	defer srv.Close()

	want, err := caFingerprintFromPEM(certPEM)
	if err != nil {
		t.Fatalf("expected fp: %v", err)
	}

	gotCert, got, err := fetchCAHTTP(srv.URL, nil)
	if err != nil {
		t.Fatalf("fetchCAHTTP: %v", err)
	}
	if got != want {
		t.Fatalf("returned fingerprint %q, want %q", got, want)
	}
	if !bytes.Equal(bytes.TrimSpace(gotCert), bytes.TrimSpace(certPEM)) {
		t.Fatal("returned certificate does not match fetched certificate")
	}
}

func TestFetchCAHTTPRejectsNonPEMBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello, not a certificate"))
	}))
	defer srv.Close()
	if _, _, err := fetchCAHTTP(srv.URL, nil); err == nil {
		t.Fatal("expected error for non-pem body")
	}
}
