package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	dst := filepath.Join(t.TempDir(), "ca.crt")
	if _, err := fetchCAHTTP(srv.URL, dst, nil); err == nil {
		t.Fatal("expected fetchCAHTTP to reject an appended second CA")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("ca.crt must not be written when the payload is rejected")
	}
}

// TestFetchCAHTTPPersistsCanonicalSingleCert: a valid single-CA payload is
// persisted as the canonical certificate the fingerprint was computed over.
func TestFetchCAHTTPPersistsCanonicalSingleCert(t *testing.T) {
	_, certPEM := inMemoryCertCache(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(certPEM)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "ca.crt")
	if _, err := fetchCAHTTP(srv.URL, dst, nil); err != nil {
		t.Fatalf("fetchCAHTTP: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(certPEM)) {
		t.Error("persisted ca.crt is not the canonical single certificate")
	}
}

func TestFetchCAHTTPReturnsFingerprintAndPersistsCert(t *testing.T) {
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

	dst := filepath.Join(t.TempDir(), "ca.crt")
	got, err := fetchCAHTTP(srv.URL, dst, nil)
	if err != nil {
		t.Fatalf("fetchCAHTTP: %v", err)
	}
	if got != want {
		t.Fatalf("returned fingerprint %q, want %q", got, want)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("dst missing after successful fetch: %v", err)
	}
}

func TestFetchCAHTTPRejectsNonPEMBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello, not a certificate"))
	}))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "ca.crt")
	if _, err := fetchCAHTTP(srv.URL, dst, nil); err == nil {
		t.Fatal("expected error for non-pem body")
	}
	// installCATrust must never see a malformed file. If a future
	// refactor wrote the body before parsing we'd silently trust
	// garbage.
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("dst should not exist after parse error")
	}
}
