package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

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
