//go:build linux

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestClaimPeerAPITokenUsesInjectedClient(t *testing.T) {
	dir := t.TempDir()
	called := false
	cli := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.URL.Host != "tailnet-only.invalid" {
			t.Fatalf("claim host = %q", req.URL.Host)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"api_token":"peer-secret"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	err := claimPeerAPITokenAtURL("http://tailnet-only.invalid/api/onboard/claim", "100.64.0.2", dir, cli)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("injected transport was not used")
	}
	assertClaimToken(t, dir, "peer-secret\n")
}

func TestClaimPeerAPITokenUsesDefaultClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Errorf("method = %q", req.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"api_token":"public-secret"}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	if err := claimPeerAPITokenAtURL(server.URL, "100.64.0.3", dir, nil); err != nil {
		t.Fatal(err)
	}
	assertClaimToken(t, dir, "public-secret\n")
}

func assertClaimToken(t *testing.T, dir, want string) {
	t.Helper()
	path := filepath.Join(dir, "api-token")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("api-token = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("api-token mode = %o, want 600", perm)
	}
}
