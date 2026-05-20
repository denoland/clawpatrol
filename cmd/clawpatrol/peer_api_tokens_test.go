package main

import (
	"path/filepath"
	"testing"
)

// TestPeerAPITokenRoundTrip mints a token, persists it, looks it
// up by its raw value, and confirms the lookup returns the right
// peer IP. Also confirms the raw token is NOT what's stored — only
// the hash.
func TestPeerAPITokenRoundTrip(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	token, err := mintAndPersistPeerAPIToken(db, "10.55.0.42")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	if got := peerIPForAPIToken(db, token); got != "10.55.0.42" {
		t.Errorf("peerIPForAPIToken = %q, want 10.55.0.42", got)
	}
	if got := peerIPForAPIToken(db, "wrong-token"); got != "" {
		t.Errorf("unknown token resolved to %q, want empty", got)
	}
	// Stored value should be the hash, not the raw token. Read
	// the row back and confirm.
	var stored string
	if err := db.QueryRow(`SELECT token_hash FROM peer_api_tokens WHERE peer_ip = ?`, "10.55.0.42").Scan(&stored); err != nil {
		t.Fatalf("select: %v", err)
	}
	if stored == token {
		t.Errorf("DB stored raw token instead of hash")
	}
	if stored != hashPeerAPIToken(token) {
		t.Errorf("stored hash mismatch")
	}
}

// TestBearerFromAuthHeader covers the trivial parser.
func TestBearerFromAuthHeader(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Bearer abc123", "abc123"},
		{"bearer abc123", "abc123"},
		{"BEARER xyz", "xyz"},
		{"Bearer  spaced  ", "spaced"},
		{"Basic abc", ""},
		{"", ""},
		{"abc", ""},
	}
	for _, c := range cases {
		if got := bearerFromAuthHeader(c.in); got != c.want {
			t.Errorf("bearerFromAuthHeader(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
