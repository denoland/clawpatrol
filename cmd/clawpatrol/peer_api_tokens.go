package main

// Per-peer API tokens. Issued at onboard-approve time, returned to
// the CLI via /api/onboard/poll, persisted by the client next to
// ca.crt. The client sends the raw token as `Authorization: Bearer
// <token>` on gated API calls (currently /api/env-pushdown). The
// server stores only the SHA-256 hash so a DB read doesn't yield
// usable bearers.

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// mintAndPersistPeerAPIToken generates a fresh bearer for peerIP,
// stores its hash in peer_api_tokens, and returns the raw token
// to the caller. The raw token is never written to disk.
func mintAndPersistPeerAPIToken(db *sql.DB, peerIP string) (string, error) {
	if db == nil {
		return "", fmt.Errorf("nil db")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := hashPeerAPIToken(token)
	_, err := db.Exec(
		`INSERT INTO peer_api_tokens (token_hash, peer_ip, created_ns) VALUES (?, ?, ?)`,
		hash, peerIP, time.Now().UnixNano(),
	)
	if err != nil {
		return "", fmt.Errorf("insert peer_api_tokens: %w", err)
	}
	return token, nil
}

// peerIPForAPIToken looks the bearer hash up in peer_api_tokens.
// Returns the peer's IP, or empty when the token is unknown.
func peerIPForAPIToken(db *sql.DB, token string) string {
	if db == nil || token == "" {
		return ""
	}
	hash := hashPeerAPIToken(token)
	var ip string
	if err := db.QueryRow(
		`SELECT peer_ip FROM peer_api_tokens WHERE token_hash = ?`, hash,
	).Scan(&ip); err != nil {
		return ""
	}
	return ip
}

// hashPeerAPIToken hashes a raw bearer for the lookup table.
// SHA-256 is fine here — the token is a uniformly-random 256-bit
// value, not a password, so we don't need a password hash.
func hashPeerAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// bearerFromAuthHeader pulls the value out of an `Authorization:
// Bearer <token>` header. Returns empty when the header is missing
// or doesn't use the Bearer scheme.
func bearerFromAuthHeader(h string) string {
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
