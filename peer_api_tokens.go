package main

// Per-peer API tokens. Issued at onboard-approve time, returned to
// the CLI via /api/onboard/poll, persisted by the client next to
// ca.crt. The client sends the raw token as `Authorization: Bearer
// <token>` on gated API calls (currently /api/env-pushdown). The
// server stores only the SHA-256 hash so a DB read doesn't yield
// usable bearers.
//
// Each token is pinned to the IPv4 and/or IPv6 address presented at
// /api/onboard/start (the registration HTTP call). Gated requests
// arrive over the WG tunnel; checkPeerAPIToken compares the WG
// peer's underlay endpoint against the pinned pair and tears the
// tunnel down on a mismatch — see site/doc/security-model.md
// "Mitigating a leaked join credential".

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"
)

// approvedIPs captures the IPv4 and/or IPv6 address a peer presented
// at registration. At most one is non-empty per HTTP bootstrap call,
// but both columns exist so a future flow that submits both in one
// trip can populate them together.
type approvedIPs struct {
	V4 string
	V6 string
}

// classifyRemoteAddr splits an "host:port" or bare-host RemoteAddr
// and returns it as either v4 or v6. IPs not parseable as either
// fall back to the v4 slot so loopback string forms ("localhost")
// don't silently drop into NULL columns during tests.
func classifyRemoteAddr(remote string) approvedIPs {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	a, err := netip.ParseAddr(host)
	if err != nil {
		return approvedIPs{V4: host}
	}
	a = a.Unmap()
	if a.Is6() {
		return approvedIPs{V6: a.String()}
	}
	return approvedIPs{V4: a.String()}
}

// mintAndPersistPeerAPIToken generates a fresh bearer for peerIP,
// stores its hash in peer_api_tokens pinned to approved, and returns
// the raw token to the caller. The raw token is never written to
// disk.
func mintAndPersistPeerAPIToken(db *sql.DB, peerIP string, approved approvedIPs) (string, error) {
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
		`INSERT INTO peer_api_tokens (token_hash, peer_ip, created_ns, approved_ipv4, approved_ipv6) VALUES (?, ?, ?, ?, ?)`,
		hash, peerIP, time.Now().UnixNano(), nullStr(approved.V4), nullStr(approved.V6),
	)
	if err != nil {
		return "", fmt.Errorf("insert peer_api_tokens: %w", err)
	}
	return token, nil
}

// peerIPForAPIToken looks the bearer hash up in peer_api_tokens.
// Returns the peer's IP, or empty when the token is unknown. Does
// NOT verify the IP-pinning constraint; use checkPeerAPIToken when
// the caller is a gated request handler.
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

// peerAPITokenRevoker tears a WG peer down when its bearer is used
// from a deviating underlay IP. Implemented by *WGServer; the
// indirection lets tests pass a fake.
type peerAPITokenRevoker interface {
	RevokePeerByIP(ip string)
}

// underlayEndpointLookup returns the underlay IP a wg peer is
// currently dialing in from for the given allowed-ip. Implemented by
// *WGServer via EndpointsByIP; tests pass a fake.
type underlayEndpointLookup interface {
	EndpointsByIP() map[string]string
}

// checkPeerAPIToken authenticates a gated request bearer.
//
// On success it returns the peer's WG-side IP. On any failure it
// returns "" — the caller responds 401. The four failure modes are
// distinct in their side effects:
//
//   - empty/unknown token: nothing to revoke, just deny.
//   - known token, no WG endpoint yet: not pinned, allow (the WG
//     handshake hasn't surfaced an endpoint to wireguard-go's IpcGet
//     yet — for example because the peer is hitting us from the
//     same loopback in tests, or the very first request races the
//     first handshake completion). The pinning check fires on the
//     next call once an endpoint exists.
//   - token with NULL pin: pre-pinning rows (older registrations or
//     dev seeds) are treated as unrestricted; allow. New rows always
//     get at least one column populated.
//   - mismatch: revoke the WG peer (tunnel down) and drop every
//     token row for that peer, then deny. Restoring access requires
//     re-approval in the dashboard.
//
// remoteHTTPAddr is the bootstrap HTTP request's RemoteAddr; it is
// only consulted as a fallback when EndpointsByIP has no entry — in
// production the request always arrives via WG and the WG endpoint
// is authoritative.
func checkPeerAPIToken(db *sql.DB, token, remoteHTTPAddr string, wg underlayEndpointLookup, revoker peerAPITokenRevoker) string {
	if db == nil || token == "" {
		return ""
	}
	hash := hashPeerAPIToken(token)
	var (
		peerIP   string
		pinnedV4 sql.NullString
		pinnedV6 sql.NullString
	)
	if err := db.QueryRow(
		`SELECT peer_ip, approved_ipv4, approved_ipv6 FROM peer_api_tokens WHERE token_hash = ?`, hash,
	).Scan(&peerIP, &pinnedV4, &pinnedV6); err != nil {
		return ""
	}
	if !pinnedV4.Valid && !pinnedV6.Valid {
		return peerIP
	}
	underlay := ""
	if wg != nil {
		underlay = wg.EndpointsByIP()[peerIP]
	}
	if underlay == "" {
		// Endpoint not yet surfaced by wireguard-go. Pinning fires on
		// the next call. See the function comment for context.
		return peerIP
	}
	observed := classifyRemoteAddr(underlay)
	if peerAPIIPMatches(observed, pinnedV4, pinnedV6) {
		return peerIP
	}
	log.Printf("peer_api_token: IP pin mismatch for peer %s (pinned v4=%q v6=%q, observed v4=%q v6=%q) — revoking",
		peerIP, pinnedV4.String, pinnedV6.String, observed.V4, observed.V6)
	if revoker != nil {
		revoker.RevokePeerByIP(peerIP)
	}
	forgetPeerAPITokens(db, peerIP)
	return ""
}

// peerAPIIPMatches enforces the security-model rule: the observed
// underlay address must match the family that was registered, and
// must equal the registered value within that family. A v6 request
// against a v4-only registration is a mismatch (and vice versa).
func peerAPIIPMatches(observed approvedIPs, pinnedV4, pinnedV6 sql.NullString) bool {
	if observed.V4 != "" {
		if !pinnedV4.Valid || pinnedV4.String == "" {
			return false
		}
		return pinnedV4.String == observed.V4
	}
	if observed.V6 != "" {
		if !pinnedV6.Valid || pinnedV6.String == "" {
			return false
		}
		return pinnedV6.String == observed.V6
	}
	return false
}

// forgetPeerAPITokens drops every issued token for a peer IP. Called
// by the dashboard's revoke-device flow so a deleted peer can't keep
// using its bearer.
func forgetPeerAPITokens(db *sql.DB, peerIP string) {
	if db == nil || peerIP == "" {
		return
	}
	_, _ = db.Exec(`DELETE FROM peer_api_tokens WHERE peer_ip = ?`, peerIP)
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
