package main

// Per-peer API tokens. Issued at onboard-approve time, returned to
// the CLI via /api/onboard/poll, persisted by the client next to
// ca.crt. The client sends the raw token as `Authorization: Bearer
// <token>` on gated API calls (currently /api/env-pushdown). The
// server stores only the SHA-256 hash so a DB read doesn't yield
// usable bearers.
//
// Each token is pinned to the IPv4 and/or IPv6 address presented at
// /api/onboard/start (the registration HTTP call). checkPeerAPIToken
// compares the request's source against that pair on every gated
// call and tears the WG peer down on a mismatch — see
// site/doc/security-model.md "Mitigating a leaked join credential".
//
// "Source" is derived from r.RemoteAddr, not from a client header or
// the request body — both can be forged by anyone holding a leaked
// token. When the request came in over the WG tunnel (the host's
// whole-machine wg-quick is up and routes 0.0.0.0/0 via the
// tunnel), r.RemoteAddr is the wg /32 — the same string for legit
// and attacker. In that case we look up wireguard-go's remembered
// underlay endpoint for the peer (i.e. where the UDP packets were
// actually coming from at the most recent handshake), which IS the
// public source, and compare against the pin.

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
// and returns it as either v4 or v6. Unparseable hosts (a bare
// "localhost" from some test harnesses, an empty string from a
// reverse-proxy hop) return an empty pair — the pinning column then
// stays NULL, which the gate treats as fail-closed: every subsequent
// request from that peer is denied until the registration is redone
// from somewhere RemoteAddr parses to an IP.
func classifyRemoteAddr(remote string) approvedIPs {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	a, err := netip.ParseAddr(host)
	if err != nil {
		return approvedIPs{}
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
// returns "" — the caller responds 401. Failure modes:
//
//   - empty/unknown token: nothing to revoke, just deny.
//   - token with no pin recorded: this is a pre-migration row that
//     predates IP pinning. Deny — every fresh mint records a pin, so
//     a row without one is stale and must be re-issued via
//     re-approval. (Holding open a free pass for old rows would
//     defeat the point of finding 2 of clawpatrol#193.)
//   - no determinable source IP: RemoteAddr was unparseable, or the
//     request came in over WG but wireguard-go has no underlay
//     endpoint for the peer yet (no handshake observed). Deny —
//     pinning is fail-closed.
//   - mismatch: revoke the WG peer (tunnel down) and drop every
//     token row for that peer, then deny. Restoring access requires
//     re-approval in the dashboard.
//
// remoteHTTPAddr is the gated HTTP request's RemoteAddr (or any
// "ip:port" / bare-IP form). When that string is the peer's own WG
// /32, the request came through the tunnel and the wg-side address
// is uniform across legit and attacker — we then look up
// wireguard-go's remembered underlay endpoint for the peer (the IP
// the most recent UDP handshake came from) and compare that. When
// it isn't, the request hit the gateway directly over the public
// internet and RemoteAddr is itself the source we compare.
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
		// No pin on this row — pre-migration leftover. Refuse rather
		// than open a free pass. The dashboard re-approve flow mints
		// a fresh row with a pin.
		log.Printf("peer_api_token: peer %s has no pin recorded — denying (re-approve to re-pin)", peerIP)
		return ""
	}
	observed := requestSourceForPin(remoteHTTPAddr, peerIP, wg)
	if observed.V4 == "" && observed.V6 == "" {
		// Couldn't determine a source. Either the request arrived via
		// WG but wireguard-go has no endpoint for the peer (no
		// handshake completed), or RemoteAddr was a hostname /
		// reverse-proxy artefact. Deny — the doc-stated guarantee is
		// "pinned to the exact pair", not "pinned when we can".
		log.Printf("peer_api_token: no usable source IP for peer %s (remote=%q) — denying", peerIP, remoteHTTPAddr)
		return ""
	}
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

// requestSourceForPin picks the public source IP to compare against
// the pinned join credential.
//
// When RemoteAddr is the peer's own wg /32 (the request came through
// the tunnel), the wg-side string is uniform across legit and
// attacker and useless on its own — we look up wireguard-go's
// remembered underlay endpoint for the peer instead.
//
// When RemoteAddr is anything else, the request reached the gateway
// directly (the host hit the public URL without routing through wg)
// and RemoteAddr IS the public source.
//
// Returns the empty pair when no parseable source can be determined
// (caller treats that as a deny).
func requestSourceForPin(remoteHTTPAddr, peerIP string, wg underlayEndpointLookup) approvedIPs {
	host := remoteHTTPAddr
	if h, _, err := net.SplitHostPort(remoteHTTPAddr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	// Request came through the WG tunnel — look up the underlay.
	if peerIP != "" && canonicalPeerIP(host) == peerIP {
		if wg == nil {
			return approvedIPs{}
		}
		ep := wg.EndpointsByIP()[peerIP]
		if ep == "" {
			return approvedIPs{}
		}
		if h, _, err := net.SplitHostPort(ep); err == nil {
			ep = h
		}
		return classifyRemoteAddr(ep)
	}
	return classifyRemoteAddr(host)
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
