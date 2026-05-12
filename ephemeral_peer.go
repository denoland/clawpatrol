package main

// Ephemeral peer support: each machine running `clawpatrol run` on
// Linux gets its own WireGuard keypair and IP rather than sharing the
// permanent device's identity. Concurrent runs on a single host would
// otherwise contend for one WG session — keepalives from one process
// invalidate the other's session, causing intermittent packet loss —
// and unconditionally allocating a fresh ephemeral per invocation
// piles dozens of throwaway device rows onto the gateway dashboard.
//
// Lifecycle:
//   - First `clawpatrol run` on a host: client generates a keypair and
//     POSTs the pubkey. Gateway evicts any prior ephemeral owned by the
//     same parent device, allocates a /32, and returns it.
//   - Subsequent runs on the same host (the client persisted the
//     keypair to disk): client POSTs the SAME pubkey. Gateway finds it
//     already registered as this parent's ephemeral and returns the
//     cached IP unchanged — no new device row.
//   - The DELETE handler is retained for clients that explicitly drop
//     their ephemeral identity (uninstall / `clawpatrol leave`). Normal
//     `run` exits no longer call it: persistence across runs is the
//     whole point.

import (
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

var ephemeralAllocMu sync.Mutex

// allocateEphemeralIP picks the next unused IP in subnetCIDR.
// The DB UNIQUE constraint on wg_peers.ip is the authoritative
// safety net against concurrent allocation races.
func allocateEphemeralIP(subnetCIDR string) (string, error) {
	ephemeralAllocMu.Lock()
	defer ephemeralAllocMu.Unlock()
	used := map[string]bool{}
	if globalDB != nil {
		rows, err := globalDB.Query("SELECT ip FROM wg_peers")
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var ip string
				if rows.Scan(&ip) == nil {
					used[ip] = true
				}
			}
			if err := rows.Err(); err != nil {
				used = map[string]bool{}
			}
		}
	}
	_, cidr, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return "", err
	}
	first := cidr.IP.To4()
	for i := 2; i < 255; i++ {
		ip := net.IPv4(first[0], first[1], first[2], byte(i)).String()
		if !used[ip] {
			return ip, nil
		}
	}
	return "", fmt.Errorf("wireguard subnet %s exhausted", subnetCIDR)
}

// lookupEphemeralPeer returns (ip, parentIP, exists) for an ephemeral
// peer pubkey already in wg_peers. exists is false for unknown keys
// AND for non-ephemeral pubkeys — we deliberately refuse to clobber a
// parent device's pubkey through this endpoint.
func lookupEphemeralPeer(db *sql.DB, pubkeyHex string) (string, string, bool) {
	if db == nil || pubkeyHex == "" {
		return "", "", false
	}
	var (
		ip        string
		ephemeral int
		parentIP  sql.NullString
	)
	err := db.QueryRow(
		"SELECT ip, ephemeral, parent_ip FROM wg_peers WHERE pubkey = ?",
		pubkeyHex,
	).Scan(&ip, &ephemeral, &parentIP)
	if err != nil || ephemeral != 1 {
		return "", "", false
	}
	return ip, parentIP.String, true
}

// evictEphemeralsForParent drops every existing ephemeral peer that
// belongs to parentIP — the wg-go peer entry, the wg_peers row, the
// onboard ephemeral-profile mapping, and the agents-registry entry.
// Called when a new pubkey arrives for a parent that already has an
// ephemeral; one parent owns at most one ephemeral at a time so a
// host that lost its on-disk keypair doesn't leak the previous IP.
func evictEphemeralsForParent(g *Gateway, parentIP string) {
	if g == nil || g.db == nil || parentIP == "" {
		return
	}
	rows, err := g.db.Query(
		"SELECT ip FROM wg_peers WHERE ephemeral = 1 AND parent_ip = ?",
		parentIP,
	)
	if err != nil {
		return
	}
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			ips = append(ips, ip)
		}
	}
	_ = rows.Close()
	for _, ip := range ips {
		if globalWG != nil {
			globalWG.RevokePeerByIP(ip)
		}
		if g.onboard != nil {
			g.onboard.ForgetIP(ip)
		}
		if g.agents != nil {
			g.agents.Delete(ip)
		}
	}
}

// apiEphemeralPeer dispatches POST (add/reuse) and DELETE (remove) on
// /api/peer/ephemeral. Both require a valid per-peer bearer token.
func (w *webMux) apiEphemeralPeer(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		w.apiAddEphemeralPeer(rw, r)
	case http.MethodDelete:
		w.apiRemoveEphemeralPeer(rw, r)
	default:
		http.Error(rw, "POST or DELETE", http.StatusMethodNotAllowed)
	}
}

func (w *webMux) apiAddEphemeralPeer(rw http.ResponseWriter, r *http.Request) {
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	parentIP := peerIPForAPIToken(w.g.db, token)
	if parentIP == "" {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	if globalWG == nil || w.ts.WGSubnetCIDR == "" {
		http.Error(rw, "wireguard not active", http.StatusServiceUnavailable)
		return
	}
	pubkeyHex := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("pubkey")))
	if pubkeyHex == "" {
		http.Error(rw, "missing pubkey", http.StatusBadRequest)
		return
	}

	// Reuse path: the client persists its ephemeral keypair across
	// invocations and POSTs the same pubkey each run. If it's already
	// registered as THIS parent's ephemeral, return the existing IP
	// unchanged.
	//
	// A pubkey bound to a different parent is rejected with 409 — that
	// would otherwise let one machine hijack another's IP just by
	// guessing its pubkey.
	if existingIP, existingParent, ok := lookupEphemeralPeer(w.g.db, pubkeyHex); ok {
		if existingParent == parentIP {
			profile := w.g.onboard.ProfileForIP(parentIP)
			w.g.onboard.setEphemeralProfile(existingIP, parentIP, profile)
			ip6 := wg6FromV4(netip.MustParseAddr(existingIP)).String()
			writeJSON(rw, map[string]string{"ip": existingIP, "ip6": ip6})
			return
		}
		http.Error(rw, "pubkey already bound", http.StatusConflict)
		return
	}

	// Different pubkey but same parent → the client lost its keypair
	// cache (reboot, profile wipe). Drop the prior ephemeral entirely
	// so this parent owns at most one ephemeral IP at a time. Without
	// this every cache loss leaks an IP into wg_peers.
	evictEphemeralsForParent(w.g, parentIP)

	ip, err := allocateEphemeralIP(w.ts.WGSubnetCIDR)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := globalWG.AddPeer(pubkeyHex, ip); err != nil {
		http.Error(rw, "add peer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.g.db.Exec(
		"UPDATE wg_peers SET ephemeral=1, parent_ip=? WHERE pubkey=?",
		parentIP, pubkeyHex,
	)
	// Use ProfileForIP (not profileFor) so we don't bake "default" into
	// the record when the parent has no explicit profile. The gateway's
	// normal defaultProfileName fallback then applies per-request, same
	// as it does for the parent device.
	profile := w.g.onboard.ProfileForIP(parentIP)
	w.g.onboard.setEphemeralProfile(ip, parentIP, profile)
	ip6 := wg6FromV4(netip.MustParseAddr(ip)).String()
	writeJSON(rw, map[string]string{"ip": ip, "ip6": ip6})
}

// apiRemoveEphemeralPeer handles DELETE /api/peer/ephemeral?pubkey=<hex>.
// Only the parent device (identified by bearer token) may remove its
// own ephemeral peers. Normal `clawpatrol run` exits no longer call
// this — ephemerals persist across runs — but it's retained so an
// uninstall or explicit `leave` flow can drop the lingering identity.
func (w *webMux) apiRemoveEphemeralPeer(rw http.ResponseWriter, r *http.Request) {
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	parentIP := peerIPForAPIToken(w.g.db, token)
	if parentIP == "" {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	pubkeyHex := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("pubkey")))
	if pubkeyHex == "" {
		http.Error(rw, "missing pubkey", http.StatusBadRequest)
		return
	}
	var peerIP, storedParent string
	if err := w.g.db.QueryRow(
		"SELECT ip, parent_ip FROM wg_peers WHERE pubkey=? AND ephemeral=1",
		pubkeyHex,
	).Scan(&peerIP, &storedParent); err != nil || storedParent != parentIP {
		http.Error(rw, "not found", http.StatusNotFound)
		return
	}
	if globalWG != nil {
		globalWG.RevokePeerByIP(peerIP)
	}
	if w.g.onboard != nil {
		w.g.onboard.ForgetIP(peerIP)
	}
	if w.g.agents != nil {
		w.g.agents.Delete(peerIP)
	}
	rw.WriteHeader(http.StatusNoContent)
}
