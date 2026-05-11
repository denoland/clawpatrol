package main

// Ephemeral peer support: each `clawpatrol run` on Linux gets its own
// WireGuard keypair and IP rather than sharing the device's permanent
// identity. Without this, concurrent runs on the same machine fight
// over a single WireGuard session — keepalives from one process
// invalidate the other's session causing intermittent packet loss.
//
// The client POSTs an ephemeral pubkey; the gateway allocates a fresh
// IP, wires it up, and inherits the parent device's profile. On clean
// exit the client DELETEs the peer. The permanent device record
// (from `clawpatrol join`) is untouched.

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
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

// apiEphemeralPeer dispatches POST (add) and DELETE (remove) on
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
	pubkeyHex := r.URL.Query().Get("pubkey")
	if pubkeyHex == "" {
		http.Error(rw, "missing pubkey", http.StatusBadRequest)
		return
	}
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
	if profile := w.g.onboard.ProfileForIP(parentIP); profile != "" {
		w.g.onboard.setEphemeralProfile(ip, profile)
	}
	ip6 := wg6FromV4(netip.MustParseAddr(ip)).String()
	writeJSON(rw, map[string]string{"ip": ip, "ip6": ip6})
}

// apiRemoveEphemeralPeer handles DELETE /api/peer/ephemeral?pubkey=<hex>.
// Only the parent device (identified by bearer token) may remove its
// own ephemeral peers.
func (w *webMux) apiRemoveEphemeralPeer(rw http.ResponseWriter, r *http.Request) {
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	parentIP := peerIPForAPIToken(w.g.db, token)
	if parentIP == "" {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	pubkeyHex := r.URL.Query().Get("pubkey")
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
