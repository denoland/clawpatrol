package main

// Peer registration handlers for `clawpatrol run`:
//
//   WG mode: each invocation gets its own WireGuard keypair and IP
//   (POST /api/peer/ephemeral, DELETE on exit) so concurrent runs on
//   the same host don't fight over a single WG session.
//
//   Tailscale mode: tsnet keeps a stable per-machine identity across
//   runs (POST /api/peer/ephemeral/tsnet/register binds the tailnet
//   IP to the parent device's profile). The "ephemeral" in the path
//   is historical — the registration is persistent.
//
// Both endpoints authenticate via the per-peer Bearer token minted
// during `clawpatrol join` and stored hashed in peer_api_tokens.

import (
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
	// Re-registration after gateway restart: pubkey already has an
	// ephemeral row (kept across restarts so the WG trie survives).
	// Skip IP allocation — restore the in-memory profile and return
	// the existing IP so the client reconnects without re-joining.
	var existingIP, existingParent string
	if err := w.g.db.QueryRow(
		"SELECT ip, parent_ip FROM wg_peers WHERE pubkey=? AND ephemeral=1",
		pubkeyHex,
	).Scan(&existingIP, &existingParent); err == nil && existingParent == parentIP {
		profile := w.g.onboard.ProfileForIP(parentIP)
		w.g.onboard.setEphemeralProfile(existingIP, parentIP, profile)
		ip6 := wg6FromV4(netip.MustParseAddr(existingIP)).String()
		writeJSON(rw, map[string]string{"ip": existingIP, "ip6": ip6})
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
	profile := w.g.onboard.ProfileForIP(parentIP)
	w.g.onboard.setEphemeralProfile(ip, parentIP, profile)
	ip6 := wg6FromV4(netip.MustParseAddr(ip)).String()
	writeJSON(rw, map[string]string{"ip": ip, "ip6": ip6})
}

// apiRegisterEphemeralTsnetIP handles POST /api/peer/ephemeral/tsnet/register.
// Called by `clawpatrol run` (tsnet mode) immediately after the tsnet node
// joins and learns its 100.x.x.x address. With persistent tsnet state on the
// client, the same machine gets the same tailnet IP across runs — we assign
// the IP directly to the parent's profile and seed a real device row so the
// dashboard shows ONE entry per machine (not per ephemeral run).
func (w *webMux) apiRegisterEphemeralTsnetIP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	parentIP := peerIPForAPIToken(w.g.db, token)
	if parentIP == "" {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	tsnetIP := r.URL.Query().Get("ip")
	if tsnetIP == "" {
		http.Error(rw, "missing ip", http.StatusBadRequest)
		return
	}
	if _, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(tsnetIP, "1")); err != nil {
		http.Error(rw, "invalid ip", http.StatusBadRequest)
		return
	}
	if w.g.onboard == nil {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	profile := w.g.onboard.ProfileForIP(parentIP)
	if profile != "" {
		w.g.onboard.AssignProfile(tsnetIP, profile)
	}
	if hn := strings.TrimSpace(r.URL.Query().Get("hostname")); hn != "" {
		// Re-registration after the client wiped its tsnet state lands
		// on a different tailnet IP. Drop stale rows for this hostname
		// so the dashboard stays at one device per machine.
		_, _ = w.g.db.Exec("DELETE FROM devices WHERE name=? AND id<>?", hn, tsnetIP)
		w.g.onboard.SetHostname(tsnetIP, hn)
	}
	// Drop the synthetic `tsnet:<device_code>` row created at approve
	// time — the real row above replaces it. Repoint the parent's
	// api-token at the new tailnet IP so future register calls find
	// the profile directly via ProfileForIP(parentIP).
	if strings.HasPrefix(parentIP, "tsnet:") {
		_, _ = w.g.db.Exec("DELETE FROM devices WHERE id=?", parentIP)
		_, _ = w.g.db.Exec("UPDATE peer_api_tokens SET peer_ip=? WHERE peer_ip=?", tsnetIP, parentIP)
	}
	if w.g.agents != nil {
		w.g.agents.Seed(tsnetIP)
	}
	rw.WriteHeader(http.StatusNoContent)
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
