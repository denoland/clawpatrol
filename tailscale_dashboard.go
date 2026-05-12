package main

// Dashboard handlers for the `credential "tailscale" "..."` connect flow.
// Mirrors the OAuth start/revoke shape: the dashboard's Connect button
// POSTs to /api/tailscale/connect and follows the returned `auth_url`
// to tailscale.com; Disconnect wipes the persisted node state so the
// next gateway boot drives the interactive login again.
//
// The live URL itself is minted by tsnet inside the tunnel plugin and
// parked on tailscaleproto.Default. These handlers are a thin
// HTTP-shaped read/write over that side-channel plus the credential
// secrets table — no tsnet state lives in this file.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/plugins/tailscaleproto"
)

type tailscaleAuthResponse struct {
	ID         string `json:"id"`
	Connected  bool   `json:"connected"`
	AuthURL    string `json:"auth_url,omitempty"`
	PendingURL string `json:"pending_url,omitempty"`
	Status     string `json:"status"` // "connected" | "pending" | "awaiting_url"
}

// apiTailscaleConnect returns the live tsnet login URL for the
// credential named in `?id=`. The frontend POSTs to start (or
// re-fetch) the auth flow; the handler reads the PendingNodeAuth
// side-channel that the tunnel plugin writes into when tsnet emits
// a BrowseToURL notification.
//
// Three response states:
//
//   - "connected": node state already lives in credential_secrets;
//     the operator doesn't need to click Connect.
//   - "pending": tsnet has a live login URL ready — the dashboard
//     redirects the browser to it.
//   - "awaiting_url": the credential exists but tsnet hasn't emitted a
//     URL yet (tunnel may still be initializing). The dashboard polls
//     by re-POSTing to this endpoint or hitting /api/tailscale/status.
func (w *webMux) apiTailscaleConnect(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(rw, "POST or GET", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(rw, "missing id", http.StatusBadRequest)
		return
	}
	if _, err := lookupTailscaleAuth(w.g.policy.Load(), id); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	resp := tailscaleAuthResponse{ID: id}
	present, _ := credentialSlotPresence(w.g.db, id, "")
	switch {
	case len(present) > 0:
		resp.Connected = true
		resp.Status = "connected"
	default:
		if u := tailscaleproto.Default.Get(id); u != "" {
			resp.AuthURL = u
			resp.PendingURL = u
			resp.Status = "pending"
		} else {
			resp.Status = "awaiting_url"
		}
	}
	writeJSON(rw, resp)
}

// apiTailscaleStatus is the polling counterpart to /connect. Same
// shape, GET-only, no side effects. The dashboard polls this while
// the operator is mid-login on tailscale.com so the "Connect" card
// flips to "Connected" the moment tsnet finishes joining.
func (w *webMux) apiTailscaleStatus(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	w.apiTailscaleConnect(rw, r)
}

// apiTailscaleDisconnect drops every stored slot for the credential
// (owner = "" — tailscale node identity is gateway-wide). On the
// next tunnel re-init, tsnet finds an empty StateStore and drives
// the interactive login again. Hot-restart of the tunnel itself is
// a follow-up; today the gateway-wide identity is reset and the next
// gateway boot picks it up.
func (w *webMux) apiTailscaleDisconnect(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.ID == "" {
		body.ID = r.URL.Query().Get("id")
	}
	if body.ID == "" {
		http.Error(rw, "missing id", http.StatusBadRequest)
		return
	}
	if _, err := lookupTailscaleAuth(w.g.policy.Load(), body.ID); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if err := clearCredentialSecrets(w.g.db, body.ID, ""); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	tailscaleproto.Default.Set(body.ID, "")
	writeJSON(rw, map[string]any{"ok": true, "id": body.ID})
}

// lookupTailscaleAuth resolves a credential bare name to its
// TailscaleAuthProvider body, or returns a clear error when the
// credential is missing or wired to a different plugin type. Splits
// the policy lookup out of every handler so they share the same error
// wording.
func lookupTailscaleAuth(policy *config.CompiledPolicy, name string) (tailscaleproto.TailscaleAuthProvider, error) {
	if policy == nil {
		return nil, errors.New("policy not loaded")
	}
	ent, ok := policy.Credentials[name]
	if !ok {
		return nil, fmt.Errorf("no credential: %s", name)
	}
	tp, ok := ent.Body.(tailscaleproto.TailscaleAuthProvider)
	if !ok {
		return nil, fmt.Errorf("credential %q is not a tailscale node-auth credential", name)
	}
	return tp, nil
}
