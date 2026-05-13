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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/plugins/tailscaleproto"
)

// tailscaleConnectURLTimeout caps the apiTailscaleConnect wait for
// tsnet's first BrowseToURL emission after the handler force-acquires
// the tunnel. Long enough to cover cold-start (LocalClient init +
// IPN-bus subscription + initial control-plane round trip); short
// enough that a wedged tsnet returns awaiting_url instead of hanging
// the dashboard request.
const tailscaleConnectURLTimeout = 15 * time.Second

// tailscaleConnectLoginWindow is how long the connect handler holds
// its manager ref after returning the URL. Picks up the operator's
// browser side of the join: redirect to login.tailscale.com, approve
// the node, control-plane pushes the node-state back to our tsnet
// instance via WatchIPNBus. If the manager would otherwise tear the
// tunnel down on idle, this keeps tsnet alive long enough for the
// handshake to finish; once joined, normal traffic acquires take
// over.
const tailscaleConnectLoginWindow = 5 * time.Minute

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
//
// Lazy-tunnel case: tunnels are normally opened only when traffic
// flows through them (or pinned via `keepalive = "always"`), so a
// freshly-booted gateway that has never dialled the upstream has no
// running tsnet, no IPN-bus watcher, and nothing parked. When this
// handler finds no URL and no stored state, it actively force-acquires
// the first compiled tunnel that references the credential, blocks
// briefly on the PendingNodeAuth notify path until the watcher emits,
// and then holds the manager ref past response so the operator's
// browser side of the login can complete.
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
	policy := w.g.policy.Load()
	if _, err := lookupTailscaleAuth(policy, id); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	resp := tailscaleAuthResponse{ID: id}
	present, _ := credentialSlotPresence(w.g.db, id)
	switch {
	case len(present) > 0:
		resp.Connected = true
		resp.Status = "connected"
	default:
		if u := tailscaleproto.Default.Get(id); u != "" {
			resp.AuthURL = u
			resp.PendingURL = u
			resp.Status = "pending"
		} else if u := w.driveTailscaleLogin(r.Context(), policy, id); u != "" {
			resp.AuthURL = u
			resp.PendingURL = u
			resp.Status = "pending"
		} else {
			resp.Status = "awaiting_url"
		}
	}
	writeJSON(rw, resp)
}

// driveTailscaleLogin force-acquires the first compiled tunnel that
// references credName so tsnet's IPN-bus watcher spins up and parks a
// login URL, then waits up to tailscaleConnectURLTimeout for that URL
// to appear. On success, schedules a background release that holds
// the manager ref for tailscaleConnectLoginWindow so the operator has
// time to complete the browser side of the login before idle teardown
// fires. Returns "" if no tunnel matches, the acquire fails, or the
// watcher doesn't park a URL within the wait window.
func (w *webMux) driveTailscaleLogin(reqCtx context.Context, policy *config.CompiledPolicy, credName string) string {
	if w.g.tunnels == nil {
		return ""
	}
	ct := firstTunnelByCredential(policy, credName)
	if ct == nil {
		return ""
	}
	// The acquire/hold runs on a detached context: the request ctx
	// fires as soon as we write the response body, but the operator's
	// browser is about to redirect to login.tailscale.com and we need
	// tsnet alive for the IPN-bus callback that completes the join.
	holdCtx, holdCancel := context.WithCancel(context.Background())
	_, release, err := w.g.tunnels.Acquire(holdCtx, ct, "")
	if err != nil {
		holdCancel()
		return ""
	}
	waitCtx, waitCancel := context.WithTimeout(reqCtx, tailscaleConnectURLTimeout)
	defer waitCancel()
	u := tailscaleproto.Default.Wait(waitCtx, credName)
	if u == "" {
		release()
		holdCancel()
		return ""
	}
	go func() {
		timer := time.NewTimer(tailscaleConnectLoginWindow)
		defer timer.Stop()
		<-timer.C
		release()
		holdCancel()
	}()
	return u
}

// firstTunnelByCredential returns the compiled tunnel whose
// Credential reference resolves to credName, picking the
// lexicographically-first match for determinism across concurrent
// Connect clicks. Returns nil when no tunnel in the policy is bound
// to that credential — caller treats this as "nothing to drive" and
// falls back to awaiting_url.
func firstTunnelByCredential(policy *config.CompiledPolicy, credName string) *config.CompiledTunnel {
	if policy == nil {
		return nil
	}
	names := make([]string, 0, len(policy.Tunnels))
	for n := range policy.Tunnels {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ct := policy.Tunnels[n]
		if ct == nil || ct.Credential == nil || ct.Credential.Symbol == nil {
			continue
		}
		if ct.Credential.Symbol.Name == credName {
			return ct
		}
	}
	return nil
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

// apiTailscaleDisconnect drops every stored slot for the credential.
// On the next tunnel re-init, tsnet finds an empty StateStore and
// drives the interactive login again. Hot-restart of the tunnel
// itself is a follow-up; today the identity is reset and the next
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
	if err := clearCredentialSecrets(w.g.db, body.ID); err != nil {
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
