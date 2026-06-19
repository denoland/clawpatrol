package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/endpoints"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// internalHostname is the reserved name an agent inside the tunnel
// hits to reach the clawpatrol API — the canonical entrypoint for a
// device. The gateway intercepts a TLS connection whose SNI is this
// name and answers locally — the request never leaves the box. DNS for
// the name resolves to the reserved VIP pair the dnsvip allocator hands
// back (see dnsvip's InternalVIPs), but because the WG forwarder routes
// every :443 SYN through g.handle regardless of dst IP, any IP the
// agent was handed lands here as long as the SNI matches. Keep this in
// sync with dnsvip.InternalHostname.
const internalHostname = "clawpatrol.internal"

// hitlPendingPath is the internal-API path where a device lists every
// request it currently has parked awaiting human approval. The full URL is
// `https://` + internalHostname + this path.
const hitlPendingPath = "/pending"

// isInternalHost reports whether host names the reserved internal API
// endpoint. The match is case-insensitive (DNS is) and tolerates a
// trailing dot and an explicit :443 suffix, both of which clients may
// attach to the authority.
func isInternalHost(host string) bool {
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == internalHostname
}

// serveInternal terminates TLS for a reserved-name connection and
// answers it from the internal API surface (manifest, CA, info). The
// profile is resolved from the connection's peer IP (the same
// connection-derived identity the request handler uses) — never from a
// token — so the manifest reflects exactly this device's grants.
// certHost is the SNI (or the dst VIP on the IP-literal fallback path);
// we mint a leaf for it so the agent's CA-trusting client accepts the
// handshake.
func (g *Gateway) serveInternal(c net.Conn, certHost string) {
	defer func() { _ = c.Close() }()
	defer otelTrackConn("internal")()
	profile := g.profileFor(peerIP(c))
	// Principal is the canonical agent identity the HITL request path
	// stamps onto a parked operation (main.go: agentAddr = agentIPFor(c),
	// principal = hitlPeerPrincipalID(agentAddr)). Resolve it the same way
	// here so the internal poll endpoint can scope an operation lookup to
	// exactly the device that parked it, alias remapping and all. agentIP
	// is the pre-principal address the in-memory HITL pool stamps onto its
	// entries (HITLPending.AgentIP), so /pending can scope the sync-only
	// pool the same way it scopes the DB lookup.
	agentIP := g.agentIPFor(c)
	principal := hitlPeerPrincipalID(agentIP)
	cert, err := g.certs.mint(certHost)
	if err != nil {
		log.Printf("internal: mint %s: %v", certHost, err)
		return
	}
	tc := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		log.Printf("internal: tls %s: %v", certHost, err)
		return
	}
	defer func() { _ = tc.Close() }()
	policy := g.Policy()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.routeInternal(w, r, policy, profile, principal, agentIP)
	})
	_ = http.Serve(&oneShotListener{c: tc}, h)
}

// routeInternal dispatches a request to the in-tunnel internal API
// entrypoint by path. clawpatrol.internal is the canonical device-facing
// API surface, so it exposes the profile manifest at / and /manifest,
// the gateway CA at /ca.crt, a liveness + CA-fingerprint blob at /info —
// the same public endpoints the gateway's tailnet web server serves,
// mirrored here so a device with only tunnel reachability can fetch them
// by name — and the list of the device's parked-for-approval requests at
// /pending. Unknown paths 404 rather than falling through to the manifest,
// so the canonical paths stay unambiguous.
func (g *Gateway) routeInternal(w http.ResponseWriter, r *http.Request, policy *config.CompiledPolicy, profile, principal, agentIP string) {
	switch r.URL.Path {
	case "/", "/manifest":
		writeDiscoveryResponse(w, r, policy, profile)
	case "/ca.crt":
		g.serveInternalCA(w)
	case "/info":
		g.serveInternalInfo(w)
	case hitlPendingPath:
		g.serveInternalPending(w, r, profile, principal, agentIP)
	default:
		http.NotFound(w, r)
	}
}

// serveInternalPending answers clawpatrol.internal/pending with the list of
// this device's parked actions — requests gated behind human approval that
// are still awaiting a decision, held with no upstream side effect yet. The
// caller is resolved from the connection-derived profile/principal (the same
// identity that parked the request), never a token, so a device only ever
// sees the actions it parked.
//
// This is the sync-HITL way to see what is waiting on a human: the request
// is parked synchronously (its connection held open until a person decides),
// so the agent needs no operation handle to track it — it just lists what is
// currently held for its device.
//
// Two stores hold parked requests and /pending must union them:
//   - The operation store (DB) holds requests that took the async-grant path
//     (sync_waiting / pending_approval rows). Scoped by profile+principal.
//   - The in-memory HITL pool holds every park, including the PURE-SYNC case
//     (a human approver with no async grant) that never writes a DB row.
//     Reading only the DB would return [] on a sync-only deployment — exactly
//     the case the manifest tells the agent to use /pending for.
//
// De-dup falls out of the operation id: buildPending sets OperationID to the
// async operation id, so a pool entry with OperationID == "" is a pure-sync
// park that is NOT in the DB, while OperationID != "" is already covered by a
// DB row. So we take the DB rows plus the pool entries that have no operation
// id and were parked by this caller (AgentIP match) — covering the sync case,
// leaving the async case unchanged, and never double-listing.
func (g *Gateway) serveInternalPending(w http.ResponseWriter, r *http.Request, profile, principal, agentIP string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Collect (parked_at, view) so the merged DB+pool list can be ordered
	// newest-first regardless of which store each entry came from.
	type entry struct {
		at   time.Time
		view map[string]any
	}
	var entries []entry
	if g.db != nil {
		ops, err := NewHITLOperationStore(g.db).ListParkedForPrincipal(r.Context(), profile, principal)
		if err != nil {
			log.Printf("internal: pending list: %v", err)
			http.Error(w, "load pending actions", http.StatusInternalServerError)
			return
		}
		for _, op := range ops {
			entries = append(entries, entry{op.CreatedAt, pendingActionView(op)})
		}
	}
	if g.hitl != nil {
		for _, p := range g.hitl.List() {
			if p.OperationID != "" || p.AgentIP != agentIP {
				continue
			}
			entries = append(entries, entry{p.CreatedAt, pendingPoolView(p)})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].at.After(entries[j].at) })
	pending := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		pending = append(pending, e.view)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"pending": pending})
}

// pendingActionView is the redacted, secret-free description of one parked
// action returned by /pending — enough for an agent or operator to tell
// which held request is which (method + endpoint + redacted target) without
// exposing credentials or any async-poll machinery (no operation id, no
// status token).
func pendingActionView(op HITLOperation) map[string]any {
	v := map[string]any{
		"endpoint":  op.EndpointID,
		"method":    op.Method,
		"url":       op.Scheme + "://" + op.Host + op.RedactedPath,
		"parked_at": op.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if op.RedactedQuery != "" {
		v["query"] = op.RedactedQuery
	}
	if !op.ApprovalExpiresAt.IsZero() {
		v["approval_expires_at"] = op.ApprovalExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return v
}

// pendingPoolView renders one in-memory pending HITL entry — a pure-sync
// park that never reached the operation store — into the same redacted view
// shape pendingActionView produces for a DB row, so /pending presents both
// sources identically. The pool entry carries no scheme (the gateway only
// MITMs TLS, so it is always https, matching the operation store's hardcoded
// "https") and its Path is the raw request URI, so the query string is
// dropped here to match the DB path's redaction (RedactedPath is the path
// component only, RedactedQuery is left empty). HITLPending.Endpoint is the
// same label the DB stores as EndpointID — the endpoint config name for HTTP,
// the resource/host for SQL and k8s.
func pendingPoolView(p runtime.HITLPending) map[string]any {
	path := p.Path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	v := map[string]any{
		"endpoint":  p.Endpoint,
		"method":    p.Method,
		"url":       "https://" + p.Host + path,
		"parked_at": p.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if !p.ExpiresAt.IsZero() {
		v["approval_expires_at"] = p.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return v
}

// serveInternalCA returns the gateway CA in PEM form at
// clawpatrol.internal/ca.crt. A client that trusts neither the system
// store nor the pushed-down CA env vars can fetch the CA here and pin it
// explicitly — the manifest text points at this path. Mirrors the
// gateway web server's public /ca.crt (web.go serveCA).
func (g *Gateway) serveInternalCA(w http.ResponseWriter) {
	pemBytes := g.certs.CertPEM()
	if len(pemBytes) == 0 {
		http.Error(w, "ca not initialized", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Length", strconv.Itoa(len(pemBytes)))
	_, _ = w.Write(pemBytes)
}

// serveInternalInfo answers clawpatrol.internal/info with a small
// liveness + identity blob carrying the CA fingerprint, so a client can
// verify the CA it fetched from /ca.crt against an out-of-band value.
// Mirrors the gateway web server's public /info (web.go serveInfo).
func (g *Gateway) serveInternalInfo(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fp := ""
	if pem := g.certs.CertPEM(); len(pem) > 0 {
		if f, err := caFingerprintFromPEM(pem); err == nil {
			fp = f
		}
	}
	writeJSON(w, map[string]any{
		"clawpatrol":     true,
		"version":        "0.1",
		"ca_fingerprint": fp,
	})
}

// isInternalVIP reports whether dstIP is the fixed VIP the dnsvip
// allocator reserves for the internal API name — the signal the
// IP-literal fallback path keys on when there's no SNI.
func (g *Gateway) isInternalVIP(dstIP string) bool {
	if g.dnsvip == nil {
		return false
	}
	addr, err := netip.ParseAddr(dstIP)
	if err != nil {
		return false
	}
	v4, v6 := g.dnsvip.InternalVIPs()
	return addr == v4 || addr == v6
}

// DiscoveryManifest is the one internal representation both output
// formats render from. It describes, scoped to a single device
// profile, exactly which endpoints and credentials the caller can use
// and how to reach each one. It is computed live from the calling
// device's current profile — it is NOT a dump of the whole gateway
// config.
type DiscoveryManifest struct {
	Profile     string                `json:"profile"`
	Endpoints   []DiscoveryEndpoint   `json:"endpoints"`
	Credentials []DiscoveryCredential `json:"credentials"`
	// EnvVars lists the environment variables `clawpatrol run` pushes
	// into the agent's process environment for THIS profile — the same
	// set the env-pushdown API serves. An agent reads its credential
	// out of one of these vars without ever seeing the real secret, so
	// it needs to know which of its env vars the gateway controls and
	// what each one carries.
	EnvVars []DiscoveryEnvVar `json:"env_vars"`
	// Notes carries profile-level caveats — e.g. the profile resolved
	// to a name with no policy entry, so the manifest is empty.
	Notes []string `json:"notes,omitempty"`
	// Dashboard is the gateway's public URL (gateway.public_url), where a
	// human operator configures this device's profile. Surfaced so an
	// agent whose profile grants nothing can tell its human where to go.
	// Empty when public_url is unset.
	Dashboard string `json:"dashboard,omitempty"`
	// HITL documents human-in-the-loop approval for this profile: that a
	// matching request may be parked pending human approval (possibly
	// indefinitely), which of the profile's endpoints carry such rules,
	// and how to poll a parked request's approval status. Always present
	// on a non-empty manifest so an agent learns the mechanism before it
	// trips a gated rule.
	HITL *DiscoveryHITL `json:"hitl,omitempty"`
}

// DiscoveryHITL is the profile-scoped human-in-the-loop summary embedded
// in the manifest. Rendered from a single representation into both output
// formats, like the rest of the manifest.
type DiscoveryHITL struct {
	// Explanation is the human/LLM-readable description of how parking and
	// polling work. Carried in the JSON and rendered verbatim into the
	// markdown HITL section so both consumers get identical guidance.
	Explanation string `json:"explanation"`
	// GatedEndpoints names this profile's endpoints (sorted) whose rules
	// may park a request for human approval. Mirrors DiscoveryEndpoint.HITL
	// as a top-level summary; empty when no endpoint is gated.
	GatedEndpoints []string `json:"gated_endpoints"`
	// PendingPath is the internal-API path where the device lists every
	// request it currently has parked awaiting human approval. The full URL
	// is `https://` + the internal host + this path.
	PendingPath string `json:"pending_path"`
	// Async documents the asynchronous-approval fallback: when a gated
	// endpoint is configured to hand back a 202 after a synchronous wait
	// window instead of holding the connection indefinitely. Present only
	// when at least one of this profile's endpoints can go async; nil on a
	// purely synchronous deployment so the sync docs above stand alone.
	Async *DiscoveryHITLAsync `json:"async,omitempty"`
}

// DiscoveryHITLAsync documents the async-approval fallback for this
// profile: the 202-then-poll protocol an agent follows when a gated
// request is not approved within an endpoint's synchronous wait window.
// Every field is rendered from the live serving constants so the
// documented flow can't drift from the served one.
type DiscoveryHITLAsync struct {
	// Explanation is the human/LLM-readable description of the 202 + poll +
	// retry protocol, with the exact response field names the agent reads.
	// Carried in JSON and rendered verbatim into the markdown async
	// subsection so both consumers get identical guidance.
	Explanation string `json:"explanation"`
	// StatusPathTemplate is the path template for the status-polling
	// endpoint, with `{operation_id}` standing in for the parked
	// operation's id. The concrete, ready-to-poll URL is returned in the
	// 202's `status_url` field (and Location header); this template only
	// shows the shape.
	StatusPathTemplate string `json:"status_path_template"`
	// RetryHeader is the request header an agent sets, with the operation
	// id as its value, when it retries the original request after approval.
	RetryHeader string `json:"retry_header"`
	// PollIntervalSeconds is the gateway's suggested poll interval — the
	// value it puts in the Retry-After header on a 202 and on a still-pending
	// status response.
	PollIntervalSeconds int `json:"poll_interval_seconds"`
	// Endpoints lists, per gated endpoint that can go async, the
	// synchronous wait window before it returns a 202 and how long the
	// parked operation then stays pollable.
	Endpoints []DiscoveryHITLAsyncEndpoint `json:"endpoints"`
}

// DiscoveryHITLAsyncEndpoint is one gated endpoint's async timing: the
// synchronous wait window after which a still-unapproved request returns
// a 202, and the lifetime of the parked operation once it goes async.
type DiscoveryHITLAsyncEndpoint struct {
	Name string `json:"name"`
	// SyncWait is the synchronous hold window (sync_wait_timeout). A request
	// to this endpoint that a human has not decided within this window
	// returns a 202 and continues asynchronously.
	SyncWait string `json:"sync_wait"`
	// PollTTL is how long the operation stays pollable after it goes async
	// (the approver's overall timeout minus the sync wait window). Once it
	// elapses with no decision the operation becomes `expired`.
	PollTTL string `json:"poll_ttl"`
}

// isEmpty reports whether the profile grants nothing — no endpoints and
// no credentials. This is the state the empty-profile guidance speaks
// to: a manifest that lists nothing actionable is useless to an agent
// unless it explains why and how to fix it.
func (m *DiscoveryManifest) isEmpty() bool {
	return len(m.Endpoints) == 0 && len(m.Credentials) == 0
}

// DiscoveryEndpoint is one reachable endpoint plus the full how-to for
// connecting to it: protocol/type, host(s)/port(s), database/path
// where applicable, and the credential(s) the profile can present.
//
// Deliberately omits any tunnel the endpoint sits behind. The gateway
// intercepts the agent's connection transparently and brings the tunnel
// up itself — the agent dials the host below either way and can't act on
// the tunnel's name or type, so reporting it would only be noise.
type DiscoveryEndpoint struct {
	Name   string `json:"name"`
	Type   string `json:"type"`   // plugin type: https, postgres, kubernetes, ...
	Family string `json:"family"` // http | sql | k8s | ssh
	// Description is the operator's free-text note from the endpoint
	// block's `description = "..."`, surfaced to orient the agent.
	Description string                   `json:"description,omitempty"`
	Hosts       []string                 `json:"hosts,omitempty"`
	Port        int                      `json:"port,omitempty"`
	Database    string                   `json:"database,omitempty"`
	SSLMode     string                   `json:"sslmode,omitempty"`
	Path        string                   `json:"path,omitempty"`
	Credentials []DiscoveryCredentialRef `json:"credentials"`
	// Hint is a concrete client invocation when the protocol makes one
	// unambiguous (psql / kubectl / clickhouse-client / ssh / curl).
	Hint string `json:"hint,omitempty"`
	// HITL is true when at least one enabled rule on this endpoint routes
	// matching requests through a human approver — so a request here may be
	// parked pending human approval and held indefinitely. The agent must
	// not treat a slow/hanging request to this endpoint as a failure; it
	// should poll the approval-status endpoint (see DiscoveryManifest.HITL)
	// instead. Rules approved purely by an automated (llm) approver do NOT
	// set this — they don't wait on a human.
	HITL bool `json:"hitl,omitempty"`
}

// DiscoveryCredentialRef is a credential the profile can present at a
// specific endpoint. Placeholder is the literal string the agent sends
// where a secret would go (the gateway swaps it for the real secret);
// Disambiguators carries non-placeholder dispatch fields (postgres /
// clickhouse user + database) so the agent connects with the values
// that route to this credential.
type DiscoveryCredentialRef struct {
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Placeholder    string            `json:"placeholder,omitempty"`
	Disambiguators map[string]string `json:"disambiguators,omitempty"`
	// Description is the operator's free-text note from the credential
	// block's `description = "..."`, surfaced to orient the agent.
	Description string `json:"description,omitempty"`
}

// DiscoveryCredential is the profile-level view of one credential: its
// type, placeholder, and the endpoints it authenticates against that
// this profile can reach.
type DiscoveryCredential struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Placeholder string   `json:"placeholder,omitempty"`
	Endpoints   []string `json:"endpoints,omitempty"`
	// Description is the operator's free-text note from the credential
	// block's `description = "..."`, surfaced to orient the agent.
	Description string `json:"description,omitempty"`
}

// DiscoveryEnvVar is one environment variable `clawpatrol run` exports
// into the agent's process so its CLI/SDK finds its credential without
// the agent ever holding the real secret. Value is the literal the
// gateway sets — a placeholder that LOOKS like a real token (swapped
// for the secret at MITM time) or a synthetic token — NOT the secret
// itself. Type is the credential/endpoint plugin that pushes it.
type DiscoveryEnvVar struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`
}

// buildDiscoveryManifest computes the manifest for one profile from the
// compiled policy. It reuses the same per-profile resolution the
// request handler walks — CompiledProfile.Endpoints and
// EndpointCredentials — so the manifest reports exactly what dispatch
// would honor, nothing more. A profile name with no policy entry (the
// default-profile fallback for an unrecognised device) yields an empty
// manifest with an explanatory note rather than an error.
func buildDiscoveryManifest(policy *config.CompiledPolicy, profileName string) *DiscoveryManifest {
	m := &DiscoveryManifest{Profile: profileName, Endpoints: []DiscoveryEndpoint{}, Credentials: []DiscoveryCredential{}}
	if policy == nil {
		m.Notes = append(m.Notes, "gateway has no compiled policy loaded")
		return m
	}
	prof := policy.Profiles[profileName]
	if prof == nil {
		m.Notes = append(m.Notes, fmt.Sprintf("profile %q grants no endpoints or credentials", profileName))
		m.Dashboard = policy.DashboardURL
		return m
	}

	// Endpoints, in a stable name order so the manifest is byte-stable
	// across calls (agents may diff it; tests assert on it).
	names := make([]string, 0, len(prof.Endpoints))
	for name := range prof.Endpoints {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ep := prof.Endpoints[name]
		if ep == nil {
			continue
		}
		de := describeEndpoint(ep)
		de.Credentials = profileEndpointCredentials(prof, name)
		if len(de.Credentials) == 0 {
			// Reachable in this profile but no credential dispatches to
			// it — the agent should know the boundary instead of
			// flailing with an endpoint it can't authenticate to.
			de.Credentials = []DiscoveryCredentialRef{}
		}
		de.Hint = connectionHint(de)
		de.HITL = endpointHasHITL(policy, ep)
		m.Endpoints = append(m.Endpoints, de)
	}

	// Credentials: what the profile HAS. Endpoints listed per credential
	// are intersected with the profile's reachable set so the agent sees
	// the boundary, not the whole config.
	for _, ent := range prof.Credentials {
		if ent == nil || ent.Symbol == nil {
			continue
		}
		dc := DiscoveryCredential{Name: ent.Symbol.Name, Description: ent.Framework.Str("description")}
		if ent.Plugin != nil {
			dc.Type = ent.Plugin.Type
		}
		dc.Placeholder = ent.Framework.Str("placeholder")
		var eps []string
		for _, target := range config.CredentialEndpointTargets(ent) {
			if _, ok := prof.Endpoints[target]; ok {
				eps = append(eps, target)
			}
		}
		sort.Strings(eps)
		dc.Endpoints = eps
		m.Credentials = append(m.Credentials, dc)
	}
	sort.Slice(m.Credentials, func(i, j int) bool { return m.Credentials[i].Name < m.Credentials[j].Name })

	// Env vars pushed into the agent's process for this profile — the
	// same union the env-pushdown API serves, scoped here too.
	m.EnvVars = buildDiscoveryEnvVars(prof)

	// HITL guidance: the mechanism, which of this profile's endpoints can
	// park a request for human approval, and how to poll a parked request.
	// An empty profile has nothing to gate or poll, so it gets the empty-
	// state guidance below instead.
	if !m.isEmpty() {
		m.HITL = buildDiscoveryHITL(policy, prof, m.Endpoints)
	}

	// A profile that grants nothing leaves the agent with nothing to act
	// on; surface the dashboard URL so it can point its human at where the
	// device's profile gets configured. Non-empty manifests already carry
	// everything actionable, so the pointer would just be noise there.
	if m.isEmpty() {
		m.Dashboard = policy.DashboardURL
	}
	return m
}

// endpointHasHITL reports whether any enabled rule on ep routes matching
// requests through a human approver — i.e. a request to this endpoint may
// be parked pending human approval. Rules decided purely by an automated
// (llm) approver don't count: they don't wait on a human.
func endpointHasHITL(policy *config.CompiledPolicy, ep *config.CompiledEndpoint) bool {
	if ep == nil {
		return false
	}
	for _, rule := range ep.Rules {
		if rule == nil || rule.Disabled {
			continue
		}
		for _, stage := range rule.Outcome.Approve {
			if isHumanApprover(policy, stage.Name) {
				return true
			}
		}
	}
	return false
}

// isHumanApprover reports whether the named approve-chain stage waits on a
// human. The built-in `dashboard` approver is always human (it has no HCL
// block — `approve = [dashboard]` resolves without a declaration). Any
// other stage is human when its declared approver plugin is the
// human_approver type; llm_approver and anything else are automated.
func isHumanApprover(policy *config.CompiledPolicy, name string) bool {
	if name == "dashboard" {
		return true
	}
	if policy == nil {
		return false
	}
	ent := policy.Approvers[name]
	if ent == nil || ent.Plugin == nil {
		return false
	}
	return ent.Plugin.Type == "human_approver"
}

// buildDiscoveryHITL assembles the profile-scoped HITL summary from the
// already-flagged endpoint list, so the gated set and the per-endpoint
// HITL bool can never disagree. Always returns a value for a non-empty
// profile: the explanation and poll path are useful even when no endpoint
// is currently gated, since rules can change under the agent.
//
// policy + prof drive the async fallback: an endpoint goes async only when
// the profile opts into async grants and the gating approver is async-
// capable with a synchronous wait window. When no endpoint qualifies the
// Async block is left nil and the manifest documents the synchronous flow
// alone.
func buildDiscoveryHITL(policy *config.CompiledPolicy, prof *config.CompiledProfile, eps []DiscoveryEndpoint) *DiscoveryHITL {
	gated := []string{}
	asyncEps := []DiscoveryHITLAsyncEndpoint{}
	for _, ep := range eps {
		if ep.HITL {
			gated = append(gated, ep.Name)
		}
		if syncWait, pollTTL, ok := endpointAsyncHITL(policy, prof, ep.Name); ok {
			asyncEps = append(asyncEps, DiscoveryHITLAsyncEndpoint{
				Name:     ep.Name,
				SyncWait: syncWait.String(),
				PollTTL:  pollTTL.String(),
			})
		}
	}
	sort.Strings(gated)
	h := &DiscoveryHITL{
		Explanation:    hitlManifestExplanation(),
		GatedEndpoints: gated,
		PendingPath:    hitlPendingPath,
	}
	if len(asyncEps) > 0 {
		sort.Slice(asyncEps, func(i, j int) bool { return asyncEps[i].Name < asyncEps[j].Name })
		h.Async = &DiscoveryHITLAsync{
			Explanation:         hitlAsyncManifestExplanation(),
			StatusPathTemplate:  hitlOperationStatusPrefix + "{operation_id}" + hitlOperationStatusSuffix,
			RetryHeader:         hitlRetryOperationHeader,
			PollIntervalSeconds: hitlDefaultRetryAfterSeconds,
			Endpoints:           asyncEps,
		}
	}
	return h
}

// endpointAsyncHITL reports whether a request to the named endpoint can
// fall back to asynchronous approval for this profile, and if so the
// synchronous wait window before it returns a 202 and the lifetime of the
// parked operation thereafter. It mirrors the gateway's live activation
// rule (asyncHumanApproverFor + maybeStartAsyncHITLOperation): the profile
// must opt into async grants, the matching rule's approve chain must be
// exactly one async-capable human approver (not the built-in dashboard),
// and that approver must declare a positive sync_wait_timeout. An endpoint
// gated only synchronously — dashboard approver, multi-stage chain, or no
// sync window — reports false and is documented by the synchronous flow.
//
// When several gated rules qualify, the earliest hand-back wins: the agent
// is told the soonest a request here could go async (smallest sync wait).
func endpointAsyncHITL(policy *config.CompiledPolicy, prof *config.CompiledProfile, endpointName string) (syncWait, pollTTL time.Duration, ok bool) {
	if policy == nil || prof == nil || !prof.HITLAsyncGrants {
		return 0, 0, false
	}
	ep := prof.Endpoints[endpointName]
	if ep == nil {
		return 0, 0, false
	}
	for _, rule := range ep.Rules {
		if rule == nil || rule.Disabled {
			continue
		}
		stages := rule.Outcome.Approve
		if len(stages) != 1 || stages[0].Name == "dashboard" {
			continue
		}
		ent := policy.Approvers[stages[0].Name]
		if ent == nil {
			continue
		}
		rt, isAsync := ent.Body.(hitlAsyncGrantRuntime)
		if !isAsync || !rt.HITLAsyncGrantEnabled() {
			continue
		}
		sw := rt.HITLSyncWaitTimeout()
		if sw <= 0 {
			continue
		}
		if !ok || sw < syncWait {
			syncWait, pollTTL, ok = sw, rt.HITLAsyncApprovalTTL(policy), true
		}
	}
	return syncWait, pollTTL, ok
}

// hitlManifestExplanation is the prose an agent reads to understand that a
// parked request is expected behavior, not a hang. Built from the live
// routing constant (internal host + pending path) so the documented flow
// can't drift from the served one.
func hitlManifestExplanation() string {
	pendingURL := "https://" + internalHostname + hitlPendingPath
	return fmt.Sprintf(`Some endpoints have rules that gate a matching request behind human `+
		`approval (human-in-the-loop). When such a rule matches, the gateway PARKS the `+
		`request pending a human decision instead of forwarding it upstream — and it may stay `+
		`parked indefinitely while it waits for a person to approve or deny it. The gateway does `+
		`NOT call upstream while a request is parked, so no side effect has happened yet. Do NOT `+
		`treat a slow or hanging request to a gated endpoint as a failure or retry it blindly; the `+
		`gateway is holding it on purpose.

The gateway parks the request synchronously: it holds your connection open until a human `+
		`decides and then answers on that same connection — the real upstream response once the `+
		`request is approved, or a denial if it is rejected. You do not have to do anything special `+
		`or re-send anything; just let the request run instead of aborting it.

To see everything currently waiting on a human for your device, GET %s. It lists each parked `+
		`action — its method, endpoint, and redacted target — so you can tell what is held without `+
		`keeping the original connection in view.`, pendingURL)
}

// hitlAsyncManifestExplanation is the prose for the async-approval
// fallback: the 202-then-poll-then-retry protocol. Built from the live
// serving constants (status path, retry header, suggested poll interval)
// so the documented field names and flow can't drift from what the
// gateway actually returns. Listed endpoints (with their per-endpoint sync
// wait windows) accompany this text in the rendered manifest.
func hitlAsyncManifestExplanation() string {
	statusTemplate := hitlOperationStatusPrefix + "{operation_id}" + hitlOperationStatusSuffix
	return fmt.Sprintf(`Some gated endpoints do not hold your connection forever. Each such endpoint has a `+
		`synchronous wait window (its sync_wait_timeout, listed per endpoint below): if a human has `+
		`not decided within that window, the gateway stops holding the connection and answers with `+
		`HTTP 202 Accepted. A 202 is NOT success and NOT failure — it means "parked for human `+
		`approval, continuing asynchronously." Do not treat it as either; switch to polling.

The 202 body is JSON describing the parked operation. The fields you act on:
- operation_id: the parked operation's id.
- status_url: the absolute URL to poll for this operation's status (also returned in the Location `+
		`header). Poll THIS url; do not build your own — the template is %s.
- state: the current state (see below).
- terminal: true once the operation has reached a final state and will not change.
- retry_original_request: true while you should still be working the operation (poll, or retry once `+
		`approved).
The 202 also carries a Retry-After header (suggested %d seconds) — wait that long between polls.

Poll status_url with GET until the state resolves. The states:
- sync_waiting / pending_approval: still waiting on a human; keep polling (honoring Retry-After). No `+
		`upstream call has happened. pending_approval includes an approval_expires_at — the operation `+
		`stays pollable until then; only after that does it become expired, so keep polling a pending `+
		`operation rather than giving up early.
- approved_waiting_for_retry: a human approved it, but the gateway has NOT called upstream yet. To `+
		`execute it, RE-SEND the exact same original request with the header %s set to the operation_id, `+
		`before retry_expires_at. The retry is what performs the upstream call.
- denied: a human rejected it; do not retry. Stop.
- expired: the approval window or the post-approval retry window elapsed with no (or no acted-on) `+
		`decision; do not retry. Stop. expired is distinct from pending_approval — pending means keep `+
		`polling, expired means it is over.

You can also GET status_url at any time without a prior 202 to re-check an operation you already `+
		`know the id of.`, statusTemplate, hitlDefaultRetryAfterSeconds, hitlRetryOperationHeader)
}

// buildDiscoveryEnvVars collects the environment variables this profile
// pushes into the agent's process, mirroring the env-pushdown API
// (apiEnvPushdown): walk every endpoint the profile reaches, take the
// EnvVars() of each bound credential first (credential-shaped values
// win on a name clash) and of each endpoint plugin second, deduping by
// variable name. Endpoints are visited in sorted order so the result is
// byte-stable across calls — agents may diff this manifest and the
// golden tests assert on it.
//
// CA-bundle vars (SSL_CERT_FILE and friends) are deliberately excluded:
// they point at a path on the client's disk, the env-pushdown API omits
// them for the same reason, and the manifest's intro already explains
// the CA installation.
func buildDiscoveryEnvVars(prof *config.CompiledProfile) []DiscoveryEnvVar {
	out := []DiscoveryEnvVar{}
	if prof == nil {
		return out
	}
	seen := map[string]bool{}
	add := func(name, value, description, pluginType string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, DiscoveryEnvVar{Name: name, Value: value, Description: description, Type: pluginType})
	}

	names := make([]string, 0, len(prof.Endpoints))
	for name := range prof.Endpoints {
		names = append(names, name)
	}
	sort.Strings(names)

	// Credentials first, so a credential's placeholder wins over an
	// endpoint plugin that happens to push the same variable name.
	credSeen := map[string]bool{}
	for _, name := range names {
		ep := prof.Endpoints[name]
		if ep == nil {
			continue
		}
		for _, ent := range ep.Credentials {
			if ent == nil || ent.Symbol == nil || ent.Plugin == nil || credSeen[ent.Symbol.Name] {
				continue
			}
			credSeen[ent.Symbol.Name] = true
			provider, ok := ent.Body.(config.EnvPushdownProvider)
			if !ok {
				continue
			}
			for _, ev := range provider.EnvVars() {
				add(ev.Name, ev.Value, ev.Description, ent.Plugin.Type)
			}
		}
	}
	// Endpoint plugins second (e.g. openai_codex_https pushes its own).
	for _, name := range names {
		ep := prof.Endpoints[name]
		if ep == nil || ep.Plugin == nil {
			continue
		}
		provider, ok := ep.Body.(config.EnvPushdownProvider)
		if !ok {
			continue
		}
		for _, ev := range provider.EnvVars() {
			add(ev.Name, ev.Value, ev.Description, ep.Plugin.Type)
		}
	}
	return out
}

// describeEndpoint extracts the connection how-to from a compiled
// endpoint by type-asserting its plugin Body. Unknown plugin types
// fall back to the declared Hosts and plugin type — a new endpoint
// plugin still surfaces in the manifest with its hosts, just without
// type-specific fields.
func describeEndpoint(ep *config.CompiledEndpoint) DiscoveryEndpoint {
	de := DiscoveryEndpoint{Name: ep.Name, Family: ep.Family, Description: ep.Description}
	if ep.Plugin != nil {
		de.Type = ep.Plugin.Type
	}

	switch body := ep.Body.(type) {
	case *endpoints.HTTPSEndpoint:
		de.Hosts = body.Hosts
	case *endpoints.ClickhouseHTTPSEndpoint:
		de.Hosts = body.Hosts
	case *endpoints.PostgresEndpoint:
		host, port := splitHostPort(body.Host, 5432)
		de.Hosts = []string{host}
		de.Port = port
		de.SSLMode = body.SSLMode
	case *endpoints.ClickhouseNativeEndpoint:
		port := body.Port
		if port == 0 {
			port = 9000
			if body.TLS {
				port = 9440
			}
		}
		de.Port = port
		hosts := make([]string, 0, len(body.Hosts))
		for _, h := range body.Hosts {
			hp, _ := splitHostPort(h, port)
			hosts = append(hosts, hp)
		}
		de.Hosts = hosts
	case *endpoints.KubernetesEndpoint:
		de.Hosts = body.EndpointHosts()
		if body.Server != "" {
			// server may be a full URL; surface its path component so
			// the agent points kubectl at the right apiserver path.
			if i := strings.Index(body.Server, "/"); i >= 0 && strings.Contains(body.Server, "://") {
				if u := strings.SplitN(body.Server, "://", 2); len(u) == 2 {
					if j := strings.Index(u[1], "/"); j >= 0 {
						de.Path = u[1][j:]
					}
				}
			}
		}
	case *endpoints.SSHEndpoint:
		hosts := make([]string, 0, len(body.Hosts))
		for _, h := range body.Hosts {
			hp, port := splitHostPort(h, 22)
			hosts = append(hosts, hp)
			de.Port = port
		}
		de.Hosts = hosts
	default:
		// Unknown plugin: best-effort hosts via the generic accessor.
		if hoster, ok := ep.Body.(interface{ EndpointHosts() []string }); ok {
			de.Hosts = hoster.EndpointHosts()
		} else {
			de.Hosts = ep.Hosts
		}
	}
	if len(de.Hosts) == 0 {
		de.Hosts = ep.Hosts
	}
	return de
}

// profileEndpointCredentials returns the credentials the profile can
// present at endpointName, with placeholder + dispatch discriminators
// pulled from the profile-scoped dispatch table (the same table
// runtime.ResolveCredential consults).
func profileEndpointCredentials(prof *config.CompiledProfile, endpointName string) []DiscoveryCredentialRef {
	ccs := prof.EndpointCredentials[endpointName]
	out := make([]DiscoveryCredentialRef, 0, len(ccs))
	for _, cc := range ccs {
		if cc == nil || cc.Credential == nil || cc.Credential.Symbol == nil {
			continue
		}
		ref := DiscoveryCredentialRef{
			Name:        cc.Credential.Symbol.Name,
			Description: cc.Credential.Framework.Str("description"),
		}
		if cc.Credential.Plugin != nil {
			ref.Type = cc.Credential.Plugin.Type
		}
		// Split the merged disambiguator map into the placeholder (the
		// literal the agent sends) and the rest (postgres/clickhouse
		// user + database the agent connects with).
		if len(cc.Disambiguators) > 0 {
			rest := map[string]string{}
			for k, v := range cc.Disambiguators {
				if k == "placeholder" {
					ref.Placeholder = v
					continue
				}
				rest[k] = v
			}
			if len(rest) > 0 {
				ref.Disambiguators = rest
			}
		}
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// splitHostPort splits a "host:port" string, falling back to def when
// no port is present. Bare hosts and bracketed IPv6 are both handled.
func splitHostPort(hp string, def int) (string, int) {
	if hp == "" {
		return "", def
	}
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return hp, def
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, def
	}
	return host, port
}

// connectionHint returns a concrete client invocation for the endpoint
// where the protocol makes one unambiguous. Empty when there's no
// single obvious command (the agent still has hosts/port/credential).
func connectionHint(de DiscoveryEndpoint) string {
	host := ""
	if len(de.Hosts) > 0 {
		host = de.Hosts[0]
	}
	if host == "" {
		return ""
	}
	switch de.Type {
	case "postgres":
		var b strings.Builder
		fmt.Fprintf(&b, "psql \"host=%s port=%d", host, de.Port)
		if user := firstDisambiguator(de, "user"); user != "" {
			fmt.Fprintf(&b, " user=%s", user)
		}
		if db := firstDisambiguator(de, "database"); db != "" {
			fmt.Fprintf(&b, " dbname=%s", db)
		} else if de.Database != "" {
			fmt.Fprintf(&b, " dbname=%s", de.Database)
		}
		if de.SSLMode != "" {
			fmt.Fprintf(&b, " sslmode=%s", de.SSLMode)
		}
		b.WriteString("\"")
		return b.String()
	case "clickhouse_native":
		hint := fmt.Sprintf("clickhouse-client --host %s --port %d", host, de.Port)
		if user := firstDisambiguator(de, "user"); user != "" {
			hint += " --user " + user
		}
		if db := firstDisambiguator(de, "database"); db != "" {
			hint += " --database " + db
		}
		return hint
	case "kubernetes":
		return fmt.Sprintf("kubectl --server https://%s%s ...", host, de.Path)
	case "ssh":
		user := firstDisambiguator(de, "user")
		if user != "" {
			return fmt.Sprintf("ssh %s@%s", user, host)
		}
		return fmt.Sprintf("ssh %s", host)
	case "https", "clickhouse_https":
		ph := firstPlaceholder(de)
		if ph != "" {
			return fmt.Sprintf("curl https://%s/ -H \"Authorization: Bearer %s\"", host, ph)
		}
		return fmt.Sprintf("curl https://%s/", host)
	}
	return ""
}

// firstPlaceholder returns the placeholder of the first credential
// bound at the endpoint that has one.
func firstPlaceholder(de DiscoveryEndpoint) string {
	for _, c := range de.Credentials {
		if c.Placeholder != "" {
			return c.Placeholder
		}
	}
	return ""
}

// firstDisambiguator returns the value of key from the first
// credential at the endpoint that carries it.
func firstDisambiguator(de DiscoveryEndpoint, key string) string {
	for _, c := range de.Credentials {
		if v := c.Disambiguators[key]; v != "" {
			return v
		}
	}
	return ""
}

// Markdown renders the manifest as an agent-readable document
// (llms.txt style). An LLM consumes this directly, so it leads with
// orientation and keeps each endpoint's how-to self-contained.
func (m *DiscoveryManifest) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Claw Patrol access manifest — profile: %s\n\n", m.Profile)
	b.WriteString("You are connected through the Claw Patrol gateway. It intercepts your\n")
	b.WriteString("connections transparently: dial the hosts below as you normally would and\n")
	b.WriteString("the gateway injects credentials and enforces policy. A credential\n")
	b.WriteString("`placeholder` is a literal string you send where the secret would go — the\n")
	b.WriteString("gateway swaps it for the real secret. This manifest is scoped to YOUR\n")
	b.WriteString("device profile; it lists only what this profile grants.\n\n")

	b.WriteString("TLS is intercepted only for the hosts this profile grants — the\n")
	b.WriteString("endpoints listed below. For those, the gateway terminates TLS and acts\n")
	b.WriteString("as a transparent man-in-the-middle: the certificate you see is minted on\n")
	b.WriteString("the fly by Claw Patrol's own certificate authority, not the host's real\n")
	b.WriteString("public certificate. The hostname matches but the issuer is the gateway\n")
	b.WriteString("CA. You normally don't have to do anything to trust it: Claw Patrol\n")
	b.WriteString("already installed its CA on this device when you joined — both in the\n")
	b.WriteString("system trust store and via environment-variable pushdown\n")
	b.WriteString("(SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE,\n")
	b.WriteString("and similar) that `clawpatrol run` sets for the processes it wraps. So\n")
	b.WriteString("most clients validate these connections out of the box, and a\n")
	b.WriteString("certificate-authority mismatch against the public web PKI is expected\n")
	b.WriteString("for these hosts, not an attack. If a client ignores both the system\n")
	b.WriteString("store and those env vars, fetch the CA from\n")
	b.WriteString("https://clawpatrol.internal/ca.crt, verify its fingerprint against\n")
	b.WriteString("https://clawpatrol.internal/info, and point that\n")
	b.WriteString("client at it explicitly.\n\n")

	b.WriteString("Every other host is passed through untouched: the gateway does not\n")
	b.WriteString("intercept it, you get the upstream's real certificate, and you must\n")
	b.WriteString("still verify it against the public web PKI as usual.\n\n")

	for _, n := range m.Notes {
		fmt.Fprintf(&b, "> Note: %s\n\n", n)
	}

	if m.isEmpty() {
		b.WriteString(m.emptyGuidance())
	}

	if m.HITL != nil {
		b.WriteString("## Human-in-the-loop approval\n\n")
		b.WriteString(m.HITL.Explanation)
		b.WriteString("\n\n")
		if len(m.HITL.GatedEndpoints) > 0 {
			b.WriteString("Endpoints below that may park a request for human approval: ")
			b.WriteString(strings.Join(m.HITL.GatedEndpoints, ", "))
			b.WriteString(".\n\n")
		} else {
			b.WriteString("None of this profile's endpoints currently gate requests behind human approval.\n\n")
		}
		if m.HITL.Async != nil {
			b.WriteString("### Asynchronous approval (202 + polling)\n\n")
			b.WriteString(m.HITL.Async.Explanation)
			b.WriteString("\n\n")
			b.WriteString("Endpoints that fall back to asynchronous approval, and the synchronous wait " +
				"window before each returns a 202:\n\n")
			for _, ae := range m.HITL.Async.Endpoints {
				fmt.Fprintf(&b, "- %s: returns 202 after %s of waiting; the parked operation then stays "+
					"pollable for %s.\n", ae.Name, ae.SyncWait, ae.PollTTL)
			}
			b.WriteString("\n")
		}
	}

	fmt.Fprintf(&b, "## Endpoints (%d)\n\n", len(m.Endpoints))
	if len(m.Endpoints) == 0 {
		b.WriteString("_None reachable for this profile._\n\n")
	}
	for _, ep := range m.Endpoints {
		fmt.Fprintf(&b, "### %s  (%s)\n\n", ep.Name, ep.Type)
		if ep.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", ep.Description)
		}
		if len(ep.Hosts) > 0 {
			fmt.Fprintf(&b, "- Host(s): %s\n", strings.Join(ep.Hosts, ", "))
		}
		if ep.Port != 0 {
			fmt.Fprintf(&b, "- Port: %d\n", ep.Port)
		}
		if ep.Database != "" {
			fmt.Fprintf(&b, "- Database: %s\n", ep.Database)
		}
		if ep.SSLMode != "" {
			fmt.Fprintf(&b, "- SSL mode: %s\n", ep.SSLMode)
		}
		if ep.Path != "" {
			fmt.Fprintf(&b, "- Path: %s\n", ep.Path)
		}
		if len(ep.Credentials) == 0 {
			b.WriteString("- Credential: NONE bound for this profile — you cannot authenticate here\n")
		}
		for _, c := range ep.Credentials {
			line := fmt.Sprintf("- Credential: %s `%s`", c.Type, c.Name)
			if c.Description != "" {
				line += fmt.Sprintf(" — %s", c.Description)
			}
			if c.Placeholder != "" {
				line += fmt.Sprintf(" — send placeholder `%s`", c.Placeholder)
			}
			if len(c.Disambiguators) > 0 {
				line += " — connect with " + joinDisambiguators(c.Disambiguators)
			}
			b.WriteString(line + "\n")
		}
		if ep.Hint != "" {
			fmt.Fprintf(&b, "- Example: `%s`\n", ep.Hint)
		}
		if ep.HITL {
			b.WriteString("- Human-in-the-loop: a matching request may be PARKED pending human " +
				"approval and held until a person decides. Let it run instead of treating a slow " +
				"request as a failure; see the human-in-the-loop section above.\n")
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Environment variables (%d)\n\n", len(m.EnvVars))
	if len(m.EnvVars) == 0 {
		b.WriteString("_None pushed for this profile._\n\n")
	} else {
		b.WriteString("`clawpatrol run` sets these in your process environment so your CLI/SDK\n")
		b.WriteString("finds its credential automatically. The value shown is what the gateway\n")
		b.WriteString("exports — a placeholder that looks like a real token (swapped for the\n")
		b.WriteString("real secret at request time) or a synthetic token, never the secret\n")
		b.WriteString("itself. You don't need to set these yourself; this is what is already\n")
		b.WriteString("in your environment.\n\n")
		for _, ev := range m.EnvVars {
			line := fmt.Sprintf("- `%s`", ev.Name)
			if ev.Value != "" {
				line += fmt.Sprintf(" = `%s`", ev.Value)
			}
			if ev.Description != "" {
				line += fmt.Sprintf(" — %s", ev.Description)
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

// emptyGuidance is the block rendered when a profile grants nothing. A
// bare "none reachable / none granted" manifest is dead-on-arrival for
// an agent: it can't tell whether the gateway is broken, whether it's
// the wrong device, or what to do next. This explains that the empty
// result is a configuration state, what unlocks Claw Patrol's value, and
// where the operator changes this device's profile.
func (m *DiscoveryManifest) emptyGuidance() string {
	var b strings.Builder
	b.WriteString("## This profile is empty\n\n")
	fmt.Fprintf(&b, "Your device is mapped to the `%s` profile, which currently grants no\n", m.Profile)
	b.WriteString("endpoints and no credentials. That's why there's nothing actionable\n")
	b.WriteString("below. This is a configuration state, not an error — the gateway is\n")
	b.WriteString("reachable, your device just hasn't been granted anything yet.\n\n")
	b.WriteString("To get value from Claw Patrol, this profile needs endpoints and the\n")
	b.WriteString("credentials to reach them bound to it. An operator does that in the\n")
	b.WriteString("dashboard by either assigning this device a profile that already grants\n")
	b.WriteString("what you need, or adding endpoints and credentials to this one.\n\n")
	if m.Dashboard != "" {
		fmt.Fprintf(&b, "Ask the person who runs this gateway to open the dashboard at %s\n", m.Dashboard)
		b.WriteString("and update this device's profile.\n\n")
	} else {
		b.WriteString("Ask the person who runs this gateway to open the Claw Patrol dashboard\n")
		b.WriteString("and update this device's profile.\n\n")
	}
	b.WriteString("Once the profile is configured, re-fetch this manifest (GET\n")
	b.WriteString("https://clawpatrol.internal/manifest) and the endpoints and credentials\n")
	b.WriteString("will appear below.\n\n")
	return b.String()
}

// joinDisambiguators renders a "key=value" set in stable key order.
func joinDisambiguators(d map[string]string) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, d[k]))
	}
	return strings.Join(parts, " ")
}

// wantsJSON decides the response format. An explicit `?format=json`
// (or `format=markdown`) query param wins; otherwise the Accept header
// picks. Default is markdown — the primary consumer is an LLM.
func wantsJSON(r *http.Request) bool {
	switch strings.ToLower(r.URL.Query().Get("format")) {
	case "json":
		return true
	case "markdown", "md", "text":
		return false
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/markdown") {
		return true
	}
	return false
}

// writeDiscoveryResponse renders the manifest for profileName in the
// format the request asked for. Factored out of the TLS-serving path
// so it can be exercised with httptest without standing up WireGuard.
func writeDiscoveryResponse(w http.ResponseWriter, r *http.Request, policy *config.CompiledPolicy, profileName string) {
	m := buildDiscoveryManifest(policy, profileName)
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(m)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write([]byte(m.Markdown()))
}
