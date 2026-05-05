package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"

	"github.com/denoland/clawpatrol/config"
)

type Agent struct {
	IP           string     `json:"ip"`
	ExternalIPv4 string     `json:"external_ipv4,omitempty"`
	ExternalIPv6 string     `json:"external_ipv6,omitempty"`
	Hostname     string     `json:"hostname"`
	User         string     `json:"user"`
	Profile      string     `json:"profile,omitempty"`
	OS           string     `json:"os"`
	UA           string     `json:"ua"`
	FirstAt      time.Time  `json:"first_at"`
	LastAt       time.Time  `json:"last_at"`
	Reqs         int64      `json:"reqs"`
	BytesIn      int64      `json:"bytes_in"`
	BytesOut     int64      `json:"bytes_out"`
	LastHost     string     `json:"last_host"`
	Activity     []int      `json:"activity"`
	Integrations []string   `json:"integrations"`
	Sessions     []*Session `json:"sessions,omitempty"`
	prevTotal    int64
}

// Session = one coding-agent conversation on a device. Identified by
// (type, hash-of-first-user-message). New session = new first-message.
type Session struct {
	ID        string    `json:"id"` // sha256(first user message), short
	Title     string    `json:"title,omitempty"`
	Type      string    `json:"type"`
	Model     string    `json:"model,omitempty"`
	TokensIn  int64     `json:"tokens_in,omitempty"`
	TokensOut int64     `json:"tokens_out,omitempty"`
	CtxUsed   int64     `json:"ctx_used,omitempty"`
	CtxMax    int64     `json:"ctx_max,omitempty"`
	FirstAt   time.Time `json:"first_at"`
	LastAt    time.Time `json:"last_at"`
	Reqs      int64     `json:"reqs"`
	Activity  []int     `json:"activity"`
	prevReqs  int64
}

// findOrAddSession returns an existing session by (type, id) or creates one.
// id may be empty → caller has no first-message hash, falls back to
// most-recent same-type session if any. Caller holds r.mu.
func (a *Agent) findOrAddSession(t, id, title string) *Session {
	if id != "" {
		for _, s := range a.Sessions {
			if s.Type == t && s.ID == id {
				s.LastAt = time.Now().UTC()
				s.Reqs++
				return s
			}
		}
	} else {
		// no id: extend most-recent same-type session
		for i := len(a.Sessions) - 1; i >= 0; i-- {
			if a.Sessions[i].Type == t {
				s := a.Sessions[i]
				s.LastAt = time.Now().UTC()
				s.Reqs++
				return s
			}
		}
	}
	now := time.Now().UTC()
	s := &Session{ID: id, Title: title, Type: t, FirstAt: now, LastAt: now, Reqs: 1}
	a.Sessions = append(a.Sessions, s)
	return s
}

func detectAgentType(ua string) string {
	u := strings.ToLower(ua)
	switch {
	case strings.Contains(u, "claude-code") || strings.Contains(u, "anthropic"):
		return "claude"
	case strings.Contains(u, "codex") || strings.Contains(u, "openai"):
		return "codex"
	case strings.Contains(u, "curl/") || strings.Contains(u, "wget/") || strings.Contains(u, "httpie"):
		return "shell"
	case u == "":
		return ""
	default:
		return "other"
	}
}

// detectAgentTypeFromHost infers type from destination host (used for
// splice path where we don't see UA).
func detectAgentTypeFromHost(host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.HasSuffix(h, "anthropic.com") || strings.HasSuffix(h, "claude.ai") || strings.HasSuffix(h, "claude.com"):
		return "claude"
	case strings.HasSuffix(h, "openai.com") || strings.HasSuffix(h, "chatgpt.com") || strings.HasSuffix(h, "oaiusercontent.com"):
		return "codex"
	}
	return ""
}

type AgentRegistry struct {
	mu      sync.RWMutex
	agents  map[string]*Agent
	lc      *local.Client
	onboard *onboardRegistry // set by Gateway ctor; supplies hostname/owner overrides in WG mode
}

const activityBuckets = 30 // ~30s history at 1s sampling

func NewAgentRegistry() *AgentRegistry {
	r := &AgentRegistry{
		agents: map[string]*Agent{},
		lc:     &local.Client{},
	}
	go r.sampleLoop()
	return r
}

// sampleLoop runs once per second, computes bytes/sec delta per agent,
// appends to Activity ring buffer.
func (r *AgentRegistry) sampleLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		r.mu.Lock()
		for _, a := range r.agents {
			total := a.BytesIn + a.BytesOut
			delta := total - a.prevTotal
			if delta < 0 {
				delta = 0
			}
			a.prevTotal = total
			a.Activity = append(a.Activity, int(delta))
			if len(a.Activity) > activityBuckets {
				a.Activity = a.Activity[len(a.Activity)-activityBuckets:]
			}
			for _, s := range a.Sessions {
				rd := s.Reqs - s.prevReqs
				if rd < 0 {
					rd = 0
				}
				s.prevReqs = s.Reqs
				s.Activity = append(s.Activity, int(rd))
				if len(s.Activity) > activityBuckets {
					s.Activity = s.Activity[len(s.Activity)-activityBuckets:]
				}
			}
		}
		r.mu.Unlock()
	}
}

// Seed creates an empty agent entry for ip if missing. Called at
// onboard-approve time so the device appears in the dashboard before
// it sends any traffic. Hostname / owner are pulled from
// onboardRegistry overrides.
func (r *AgentRegistry) Seed(ip string) {
	if ip == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agents[ip]; ok {
		return
	}
	now := time.Now().UTC()
	a := &Agent{IP: ip, FirstAt: now, LastAt: now}
	if r.onboard != nil {
		if hn := r.onboard.HostnameForIP(ip); hn != "" {
			a.Hostname = hn
		}
		if owner := r.onboard.OwnerForIP(ip); owner != "" {
			a.User = owner
		}
	}
	r.agents[ip] = a
}

func (r *AgentRegistry) track(remoteAddr, host string, in, out int64) {
	r.trackUA(remoteAddr, host, "", in, out)
}

func (r *AgentRegistry) trackUA(remoteAddr, host, ua string, in, out int64) {
	ip, _, _ := net.SplitHostPort(remoteAddr)
	if ip == "" {
		ip = remoteAddr
	}
	now := time.Now().UTC()

	r.mu.Lock()
	a, ok := r.agents[ip]
	if !ok {
		a = &Agent{IP: ip, FirstAt: now}
		// WG-mode override: hostname captured at `clawpatrol join` time.
		// Tailscale whois fills more (User, OS) — see fillIdentity.
		if r.onboard != nil {
			if hn := r.onboard.HostnameForIP(ip); hn != "" {
				a.Hostname = hn
			}
			if owner := r.onboard.OwnerForIP(ip); owner != "" {
				a.User = owner
			}
		}
		r.agents[ip] = a
		go r.fillIdentity(ip)
	}
	a.LastAt = now
	a.Reqs++
	a.BytesIn += in
	a.BytesOut += out
	a.LastHost = host
	if ua != "" {
		a.UA = ua
	}
	// best-effort session creation for codex via splice (chatgpt.com etc.)
	// — claude sessions are created in trackLLMUsage when /v1/messages
	// fires. We only auto-create here for hosts we *can't* MITM.
	if t := detectAgentTypeFromHost(host); t == "codex" {
		a.findOrAddSession(t, "", "")
	}
	r.mu.Unlock()
}

// lookupWhois does a synchronous whois (short timeout). Used for
// credential-owner derivation per-request. Returns nil on failure.
func (r *AgentRegistry) lookupWhois(ip string) *whoisResult {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	who, err := r.lc.WhoIs(ctx, netip.AddrPortFrom(addr, 0).String())
	if err != nil || who == nil {
		return nil
	}
	res := &whoisResult{}
	if who.Node != nil {
		res.Node = whoisNode{StableID: string(who.Node.StableID), HostName: who.Node.Hostinfo.Hostname()}
	}
	if who.UserProfile != nil {
		res.UserProfile = whoisProfile{LoginName: who.UserProfile.LoginName}
	}
	return res
}

type whoisResult struct {
	Node        whoisNode
	UserProfile whoisProfile
}
type whoisNode struct{ StableID, HostName string }
type whoisProfile struct{ LoginName string }

func (n whoisNode) IsZero() bool         { return n.StableID == "" && n.HostName == "" }
func (p whoisProfile) IsZero() bool      { return p.LoginName == "" }
func (r *whoisResult) NodeNonZero() bool { return !r.Node.IsZero() }

func (r *AgentRegistry) fillIdentity(ip string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	addrPort := netip.AddrPortFrom(addr, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	who, err := r.lc.WhoIs(ctx, addrPort.String())
	if err != nil || who == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[ip]
	if !ok {
		return
	}
	if who.Node != nil {
		a.Hostname = who.Node.Hostinfo.Hostname()
		a.OS = who.Node.Hostinfo.OS()
	}
	if who.UserProfile != nil {
		a.User = who.UserProfile.LoginName
	}
}

func printDashboardURL(listen string) {
	port := listen
	if i := strings.LastIndex(port, ":"); i >= 0 {
		port = port[i:]
	}
	lc := &local.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := lc.Status(ctx)
	if err != nil || st == nil || st.Self == nil {
		log.Printf("dashboard: http://0.0.0.0%s", port)
		return
	}
	hostName := st.Self.HostName
	if st.MagicDNSSuffix != "" && hostName != "" {
		log.Printf("dashboard: http://%s.%s%s", hostName, st.MagicDNSSuffix, port)
	}
	if len(st.Self.TailscaleIPs) > 0 {
		log.Printf("dashboard: http://%s%s", st.Self.TailscaleIPs[0], port)
	}
}

func (r *AgentRegistry) snapshot() []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		cp := *a
		if r.onboard != nil {
			cp.Profile = r.onboard.ProfileForIP(a.IP)
		}
		if a.Activity != nil {
			cp.Activity = append([]int(nil), a.Activity...)
		}
		if a.Integrations != nil {
			cp.Integrations = append([]string(nil), a.Integrations...)
		}
		if a.Sessions != nil {
			cp.Sessions = make([]*Session, len(a.Sessions))
			for i, s := range a.Sessions {
				sc := *s
				if s.Activity != nil {
					sc.Activity = append([]int(nil), s.Activity...)
				}
				cp.Sessions[i] = &sc
			}
		}
		out = append(out, &cp)
	}
	return out
}

// Delete drops an agent from the registry. Idempotent — silent on
// unknown IP. Caller is expected to also clear any side-tables
// (onboard ownerByIP override, OAuth credentials, etc.).
func (r *AgentRegistry) Delete(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agents, ip)
}

func (r *AgentRegistry) recordLLMUsage(ip, sessionType, sessionID, sessionTitle, model string, in, out int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.agents[ip]
	if a == nil {
		return
	}
	s := a.findOrAddSession(sessionType, sessionID, sessionTitle)
	if model != "" {
		s.Model = model
	}
	if s.Title == "" && sessionTitle != "" {
		s.Title = sessionTitle
	}
	s.TokensIn += in
	s.TokensOut += out
	s.CtxUsed = in + out
	s.CtxMax = ctxMaxFor(model)
}

func ctxMaxFor(model string) int64 {
	return models.ctxMax(model)
}

func shortHash(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

type IntegrationRow struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Type     string              `json:"type"` // credential plugin type
	HasOAuth bool                `json:"has_oauth"`
	Slots    []config.SecretSlot `json:"slots,omitempty"`
	Owners   []Owner             `json:"owners"`
}

type Owner struct {
	Owner     string `json:"owner"`
	Connected bool   `json:"connected"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

func (w *webMux) apiStatus(rw http.ResponseWriter, r *http.Request) {
	out := []IntegrationRow{}
	policy := w.g.policy.Load()
	if policy == nil {
		writeJSON(rw, out)
		return
	}
	profile := r.URL.Query().Get("profile")
	allowed := credentialsInProfile(policy, profile) // nil = no filter

	names := make([]string, 0, len(policy.Credentials))
	for name := range policy.Credentials {
		if allowed != nil && !allowed[name] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	caller, _ := w.ownerForCaller(r)
	for _, name := range names {
		ent := policy.Credentials[name]
		row := IntegrationRow{ID: name, Name: name, Type: ent.Plugin.Type}
		if _, ok := ent.Body.(config.OAuthFlowProvider); ok {
			row.HasOAuth = true
			for _, owner := range w.g.oauth.Owners(name) {
				connected, exp := w.g.oauth.Status(name, owner)
				o := Owner{Owner: owner, Connected: connected}
				if !exp.IsZero() {
					o.ExpiresAt = exp.Unix()
				}
				row.Owners = append(row.Owners, o)
			}
		}
		if sp, ok := ent.Body.(config.SecretSlotsProvider); ok {
			row.Slots = sp.SecretSlots()
			if caller != "" {
				present, _ := credentialSlotPresence(w.g.db, name, caller)
				if len(present) > 0 {
					row.Owners = append(row.Owners, Owner{Owner: caller, Connected: true})
				}
			}
		}
		out = append(out, row)
	}
	writeJSON(rw, out)
}

// credentialsInProfile returns the set of credential bare names that
// any endpoint in the given profile references. nil means "no filter
// — return everything." Used by apiStatus and the device-page card
// render so per-device views only show credentials the device's
// profile actually uses.
func credentialsInProfile(policy *config.CompiledPolicy, profile string) map[string]bool {
	if profile == "" || policy == nil {
		return nil
	}
	prof, ok := policy.Profiles[profile]
	if !ok {
		return map[string]bool{} // unknown profile → empty set, not nil
	}
	out := map[string]bool{}
	for _, ep := range prof.Endpoints {
		for _, cb := range ep.Credentials {
			if cb.Credential != nil {
				out[cb.Credential.Symbol.Name] = true
			}
		}
	}
	return out
}

func (w *webMux) apiAgents(rw http.ResponseWriter, _ *http.Request) {
	var snap []*Agent
	if w.g.agents != nil {
		snap = w.g.agents.snapshot()
	}
	// External IPs: the underlay v4/v6 each WG peer is dialing in from.
	// Show these in place of the server-side /32 (routing artefact).
	// Live endpoint observed via wg-go IpcGet — persist into the devices
	// row so the dashboard keeps a stable last-known address even when
	// the peer goes idle and wg-go drops its endpoint state.
	if globalWG != nil {
		for ip, ep := range globalWG.EndpointsByIP() {
			if ep == "" {
				continue
			}
			parsed := net.ParseIP(ep)
			var v4, v6 string
			if p4 := parsed.To4(); p4 != nil {
				v4 = p4.String()
			} else if parsed != nil {
				v6 = parsed.String()
			}
			w.onboard.SetExternalIPs(ip, v4, v6)
		}
	}
	for _, a := range snap {
		v4, v6 := w.onboard.ExternalIPs(a.IP)
		a.ExternalIPv4, a.ExternalIPv6 = v4, v6
	}
	// enrich with connected integrations per agent's user. Re-run on
	// every snapshot — caching by `Integrations != nil` would freeze
	// the list at first sighting (a freshly-onboarded device whose
	// user later connects Claude wouldn't reflect the new connection).
	for _, a := range snap {
		// Per-profile credentials: the agent's Integrations list
		// reflects what the device's bound profile has connected. Falls
		// back to the legacy per-user lookup for tailnet-control-mode
		// installs that still bucket creds by login.
		profile := w.onboard.ProfileForIP(a.IP)
		if profile == "" {
			if a.User == "" || a.User == "tagged-devices" {
				if owner := w.onboard.OwnerForIP(a.IP); owner != "" {
					a.User = owner
				}
			}
			profile = a.User
		}
		if profile == "" {
			continue
		}
		// Walk every declared credential — connected if either an
		// OAuth token exists OR the operator pasted a secret slot via
		// the dashboard. Was hardcoded to the claude/codex/github
		// legacy trio, which silently hid every other credential type
		// from the agents table.
		var ids []string
		if policy := w.g.Policy(); policy != nil {
			names := make([]string, 0, len(policy.Credentials))
			for name := range policy.Credentials {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if conn, _ := w.g.oauth.Status(name, profile); conn {
					ids = append(ids, name)
					continue
				}
				present, _ := credentialSlotPresence(w.g.db, name, profile)
				if len(present) > 0 {
					ids = append(ids, name)
				}
			}
		}
		if ids != nil {
			a.Integrations = ids
		}
	}
	writeJSON(rw, snap)
}

// apiAgentDelete drops a device from clawpatrol's view. Removes the
// in-memory agent record, the onboard owner / hostname / profile
// row, and (in WG mode) the WireGuard peer + allowed-IP entry — so
// traffic from the deleted device's tunnel can't keep flowing under
// the old owner. The Tailscale node itself isn't kicked; admins do
// that from the Tailscale admin console.
func (w *webMux) apiAgentDelete(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(rw, "missing ip", 400)
		return
	}
	if w.g.agents != nil {
		w.g.agents.Delete(ip)
	}
	if w.g.onboard != nil {
		w.g.onboard.ForgetIP(ip)
	}
	if globalWG != nil {
		globalWG.RevokePeerByIP(ip)
	}
	writeJSON(rw, map[string]bool{"ok": true})
}

// apiAgentProfile assigns a peer IP to a named profile. Profile must
// be declared in cfg.Profiles. The mapping is persisted in
// onboard.profileByIP and consulted by Gateway.profileFor at MITM
// time, so rule scoping switches over immediately.
func (w *webMux) apiAgentProfile(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	ip := r.URL.Query().Get("ip")
	profile := r.URL.Query().Get("profile")
	if ip == "" || profile == "" {
		http.Error(rw, "missing ip or profile", 400)
		return
	}
	names := orderedProfileNames(w.g.cfg.Policy)
	known := false
	for _, n := range names {
		if n == profile {
			known = true
			break
		}
	}
	if !known {
		http.Error(rw, "unknown profile", 400)
		return
	}
	w.g.onboard.AssignProfile(ip, profile)
	writeJSON(rw, map[string]any{"ok": true, "ip": ip, "profile": profile})
}

// apiProfiles lists declared profile names so the dashboard can
// render a profile picker per device.
func (w *webMux) apiProfiles(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, orderedProfileNames(w.g.cfg.Policy))
}

// RuleSummary is the JSON shape the dashboard renders for each rule.
// It flattens a CompiledRule plus its enclosing endpoint and profile
// context so the table view doesn't need to walk the policy graph
// itself.
type RuleSummary struct {
	Name     string                `json:"name"`
	Family   string                `json:"family"` // "https" | "sql" | "k8s"
	Endpoint string                `json:"endpoint"`
	Profile  string                `json:"profile,omitempty"`
	Priority int                   `json:"priority,omitempty"`
	Disabled bool                  `json:"disabled,omitempty"`
	Match    map[string]any        `json:"match,omitempty"`
	Verdict  string                `json:"verdict,omitempty"`
	Reason   string                `json:"reason,omitempty"`
	Approve  []config.ApproveStage `json:"approve,omitempty"`
}

// apiRules returns every compiled rule across every profile, flattened
// for the dashboard table view. Rules attached to multiple endpoints
// emit one row per endpoint so the operator sees each attachment
// site individually.
//
// Read-only. Edits go through PUT /api/config (whole-file HCL via
// the new typed-block validator).
func (w *webMux) apiRules(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(rw, w.collectRuleSummaries(""))
	default:
		http.Error(rw, "edit rules through PUT /api/config", http.StatusNotImplemented)
	}
}

// collectRuleSummaries walks the compiled policy and emits one
// RuleSummary per (rule × endpoint × profile) triple. When profile is
// empty, every profile contributes; otherwise only that profile.
//
// Sort: by profile, then endpoint, then descending priority (so the
// dashboard mirrors first-match-wins order within each endpoint).
func (w *webMux) collectRuleSummaries(profileFilter string) []RuleSummary {
	policy := w.g.Policy()
	if policy == nil {
		return []RuleSummary{}
	}
	var out []RuleSummary
	for profileName, prof := range policy.Profiles {
		if profileFilter != "" && profileName != profileFilter {
			continue
		}
		for epName, ep := range prof.Endpoints {
			for _, r := range ep.Rules {
				out = append(out, RuleSummary{
					Name:     r.Name,
					Family:   ep.Family,
					Endpoint: epName,
					Profile:  profileName,
					Priority: r.Priority,
					Disabled: r.Disabled,
					Match:    matchSourceMap(r),
					Verdict:  r.Outcome.Verdict,
					Reason:   r.Outcome.Reason,
					Approve:  r.Outcome.Approve,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Profile != out[j].Profile {
			return out[i].Profile < out[j].Profile
		}
		if out[i].Endpoint != out[j].Endpoint {
			return out[i].Endpoint < out[j].Endpoint
		}
		return out[i].Priority > out[j].Priority
	})
	return out
}

func matchSourceMap(r *config.CompiledRule) map[string]any {
	if r == nil {
		return nil
	}
	return r.Match
}
