package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
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
