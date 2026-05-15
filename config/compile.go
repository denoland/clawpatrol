package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/config/match"
)

// CompiledPolicy is the runtime-friendly view of a loaded gateway:
// per-profile maps that the request handler walks at dispatch time.
// Build with Compile after Load.
type CompiledPolicy struct {
	// Policy fallbacks (mirrored from the top-level Gateway fields).
	UnknownHost    string
	LLMFailMode    string
	LLMCacheTTL    int
	HumanTimeout   int
	HumanOnTimeout string

	// Profiles indexed by name. Each holds a per-endpoint rule list,
	// already family-tagged and priority-sorted.
	Profiles map[string]*CompiledProfile

	// Endpoints contains every declared endpoint, keyed by name.
	// Useful for callers that don't care about profile scoping
	// (status pages, dashboard listings).
	Endpoints map[string]*CompiledEndpoint

	// Tunnels contains every declared tunnel, keyed by name. The
	// TunnelManager (host-side) walks this on policy reload to diff
	// old vs new tunnels. Endpoints store a *CompiledTunnel pointer
	// in their Tunnel field — same instance as the entry here.
	Tunnels map[string]*CompiledTunnel

	// Approvers / Policies / Credentials surface the same entities
	// from the Policy struct under a runtime-friendly typed alias —
	// they're pointers into the same Entity records, no copies.
	Approvers   map[string]*Entity
	Credentials map[string]*Entity
	Policies    map[string]*PolicyText
}

// CompiledProfile binds an identity to the endpoint set its requests
// dispatch against. Endpoints map by name; HostIndex maps exact
// declared hosts plus bare-host aliases for HTTPS-family default-port
// declarations to the endpoint that owns them for fast SNI / authority
// lookup. CompiledEndpoint.Hosts keeps the operator-declared strings
// unchanged.
type CompiledProfile struct {
	Name      string
	Endpoints map[string]*CompiledEndpoint
	HostIndex map[string]*CompiledEndpoint
}

// CompiledEndpoint flattens an endpoint plus the rules that target it.
// Body is whatever the endpoint plugin's Build returned (e.g.
// *endpoints.HTTPSEndpoint) — runtime callers type-assert based on
// Family.
type CompiledEndpoint struct {
	Name        string
	Family      string // "http" | "sql" | "k8s"
	Plugin      *Plugin
	Body        any
	Hosts       []string
	Credentials []*CompiledCredential // resolved to Entity records
	Rules       []*CompiledRule       // sorted by priority desc

	// Tunnel is the resolved tunnel this endpoint dials through, or
	// nil for endpoints reached over the gateway's plain dialer.
	// Populated from the endpoint plugin's optional EndpointTunnel()
	// accessor.
	Tunnel *CompiledTunnel
}

// RequiresVIP reports whether DNS-VIP allocation should claim this
// endpoint's hostnames. True when the body opts in via the
// dnsvip.RequiresVIP marker OR when the endpoint dials through a
// tunnel — tunneled upstreams can't be resolved by the agent's
// resolver, so VIP-routing is the only way to recover the hostname
// → endpoint mapping at conn-accept time.
//
// Implemented as a method (rather than a stored bool) so the
// dnsvip package — which already type-asserts on a `RequiresVIP()
// bool` shape — keeps working unchanged once it's pointed at the
// CompiledEndpoint instead of the body.
func (ce *CompiledEndpoint) RequiresVIP() bool {
	if ce == nil {
		return false
	}
	if ce.Tunnel != nil {
		return true
	}
	if r, ok := ce.Body.(interface{ RequiresVIP() bool }); ok && r.RequiresVIP() {
		return true
	}
	return false
}

// CompiledTunnel is the runtime-friendly view of one tunnel block.
// The TunnelManager walks these to spawn / refcount / tear down
// runtime instances; endpoint dispatch holds a pointer into this
// list via CompiledEndpoint.Tunnel.
type CompiledTunnel struct {
	Name   string
	Plugin *Plugin
	// Body is whatever the tunnel plugin's Build returned — runtime
	// callers type-assert it to TunnelRuntime (the runtime contract)
	// to call Open / Sharing.
	Body any

	// Sharing is the resolved sharing model after applying any
	// `share = ...` HCL override on top of the plugin's default.
	Sharing string

	// Keepalive is the idle window after refcount==0 before the
	// manager calls Close on the tunnel instance. Zero means tear
	// down immediately; KeepaliveAlways means never tear down on
	// idle (the manager pins refcount).
	Keepalive       time.Duration
	KeepaliveAlways bool

	// Via is the underlying tunnel this one chains through, or nil
	// for top-level tunnels. The manager Acquires the via tunnel
	// before opening this one and releases on teardown.
	Via *CompiledTunnel

	// Credential is the resolved credential entity this tunnel
	// drives its auth from, or nil if the HCL didn't declare one.
	// Plugins fetch the secret bytes via SecretStore.Get keyed on
	// Credential.Symbol.Name.
	Credential *Entity

	// Fingerprint is a stable hash of the compiled tunnel definition,
	// including its credential definition and via chain. Runtime
	// managers use it to distinguish same-name tunnels across policy
	// reloads without retaining or logging raw config/secret-bearing
	// fields.
	Fingerprint string `json:"-"`
}

// KeepaliveAlwaysSentinel is the duration value that means "pin
// the tunnel up for the lifetime of the policy that declared it".
// Plugins / loaders set CompiledTunnel.KeepaliveAlways=true rather
// than picking a magic duration; this constant exists so callers
// have a name for the "no idle teardown" case when they need to
// log it.
const KeepaliveAlwaysSentinel = time.Duration(-1)

// CompiledCredential expands an endpoint's `credential = X` or
// `credentials = [...]` binding into a flat list. Each entry pairs a
// dispatcher placeholder (empty for the singular / no-placeholder
// fallback) with the credential entity.
type CompiledCredential struct {
	Placeholder string
	Credential  *Entity
}

// CredBinding is one (placeholder, credential bare-name) pair. Endpoint
// plugins return these via the EndpointCredentials() interface so the
// compile pass can resolve credential names against the symbol table
// without knowing each endpoint type. Named (rather than anonymous)
// type is what lets every endpoint impl reuse the same return type
// without restating the field set.
type CredBinding struct {
	Placeholder string
	Credential  string
}

// CompiledRule is one priority-sorted rule attached to an endpoint.
//
// Condition is the original CEL source the matcher was built from,
// kept alongside Matcher for dashboard / diagnostic consumers that
// want to inspect the predicate without re-walking the rule
// plugin's Body. Credential, when set, is the bare-name reference
// the runtime checks against the dispatching credential before
// evaluating the matcher.
type CompiledRule struct {
	Name       string
	Priority   int
	Disabled   bool
	Condition  string
	Credential string
	Matcher    match.Matcher
	Outcome    Outcome
}

// Outcome captures a rule's verdict + (when applicable) approve chain.
// Exactly one of Verdict and Approve is set after Build's validation.
type Outcome struct {
	Verdict string // "allow" | "deny"
	Reason  string
	Approve []ApproveStage
}

// ApproveStage is one node in an approve = [...] chain — a bare-name
// reference to an approver block. LLM policy text and cache TTL ride on
// the approver block itself (see LLMApprover), so the use site stays a
// single bare name. Lives here so runtime callers don't need to import
// the rules plugin package.
type ApproveStage struct {
	Name string `json:"name"`
}

// Compile lowers a *Gateway into a *CompiledPolicy. Errors surface as
// Go errors (not hcl.Diagnostics) — semantic validation has already
// run at Load time; Compile only fails when a plugin's match map is
// shaped in a way the matcher can't compile (e.g. malformed regex).
func Compile(gw *Gateway) (*CompiledPolicy, error) {
	if gw == nil || gw.Policy == nil {
		return &CompiledPolicy{}, nil
	}
	p := gw.Policy
	cp := &CompiledPolicy{
		UnknownHost:    gw.UnknownHost,
		LLMFailMode:    gw.LLMFailMode,
		LLMCacheTTL:    gw.LLMCacheTTL,
		HumanTimeout:   gw.HumanTimeout,
		HumanOnTimeout: gw.HumanOnTimeout,
		Profiles:       map[string]*CompiledProfile{},
		Endpoints:      map[string]*CompiledEndpoint{},
		Tunnels:        map[string]*CompiledTunnel{},
		Approvers:      p.Approvers,
		Credentials:    p.Credentials,
		Policies:       p.Policies,
	}

	// Compile tunnels first so endpoint compilation can resolve
	// `tunnel = X` refs to a *CompiledTunnel.
	if err := compileTunnels(cp, p); err != nil {
		return nil, err
	}

	// Compile every endpoint once into a CompiledEndpoint with
	// resolved credentials and (placeholder) rule list. Rules attach
	// in the next pass.
	for name, ent := range p.Endpoints {
		ce, err := compileEndpoint(name, ent, p, cp)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", name, err)
		}
		cp.Endpoints[name] = ce
	}

	// Compile rules and attach to each endpoint they target. The
	// rule plugin owns the lowering (its CompileRule callback) so
	// match.Matcher construction lives next to the rule's schema,
	// not behind a decoupling interface in the compile pass. Same
	// rule attached to N endpoints lands as a *CompiledRule pointer
	// in N rule slices — runtime is read-only so sharing is safe.
	for name, ent := range p.Rules {
		if ent.Plugin.CompileRule == nil {
			return nil, fmt.Errorf("rule %q (%s): plugin has no CompileRule hook", name, ent.Plugin.Type)
		}
		cr, targets, err := ent.Plugin.CompileRule(ent.Body, name)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", name, err)
		}
		for _, target := range targets {
			ce, ok := cp.Endpoints[target]
			if !ok {
				return nil, fmt.Errorf("rule %q targets unknown endpoint %q", name, target)
			}
			ce.Rules = append(ce.Rules, cr)
		}
	}

	// Sort each endpoint's rules by priority descending. Ties keep
	// declaration order (stable sort) so the source-order intent
	// expressed in the HCL is preserved within a priority bucket.
	for _, ce := range cp.Endpoints {
		sort.SliceStable(ce.Rules, func(i, j int) bool {
			return ce.Rules[i].Priority > ce.Rules[j].Priority
		})
	}

	// Build per-profile views. A profile's Endpoints map points at
	// the SAME *CompiledEndpoint instances as cp.Endpoints — rules
	// don't fork per profile.
	for name, pr := range p.Profiles {
		profile := &CompiledProfile{
			Name:      name,
			Endpoints: map[string]*CompiledEndpoint{},
			HostIndex: map[string]*CompiledEndpoint{},
		}
		for _, epName := range pr.Endpoints {
			ce, ok := cp.Endpoints[epName]
			if !ok {
				continue
			}
			profile.Endpoints[epName] = ce
			// DNS hostnames are case-insensitive; index lowercase
			// so a SNI-peek lookup (TLS clients usually lowercase
			// SNI on the wire) matches a config-declared host
			// regardless of its casing.
			for _, h := range ce.Hosts {
				profile.HostIndex[strings.ToLower(h)] = ce
			}
		}
		// Add default-port TLS aliases only after every exact host is
		// indexed. That lets an explicit bare host beat any alias, while
		// keeping the alias attached to the HTTPS-family endpoint that
		// declared it even if another endpoint collides on the exact
		// host:port string.
		for _, epName := range pr.Endpoints {
			ce, ok := cp.Endpoints[epName]
			if !ok {
				continue
			}
			for _, h := range ce.Hosts {
				if bare, ok := bareHostAlias(ce, h); ok {
					bare = strings.ToLower(bare)
					if _, exists := profile.HostIndex[bare]; !exists {
						profile.HostIndex[bare] = ce
					}
				}
			}
		}
		cp.Profiles[name] = profile
	}

	return cp, nil
}

func compileEndpoint(name string, ent *Entity, p *Policy, cp *CompiledPolicy) (*CompiledEndpoint, error) {
	ce := &CompiledEndpoint{
		Name:   name,
		Family: ent.Plugin.Family,
		Plugin: ent.Plugin,
		Body:   ent.Body,
	}
	// Hosts and credential refs live on the plugin's typed body.
	// We cross-cut via a small interface so the compile pass doesn't
	// have to know every endpoint type — plugins that satisfy this
	// interface contribute their hosts + credential entries.
	if hp, ok := ent.Body.(interface{ HostList() []string }); ok {
		ce.Hosts = hp.HostList()
	} else {
		ce.Hosts = extractHosts(ent.Body)
	}
	for _, cb := range extractCredentialBindings(ent.Body) {
		credEnt, ok := p.Credentials[cb.Credential]
		if !ok {
			return nil, fmt.Errorf("credential %q not declared", cb.Credential)
		}
		ce.Credentials = append(ce.Credentials, &CompiledCredential{
			Placeholder: cb.Placeholder,
			Credential:  credEnt,
		})
	}
	if tn := ent.Framework.Ref("tunnel"); tn != "" {
		ct, ok := cp.Tunnels[tn]
		if !ok {
			return nil, fmt.Errorf("tunnel %q not declared", tn)
		}
		ce.Tunnel = ct
		// Tunneled endpoints are reached via VIP. If every host is
		// an IP literal there's no DNS query for the gateway to
		// intercept and the endpoint is unreachable.
		if !hasResolvableHostname(ce.Hosts) {
			return nil, fmt.Errorf("tunnel %q routes endpoint %q but it has no hostnames in `hosts` (only IP literals); tunneled endpoints rely on DNS-VIP interception, which needs a name to intercept", tn, name)
		}
	}
	return ce, nil
}

// hasResolvableHostname reports whether at least one entry in hosts
// carries a hostname (not an IP literal). Used by the compile pass
// to reject tunneled endpoints whose hosts are all IP literals —
// DNS-VIP would have nothing to intercept.
func hasResolvableHostname(hosts []string) bool {
	for _, hp := range hosts {
		host := hp
		if h, _, err := net.SplitHostPort(hp); err == nil {
			host = h
		}
		if host == "" {
			continue
		}
		if net.ParseIP(host) == nil {
			return true
		}
	}
	return false
}

func bareHostAlias(ep *CompiledEndpoint, host string) (string, bool) {
	if ep == nil || (ep.Family != "http" && ep.Family != "k8s") {
		return "", false
	}
	bare, port, err := net.SplitHostPort(host)
	if err != nil || bare == "" || port != "443" {
		return "", false
	}
	return bare, true
}

// hostExtractor / credentialExtractor are the small cross-cut readers
// used by compileEndpoint. They live on the endpoint plugin types but
// are referenced via interface here to keep imports clean.

// extractHosts mirrors the per-type hosts field via interface dispatch.
// The universe of endpoint types is closed; reflect would be overkill.
func extractHosts(body any) []string {
	if h, ok := body.(interface{ EndpointHosts() []string }); ok {
		return h.EndpointHosts()
	}
	return nil
}

func extractCredentialBindings(body any) []CredBinding {
	if h, ok := body.(interface{ EndpointCredentials() []CredBinding }); ok {
		return h.EndpointCredentials()
	}
	return nil
}

// TunnelCommon is the framework-level slice every tunnel plugin's
// HCL body restates. The compile pass reads them via TunnelCommonRead
// instead of reflecting into the plugin struct, so plugins keep full
// control of their schema while sharing the manager-visible knobs.
//
// Share / Keepalive accept "" (use the plugin default) or one of the
// recognised values. Via / Credential are bare-name refs validated
// against the symbol table at load time — empty when the HCL omitted
// them.
type TunnelCommon struct {
	Share      string
	Keepalive  string
	Via        string
	Credential string
}

// TunnelCommonRead is the cross-cut interface tunnel plugin bodies
// implement so the compile pass can pick up the framework-level
// attrs (share / keepalive / via / credential) without depending on
// the concrete plugin type.
type TunnelCommonRead interface {
	TunnelCommon() TunnelCommon
}

// compileTunnels lowers every tunnel block into a *CompiledTunnel,
// resolves `via` chains (with cycle detection), attaches credential
// entities, and parses share / keepalive into runtime-friendly
// shapes.
func compileTunnels(cp *CompiledPolicy, p *Policy) error {
	if len(p.Tunnels) == 0 {
		return nil
	}
	// Pass 1: build the bare CompiledTunnel records keyed by name.
	commons := make(map[string]TunnelCommon, len(p.Tunnels))
	for name, ent := range p.Tunnels {
		var common TunnelCommon
		if r, ok := ent.Body.(TunnelCommonRead); ok {
			common = r.TunnelCommon()
		}
		commons[name] = common

		share := common.Share
		if share == "" {
			if s, ok := ent.Plugin.Runtime.(interface{ Sharing() string }); ok {
				share = s.Sharing()
			}
		}
		if share == "" {
			share = "singleton"
		}
		switch share {
		case "singleton", "per_endpoint", "per_conn":
		default:
			return fmt.Errorf("tunnel %q: invalid share %q (want singleton | per_endpoint | per_conn)", name, share)
		}

		keepalive, always, err := parseKeepalive(common.Keepalive)
		if err != nil {
			return fmt.Errorf("tunnel %q: %w", name, err)
		}

		ct := &CompiledTunnel{
			Name:            name,
			Plugin:          ent.Plugin,
			Body:            ent.Body,
			Sharing:         share,
			Keepalive:       keepalive,
			KeepaliveAlways: always,
		}
		if common.Credential != "" {
			credEnt, ok := p.Credentials[common.Credential]
			if !ok {
				return fmt.Errorf("tunnel %q: credential %q not declared", name, common.Credential)
			}
			ct.Credential = credEnt
		}
		cp.Tunnels[name] = ct
	}

	// Pass 2: link Via pointers and detect cycles.
	for name, ct := range cp.Tunnels {
		viaName := commons[name].Via
		if viaName == "" {
			continue
		}
		via, ok := cp.Tunnels[viaName]
		if !ok {
			return fmt.Errorf("tunnel %q: via %q is not a declared tunnel", name, viaName)
		}
		ct.Via = via
	}
	for name := range cp.Tunnels {
		seen := map[string]bool{}
		cur := cp.Tunnels[name]
		for cur != nil {
			if seen[cur.Name] {
				return fmt.Errorf("tunnel %q: via chain forms a cycle (visits %q twice)", name, cur.Name)
			}
			seen[cur.Name] = true
			cur = cur.Via
		}
	}
	if err := fingerprintTunnels(cp.Tunnels); err != nil {
		return err
	}
	return nil
}

type compiledTunnelFingerprint struct {
	Name            string                         `json:"name"`
	PluginKind      Kind                           `json:"plugin_kind"`
	PluginType      string                         `json:"plugin_type"`
	Body            any                            `json:"body"`
	Sharing         string                         `json:"sharing"`
	Keepalive       time.Duration                  `json:"keepalive"`
	KeepaliveAlways bool                           `json:"keepalive_always"`
	ViaName         string                         `json:"via_name,omitempty"`
	ViaFingerprint  string                         `json:"via_fingerprint,omitempty"`
	Credential      *compiledCredentialFingerprint `json:"credential,omitempty"`
}

type compiledCredentialFingerprint struct {
	Name       string `json:"name"`
	PluginKind Kind   `json:"plugin_kind"`
	PluginType string `json:"plugin_type"`
	Body       any    `json:"body"`
}

func fingerprintTunnels(tunnels map[string]*CompiledTunnel) error {
	memo := map[*CompiledTunnel]string{}
	for name, ct := range tunnels {
		fp, err := tunnelFingerprint(ct, memo)
		if err != nil {
			return fmt.Errorf("tunnel %q: fingerprint: %w", name, err)
		}
		ct.Fingerprint = fp
	}
	return nil
}

func tunnelFingerprint(ct *CompiledTunnel, memo map[*CompiledTunnel]string) (string, error) {
	if ct == nil {
		return "", nil
	}
	if fp, ok := memo[ct]; ok {
		return fp, nil
	}
	viaFP, err := tunnelFingerprint(ct.Via, memo)
	if err != nil {
		return "", err
	}
	rec := compiledTunnelFingerprint{
		Name:            ct.Name,
		PluginKind:      pluginKind(ct.Plugin),
		PluginType:      pluginType(ct.Plugin),
		Body:            ct.Body,
		Sharing:         ct.Sharing,
		Keepalive:       ct.Keepalive,
		KeepaliveAlways: ct.KeepaliveAlways,
		Credential:      credentialFingerprint(ct.Credential),
	}
	if ct.Via != nil {
		rec.ViaName = ct.Via.Name
		rec.ViaFingerprint = viaFP
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	fp := hex.EncodeToString(sum[:])
	memo[ct] = fp
	return fp, nil
}

func credentialFingerprint(ent *Entity) *compiledCredentialFingerprint {
	if ent == nil {
		return nil
	}
	name := ""
	if ent.Symbol != nil {
		name = ent.Symbol.Name
	}
	return &compiledCredentialFingerprint{
		Name:       name,
		PluginKind: pluginKind(ent.Plugin),
		PluginType: pluginType(ent.Plugin),
		Body:       ent.Body,
	}
}

func pluginKind(p *Plugin) Kind {
	if p == nil {
		return ""
	}
	return p.Kind
}

func pluginType(p *Plugin) string {
	if p == nil {
		return ""
	}
	return p.Type
}

// parseKeepalive turns the HCL keepalive string into (duration,
// always, error). Empty defaults to a 5m idle window. "always" pins
// the tunnel up; "0" tears down immediately on idle.
func parseKeepalive(s string) (time.Duration, bool, error) {
	switch s {
	case "":
		return 5 * time.Minute, false, nil
	case "always":
		return 0, true, nil
	case "0":
		return 0, false, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false, fmt.Errorf("invalid keepalive %q: %w (want 'always' | duration like '5m' | '0')", s, err)
	}
	if d < 0 {
		return 0, false, fmt.Errorf("invalid keepalive %q: negative durations not allowed", s)
	}
	return d, false, nil
}
