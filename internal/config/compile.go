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

	"github.com/denoland/clawpatrol/internal/config/hostmatch"
	"github.com/denoland/clawpatrol/internal/config/match"
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

	// DashboardURL mirrors gateway.public_url — the canonical URL where
	// an operator reaches the dashboard to configure device profiles.
	// Surfaced here so the discovery manifest can point an agent (or its
	// human) at the dashboard when its profile grants nothing. Empty when
	// public_url is unset.
	DashboardURL string

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

	// Approvers / Credentials surface the same entities from the
	// Policy struct under a runtime-friendly typed alias — they're
	// pointers into the same Entity records, no copies.
	Approvers   map[string]*Entity
	Credentials map[string]*Entity
}

// CompiledProfile binds an identity to the endpoint set its requests
// dispatch against. Endpoints map by name; HostIndex maps exact
// declared hosts plus bare-host aliases for HTTPS-family default-port
// declarations to the endpoint that owns them for fast SNI / authority
// lookup. HostPatterns captures wildcard `*.suffix` declarations the
// dispatcher walks when HostIndex misses. CompiledEndpoint.Hosts keeps
// the operator-declared strings unchanged.
//
// Endpoint membership is the transitive closure
// profile → credentials → endpoints: a profile names credentials, and
// each credential names the endpoint(s) it authenticates against.
// Credentials surfaces the raw HCL list (one entry per name as
// written); Endpoints surfaces the resolved set, deduplicated when
// multiple listed credentials bind the same endpoint.
//
// EndpointCredentials is the profile-scoped credential dispatch table:
// for each endpoint reached via this profile, the *CompiledCredential
// entries that the request-time placeholder detector matches against.
// The Placeholder string on each entry comes from the profile's
// inline `{ placeholder = "...", credential = ... }` entries, so two
// profiles binding the same endpoint with the same credentials may
// carry different (or no) placeholders depending on whether the
// binding is ambiguous in that profile.
type CompiledProfile struct {
	Name                string
	Credentials         []*Entity
	Endpoints           map[string]*CompiledEndpoint
	HostIndex           map[string]*CompiledEndpoint
	HostPatterns        []HostPattern
	EndpointCredentials map[string][]*CompiledCredential
	HITLAsyncGrants     bool
}

// HostPattern is one wildcard host binding inside a CompiledProfile.
// Pattern is the full lowercased `*.suffix` string; Endpoint is the
// CompiledEndpoint that declared it. The dispatcher walks
// HostPatterns when an exact HostIndex lookup misses; the slice is
// pre-sorted at compile time so longer (more specific) suffixes are
// tried first.
type HostPattern struct {
	Pattern  string
	Endpoint *CompiledEndpoint
}

// CompiledEndpoint flattens an endpoint plus the rules that target it.
// Body is whatever the endpoint plugin's Build returned (e.g.
// *endpoints.HTTPSEndpoint) — runtime callers type-assert based on
// Family.
//
// Credentials is the global set of credential Entities whose
// `endpoint` / `endpoints` framework attr names this endpoint. The
// list is profile-agnostic — used by code that inspects an endpoint's
// binding (TLS cert lookup, dashboard cards). Per-request credential
// dispatch reads CompiledProfile.EndpointCredentials instead, because
// the placeholder discriminator lives on the profile in v15.
type CompiledEndpoint struct {
	Name        string
	Family      string // "http" | "sql" | "k8s"
	Plugin      *Plugin
	Body        any
	Hosts       []string
	Credentials []*Entity       // credentials globally bound to this endpoint
	Rules       []*CompiledRule // sorted by priority desc

	// Description is the operator-supplied free-text note from the
	// block's `description = "..."` framework attr, or "" if unset.
	// Surfaced in the discovery manifest to orient agents.
	Description string

	// InspectsTruncatable is true when any rule on this endpoint reads a
	// facet whose bytes a wire frontend buffers under a cap (for ssh:
	// ssh.stdin; the http/sql bodies are buffered by their own frontends
	// on a coarser heuristic). The ssh runtime reads it to keep the
	// channel splice byte-for-byte unchanged when no rule needs stdin —
	// inspection is opt-in per endpoint, not paid by every connection.
	// Computed once at compile time from the per-matcher
	// InspectsTruncatableFacet() bool.
	InspectsTruncatable bool

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

// CompiledCredential expands a credential's `endpoint = X` /
// `endpoints = [...]` binding into a per-endpoint entry. The
// Disambiguators map carries the merged dispatch discriminators
// (block-side values from the credential body's
// CredentialDisambiguatorBody + framework-peeled `placeholder`,
// overlaid with profile-side values from `{ credential = X,
// <field> = "..." }` inline entries). An empty / nil map marks the
// no-constraint catchall entry. Dispatch picks the most-specific
// matching entry per request — see runtime.ResolveCredential.
type CompiledCredential struct {
	Disambiguators map[string]string
	Credential     *Entity
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
	d := gw.Defaults
	if d == nil {
		d = &Defaults{}
	}
	cp := &CompiledPolicy{
		UnknownHost:    d.UnknownHost,
		LLMFailMode:    d.LLMFailMode,
		LLMCacheTTL:    d.LLMCacheTTL,
		HumanTimeout:   d.HumanTimeout,
		HumanOnTimeout: d.HumanOnTimeout,
		DashboardURL:   gw.PublicURL(),
		Profiles:       map[string]*CompiledProfile{},
		Endpoints:      map[string]*CompiledEndpoint{},
		Tunnels:        map[string]*CompiledTunnel{},
		Approvers:      p.Approvers,
		Credentials:    p.Credentials,
	}

	// Compile tunnels first so endpoint compilation can resolve
	// `tunnel = X` refs to a *CompiledTunnel.
	if err := compileTunnels(cp, p); err != nil {
		return nil, err
	}

	// Compile every endpoint once into a CompiledEndpoint with the
	// (placeholder) rule list. Credentials attach in the next pass —
	// the credential→endpoint inversion means each credential names
	// its endpoint(s), so the per-endpoint credential list is built
	// by walking p.Credentials and pushing entries into the target
	// endpoints. Rules attach after that.
	for name, ent := range p.Endpoints {
		ce, err := compileEndpoint(name, ent, cp)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", name, err)
		}
		cp.Endpoints[name] = ce
	}

	// Invert credential→endpoint refs into per-endpoint credential
	// lists. This is the global, profile-agnostic view used by
	// code that inspects an endpoint's binding (TLS cert lookup,
	// dashboard cards). Per-request dispatch tables live on each
	// CompiledProfile and are built below.
	if err := attachCredentials(cp, p); err != nil {
		return nil, err
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
	// While here, cache whether any rule reads a truncatable facet so
	// the wire frontend can decide once-per-connection whether to
	// inspect capped bytes (ssh stdin) at all.
	for _, ce := range cp.Endpoints {
		sort.SliceStable(ce.Rules, func(i, j int) bool {
			return ce.Rules[i].Priority > ce.Rules[j].Priority
		})
		for _, r := range ce.Rules {
			if !r.Disabled && r.Matcher != nil && r.Matcher.InspectsTruncatableFacet() {
				ce.InspectsTruncatable = true
				break
			}
		}
	}

	// Build per-profile views. A profile names credentials; endpoint
	// membership is the transitive closure profile → credential →
	// endpoint. Pointers into cp.Endpoints are shared — rules don't
	// fork per profile. EndpointCredentials is the profile-scoped
	// dispatch table; the Placeholder string comes from this profile's
	// inline `{ placeholder = "...", credential = ... }` entries.
	for name, pr := range p.Profiles {
		profile := &CompiledProfile{
			Name:                name,
			Endpoints:           map[string]*CompiledEndpoint{},
			HostIndex:           map[string]*CompiledEndpoint{},
			EndpointCredentials: map[string][]*CompiledCredential{},
			HITLAsyncGrants:     pr.HITLAsyncGrants,
		}
		for _, credName := range pr.Credentials {
			credEnt, ok := p.Credentials[credName]
			if !ok {
				continue
			}
			profile.Credentials = append(profile.Credentials, credEnt)
			merged := mergeDisambig(blockDisambiguators(credEnt), pr.Disambiguators[credName])
			for _, epName := range CredentialEndpointTargets(credEnt) {
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
					host, _, hpErr := hostmatch.SplitHostPort(h)
					if hpErr != nil || host == "" {
						continue
					}
					if hostmatch.IsWildcardHost(host) {
						// Wildcard patterns route on the SNI/authority
						// host alone (no port), so collapse port-qualified
						// `*.foo.com:443` and bare `*.foo.com` to a single
						// pattern keyed on the host portion. Duplicates
						// from listing both forms are removed below.
						profile.HostPatterns = append(profile.HostPatterns, HostPattern{
							Pattern:  strings.ToLower(host),
							Endpoint: ce,
						})
						continue
					}
					profile.HostIndex[strings.ToLower(h)] = ce
				}
				profile.EndpointCredentials[epName] = append(
					profile.EndpointCredentials[epName],
					&CompiledCredential{
						Disambiguators: merged,
						Credential:     credEnt,
					},
				)
			}
		}
		// Add default-port TLS aliases only after every exact host is
		// indexed. That lets an explicit bare host beat any alias, while
		// keeping the alias attached to the HTTPS-family endpoint that
		// declared it even if another endpoint collides on the exact
		// host:port string.
		for _, ce := range profile.Endpoints {
			for _, h := range ce.Hosts {
				if bare, ok := bareHostAlias(ce, h); ok {
					bare = strings.ToLower(bare)
					if _, exists := profile.HostIndex[bare]; !exists {
						profile.HostIndex[bare] = ce
					}
				}
			}
		}
		// Wildcard patterns: longest-suffix-wins, so sort by
		// descending pattern length. Within equal length we sort
		// alphabetically for determinism.
		dedupePatterns(&profile.HostPatterns)
		sortHostPatterns(profile.HostPatterns)
		cp.Profiles[name] = profile
	}

	return cp, nil
}

// CredentialEndpointTargets returns the endpoint names a credential
// binds. Reads either the singular `endpoint` framework attr or the
// list-form `endpoints`; cross-credential validation has already
// rejected the both-set case.
//
// This is the canonical "credentials bind endpoints" direction.
// CompiledEndpoint.Credentials is the inverted index built from these
// targets — callers asking "which endpoints does credential C declare?"
// should use this function, not walk every endpoint's Credentials list.
func CredentialEndpointTargets(ent *Entity) []string {
	if ent == nil {
		return nil
	}
	if list := ent.Framework.RefList("endpoints"); len(list) > 0 {
		return list
	}
	if single := ent.Framework.Ref("endpoint"); single != "" {
		return []string{single}
	}
	return nil
}

// attachCredentials walks every loaded credential and appends its
// *Entity to each endpoint it binds. Order of appended entries is
// deterministic by following p.Order (the source declaration
// sequence) so dashboards / dumps render stable lists across loads.
//
// Placeholder dispatch information is NOT attached here — it lives on
// the profile in v15 and is materialised onto each CompiledProfile in
// the Compile loop below.
func attachCredentials(cp *CompiledPolicy, p *Policy) error {
	walk := func(credName string) error {
		ent, ok := p.Credentials[credName]
		if !ok {
			return nil
		}
		targets := CredentialEndpointTargets(ent)
		if len(targets) == 0 {
			return nil
		}
		for _, epName := range targets {
			ce, ok := cp.Endpoints[epName]
			if !ok {
				return fmt.Errorf("credential %q references endpoint %q which is not declared", credName, epName)
			}
			ce.Credentials = append(ce.Credentials, ent)
		}
		return nil
	}
	seen := map[string]bool{}
	for _, name := range p.Order {
		if _, ok := p.Credentials[name]; !ok {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if err := walk(name); err != nil {
			return err
		}
	}
	// Defensive: any credential missed by Order.
	for name := range p.Credentials {
		if seen[name] {
			continue
		}
		if err := walk(name); err != nil {
			return err
		}
	}
	return nil
}

func compileEndpoint(name string, ent *Entity, cp *CompiledPolicy) (*CompiledEndpoint, error) {
	ce := &CompiledEndpoint{
		Name:        name,
		Family:      ent.Plugin.Family,
		Plugin:      ent.Plugin,
		Body:        ent.Body,
		Description: ent.Framework.Str("description"),
	}
	// Hosts live on the plugin's typed body. We cross-cut via a small
	// interface so the compile pass doesn't have to know every
	// endpoint type — plugins that satisfy this interface contribute
	// their hosts. Credential bindings come from the inverted walk
	// (attachCredentials), not from the endpoint body anymore.
	if hp, ok := ent.Body.(interface{ HostList() []string }); ok {
		ce.Hosts = hp.HostList()
	} else {
		ce.Hosts = extractHosts(ent.Body)
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
	// Wildcards go through HostPatterns, not HostIndex.
	if strings.HasPrefix(bare, "*.") {
		return "", false
	}
	return bare, true
}

// dedupePatterns removes duplicate (pattern, endpoint) entries that
// arise when a profile binds the same wildcard via both bare and
// port-qualified forms (e.g. `*.foo.com` and `*.foo.com:443`).
func dedupePatterns(patterns *[]HostPattern) {
	if len(*patterns) < 2 {
		return
	}
	seen := make(map[string]struct{}, len(*patterns))
	out := (*patterns)[:0]
	for _, p := range *patterns {
		key := p.Pattern + "\x00" + p.Endpoint.Name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	*patterns = out
}

// sortHostPatterns orders patterns so the dispatcher's linear scan
// returns the longest (most specific) suffix first. Ties break
// alphabetically for determinism.
func sortHostPatterns(patterns []HostPattern) {
	sort.SliceStable(patterns, func(i, j int) bool {
		if len(patterns[i].Pattern) != len(patterns[j].Pattern) {
			return len(patterns[i].Pattern) > len(patterns[j].Pattern)
		}
		return patterns[i].Pattern < patterns[j].Pattern
	})
}

// MatchHostPattern is the matcher used at dispatch time. Returns the
// first endpoint whose pattern matches hostname (patterns must already
// be sorted by descending pattern length). Hostname must already be
// lowercased; patterns are stored lowercased by Compile.
func MatchHostPattern(patterns []HostPattern, hostname string) *CompiledEndpoint {
	for _, p := range patterns {
		if hostmatch.MatchWildcard(p.Pattern, hostname) {
			return p.Endpoint
		}
	}
	return nil
}

// extractHosts mirrors the per-type hosts field via interface dispatch.
// The universe of endpoint types is closed; reflect would be overkill.
func extractHosts(body any) []string {
	if h, ok := body.(interface{ EndpointHosts() []string }); ok {
		return h.EndpointHosts()
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
