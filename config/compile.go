package config

import (
	"fmt"
	"sort"

	"github.com/denoland/clawpatrol-go/config/match"
)

// CompiledPolicy is the runtime-friendly view of a loaded gateway:
// per-profile maps that the request handler walks at dispatch time.
// Build with Compile after Load.
type CompiledPolicy struct {
	Defaults Defaults

	// Profiles indexed by name. Each holds a per-endpoint rule list,
	// already family-tagged and priority-sorted.
	Profiles map[string]*CompiledProfile

	// Endpoints contains every declared endpoint, keyed by name.
	// Useful for callers that don't care about profile scoping
	// (status pages, dashboard listings).
	Endpoints map[string]*CompiledEndpoint

	// Approvers / Policies / Credentials surface the same entities
	// from the Policy struct under a runtime-friendly typed alias —
	// they're pointers into the same Entity records, no copies.
	Approvers   map[string]*Entity
	Credentials map[string]*Entity
	Policies    map[string]*PolicyText
}

// CompiledProfile binds an identity to the endpoint set its requests
// dispatch against. Endpoints map by name; HostIndex maps every host
// (with port) to the endpoint that owns it for fast SNI / authority
// lookup.
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
	Family      string // "https" | "sql" | "k8s"
	Plugin      *Plugin
	Body        any
	Hosts       []string
	Credentials []*CompiledCredential // resolved to Entity records
	Rules       []*CompiledRule       // sorted by priority desc
}

// CompiledCredential expands an endpoint's `credential = X` or
// `credentials = [...]` binding into a flat list. Each entry pairs a
// dispatcher placeholder (empty for the singular / no-placeholder
// fallback) with the credential entity.
type CompiledCredential struct {
	Placeholder string
	Credential  *Entity
}

// CompiledRule is one priority-sorted rule attached to an endpoint.
type CompiledRule struct {
	Name     string
	Priority int
	Disabled bool
	Matcher  match.Matcher
	Outcome  Outcome
}

// Outcome captures a rule's verdict + (when applicable) approve chain.
// Exactly one of Verdict and Approve is set after Build's validation.
type Outcome struct {
	Verdict string // "allow" | "deny"
	Reason  string
	Approve []ApproveStage
}

// ApproveStage is one node in an approve = [...] chain. Either a
// bare-name reference (Name set, Policy empty) or a struct stage with
// a bound LLM policy and optional cache TTL override. Lives here so
// runtime callers don't need to import the rules plugin package.
type ApproveStage struct {
	Name     string `json:"name"`
	Policy   string `json:"policy,omitempty"`
	CacheTTL int    `json:"cache_ttl,omitempty"` // seconds; 0 → defaults
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
		Defaults:    p.Defaults,
		Profiles:    map[string]*CompiledProfile{},
		Endpoints:   map[string]*CompiledEndpoint{},
		Approvers:   p.Approvers,
		Credentials: p.Credentials,
		Policies:    p.Policies,
	}

	// Compile every endpoint once into a CompiledEndpoint with
	// resolved credentials and (placeholder) rule list. Rules attach
	// in the next pass.
	for name, ent := range p.Endpoints {
		ce, err := compileEndpoint(name, ent, p)
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
				// Already reported at Load time.
				continue
			}
			profile.Endpoints[epName] = ce
			for _, h := range ce.Hosts {
				profile.HostIndex[h] = ce
			}
		}
		cp.Profiles[name] = profile
	}

	return cp, nil
}

func compileEndpoint(name string, ent *Entity, p *Policy) (*CompiledEndpoint, error) {
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
		credEnt, ok := p.Credentials[cb.credential]
		if !ok {
			return nil, fmt.Errorf("credential %q not declared", cb.credential)
		}
		ce.Credentials = append(ce.Credentials, &CompiledCredential{
			Placeholder: cb.placeholder,
			Credential:  credEnt,
		})
	}
	return ce, nil
}

// hostExtractor / credentialExtractor are the small cross-cut readers
// used by compileEndpoint. They live on the endpoint plugin types but
// are referenced via interface here to keep imports clean.

type hostsAndCreds struct {
	placeholder string
	credential  string
}

// extractHosts mirrors the per-type hosts field via reflection — kept
// as a tiny interface-method dispatch on the endpoint plugin types
// instead of going through reflect, since the universe of endpoint
// types is closed.
func extractHosts(body any) []string {
	if h, ok := body.(interface{ EndpointHosts() []string }); ok {
		return h.EndpointHosts()
	}
	return nil
}

func extractCredentialBindings(body any) []hostsAndCreds {
	if h, ok := body.(interface {
		EndpointCredentials() []struct {
			Placeholder string
			Credential  string
		}
	}); ok {
		raw := h.EndpointCredentials()
		out := make([]hostsAndCreds, len(raw))
		for i, r := range raw {
			out[i] = hostsAndCreds{placeholder: r.Placeholder, credential: r.Credential}
		}
		return out
	}
	return nil
}
