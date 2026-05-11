package runtime

import (
	"net"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
)

// HostEndpoint resolves a profile + SNI host (with port stripped to
// match how endpoint plugins record hosts) to the endpoint that owns
// it. Returns nil when the profile doesn't bind any matching endpoint
// — the caller then applies the defaults.unknown_host policy.
//
// Hosts include port when an endpoint declared one ("localhost:8443"),
// per the v14 design notes. We try the host-with-port first, then a
// bare host fallback so agents that connect on the default port don't
// have to know whether the endpoint hardcoded ":443".
func HostEndpoint(policy *config.CompiledPolicy, profile, host string) *config.CompiledEndpoint {
	if policy == nil {
		return nil
	}
	lookup := func(p *config.CompiledProfile) *config.CompiledEndpoint {
		if p == nil {
			return nil
		}
		for _, h := range hostLookupCandidates(host) {
			if ep := p.HostIndex[h]; ep != nil {
				return ep
			}
		}
		return nil
	}
	if profile != "" {
		// A named profile is an authorization boundary. If a peer maps to a
		// profile that disappeared after reload, fail closed instead of falling
		// through to another profile's endpoint.
		return lookup(policy.Profiles[profile])
	}
	// Single-tenant fallback: if no peer-to-profile mapping is established,
	// walk every profile and return the first matching endpoint.
	for _, p := range policy.Profiles {
		if ep := lookup(p); ep != nil {
			return ep
		}
	}
	return nil
}

func hostLookupCandidates(host string) []string {
	if host == "" {
		return nil
	}
	out := []string{host}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if p == "443" {
			out = append(out, h)
		}
	} else {
		out = append(out, net.JoinHostPort(host, "443"))
	}
	return out
}

// MatchRequest walks an endpoint's priority-sorted rule list and
// returns the first rule whose matcher accepts req. Disabled rules
// are skipped. nil is returned when no rule fires — the caller then
// applies the defaults.unknown_host policy (or the endpoint plugin's
// own default).
func MatchRequest(ep *config.CompiledEndpoint, req *match.Request) *config.CompiledRule {
	if ep == nil {
		return nil
	}
	for _, r := range ep.Rules {
		if r.Disabled {
			continue
		}
		if r.Matcher == nil {
			// Empty match = match-everything; produced by Compile
			// for catch-all rules without a match block.
			return r
		}
		if r.Matcher.Match(req) {
			return r
		}
	}
	return nil
}

// ResolveCredential picks the credential entry that applies to req.
//
// Single-binding endpoints (`credential = X`) short-circuit and
// return the only entry. Multi-credential endpoints
// (`credentials = [...]`) ask the endpoint plugin's runtime — via
// the PlaceholderDetector interface — which placeholder string the
// agent embedded in the request, then match that against the
// configured placeholders. The trailing no-placeholder entry is the
// fallback when no agent-side placeholder matched.
//
// Returns nil only when an endpoint declares no credentials at all.
// The endpoint plugin then decides what to do (default-deny vs.
// forward-unauthenticated).
func ResolveCredential(ep *config.CompiledEndpoint, req *match.Request) *config.CompiledCredential {
	if ep == nil || len(ep.Credentials) == 0 {
		return nil
	}
	if len(ep.Credentials) == 1 && ep.Credentials[0].Placeholder == "" {
		return ep.Credentials[0]
	}
	var fallback *config.CompiledCredential
	candidates := make([]string, 0, len(ep.Credentials))
	for _, c := range ep.Credentials {
		if c.Placeholder == "" {
			fallback = c
			continue
		}
		candidates = append(candidates, c.Placeholder)
	}
	var sent string
	if det, ok := ep.Plugin.Runtime.(PlaceholderDetector); ok && req != nil && len(candidates) > 0 {
		sent = det.DetectPlaceholder(req, candidates)
	}
	if sent != "" {
		for _, c := range ep.Credentials {
			if c.Placeholder == sent {
				return c
			}
		}
	}
	return fallback
}
