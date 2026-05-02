package runtime

import (
	"github.com/denoland/clawpatrol-go/config"
	"github.com/denoland/clawpatrol-go/config/match"
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
	prof, ok := policy.Profiles[profile]
	if !ok {
		// Single-tenant fallback: if no peer-to-profile mapping is
		// established, walk every profile and return the first match.
		// Matches main.go's existing profileFor behavior when only
		// one profile exists.
		for _, p := range policy.Profiles {
			if ep := p.HostIndex[host]; ep != nil {
				return ep
			}
		}
		return nil
	}
	if ep := prof.HostIndex[host]; ep != nil {
		return ep
	}
	return nil
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

// ResolveCredential picks the credential entry that applies to a
// request. For singular endpoints it returns the only entry. For
// multi-credential endpoints (placeholder dispatch) it tries each
// placeholder against the request — caller-provided detector
// decides which placeholder the agent sent. Returns nil when no
// entry matches; the endpoint plugin then decides what to do
// (default-deny vs. forward-without-injection).
func ResolveCredential(ep *config.CompiledEndpoint, hasPlaceholder func(string) bool) *config.CompiledCredential {
	if ep == nil || len(ep.Credentials) == 0 {
		return nil
	}
	if len(ep.Credentials) == 1 && ep.Credentials[0].Placeholder == "" {
		return ep.Credentials[0]
	}
	var fallback *config.CompiledCredential
	for _, c := range ep.Credentials {
		if c.Placeholder == "" {
			fallback = c
			continue
		}
		if hasPlaceholder != nil && hasPlaceholder(c.Placeholder) {
			return c
		}
	}
	return fallback
}
