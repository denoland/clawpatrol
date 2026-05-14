package runtime

import (
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
)

// HostEndpoint resolves a profile + SNI/authority host to the endpoint
// that owns it. Compile populates HostIndex with exact declared hosts
// plus bare-host aliases for HTTPS-family default-port declarations,
// so a TLS SNI value like "api.example.com" can match an endpoint
// declared as "api.example.com:443" without a runtime scan. DNS
// hostnames are case-insensitive; the lookup key is lowercased to
// match the lowercase keys Compile inserts. Returns nil when the
// profile doesn't bind any matching endpoint — the caller then
// applies the defaults.unknown_host policy.
func HostEndpoint(policy *config.CompiledPolicy, profile, host string) *config.CompiledEndpoint {
	if policy == nil {
		return nil
	}
	host = strings.ToLower(host)
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
//
// Truncated-request fail-close: when req.Truncated is set, a rule
// whose matcher reports InspectsTruncatableFacet() == true is
// auto-fired with a synthesized deny verdict — the matcher is NOT
// called, because its CEL condition reads bytes the wire frontend
// already discarded. Higher-priority rules that don't read truncated
// facets still get to match normally; this only fails the rules
// that would have been evaluating ghost bytes. The returned
// CompiledRule keeps the original rule's identity (name / priority)
// so logs still attribute the deny to the rule whose contract the
// truncation broke.
func MatchRequest(ep *config.CompiledEndpoint, req *match.Request) *config.CompiledRule {
	if ep == nil {
		return nil
	}
	for _, r := range ep.Rules {
		if r.Disabled {
			continue
		}
		// Credential predicate: rule applies only when the
		// dispatching credential matches. Checked before the CEL
		// program so an empty condition + a credential pin still
		// behaves as expected.
		if r.Credential != "" {
			if req == nil || req.Credential != r.Credential {
				continue
			}
		}
		if r.Matcher == nil {
			// Empty match = match-everything; produced by Compile
			// for catch-all rules without a condition. A catch-all
			// reads no facets, so it can't be poisoned by
			// truncation — fire it as written even when
			// req.Truncated.
			return r
		}
		if req != nil && req.Truncated && r.Matcher.InspectsTruncatableFacet() {
			return synthesizeTruncatedDeny(r)
		}
		if r.Matcher.Match(req) {
			return r
		}
	}
	return nil
}

// synthesizeTruncatedDeny returns a CompiledRule that mirrors r's
// identity but forces a deny verdict with a fabricated reason. Used
// by MatchRequest when a rule that reads a truncatable facet meets
// a request whose facet bytes were capped at the wire — the rule's
// match predicate can't be evaluated honestly, so we surface a
// fail-closed deny attributed to the rule that owns the contract.
func synthesizeTruncatedDeny(r *config.CompiledRule) *config.CompiledRule {
	reason := "rule \"" + r.Name + "\" reads a request facet whose bytes were truncated by the gateway's inspection buffer; failing closed"
	synth := *r
	synth.Outcome = config.Outcome{
		Verdict: "deny",
		Reason:  reason,
	}
	return &synth
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
