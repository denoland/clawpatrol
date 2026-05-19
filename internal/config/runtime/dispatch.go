package runtime

import (
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
)

// HostEndpoint resolves a profile + SNI/authority host to the endpoint
// that owns it. Compile populates HostIndex with exact declared hosts
// plus bare-host aliases for HTTPS-family default-port declarations,
// so a TLS SNI value like "api.example.com" can match an endpoint
// declared as "api.example.com:443" without a runtime scan. DNS
// hostnames are case-insensitive; the lookup key is lowercased to
// match the lowercase keys Compile inserts.
//
// When the exact lookup misses we walk HostPatterns — the profile's
// wildcard declarations (`hosts = ["*.foo.com"]`) — in
// longest-suffix-first order. Exact matches always win over wildcards
// for the same name. Returns nil when nothing matches; the caller
// then applies the defaults.unknown_host policy.
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
		// one profile exists. Exact matches are tried across all
		// profiles before falling back to wildcards so a profile that
		// declared the exact host wins over a different profile's
		// wildcard.
		for _, p := range policy.Profiles {
			if ep := p.HostIndex[host]; ep != nil {
				return ep
			}
		}
		for _, p := range policy.Profiles {
			if ep := config.MatchHostPattern(p.HostPatterns, host); ep != nil {
				return ep
			}
		}
		return nil
	}
	if ep := prof.HostIndex[host]; ep != nil {
		return ep
	}
	return config.MatchHostPattern(prof.HostPatterns, host)
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
//
// Unparseable-request fail-close: same shape as the truncated path,
// but keyed on req.Unparseable + InspectsUnparseableFacet(). When a
// frontend's parser refused the inbound bytes, the parser-derived
// facets (e.g. for SQL: verb / tables / functions) are zero on the
// request; a rule that reads any of them on an Unparseable request
// would be evaluating zero values that don't reflect the actual
// payload, so it synthesizes a deny instead. Rules that read only
// the raw payload (e.g. sql.statement), the credential, or the
// peer IP still get a normal Match call — those facets are populated
// regardless of parse success. Rule priority is walked first, so a
// higher-priority payload-only rule that matches keeps its verdict;
// an unparseable request only triggers the synthesized deny when no
// higher-priority rule covers it AND a lower-priority rule references
// an unset parser facet.
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
		if req != nil && req.Unparseable && r.Matcher.InspectsUnparseableFacet() {
			return synthesizeUnparseableDeny(r)
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

// synthesizeUnparseableDeny mirrors synthesizeTruncatedDeny for the
// parser-failure gate. The reason names the rule whose contract the
// unparseable-request case broke, so logs / dashboard cards attribute
// the synthesized deny to the matching rule rather than to an opaque
// "unparseable" line item. The string is intentionally generic across
// facet families: any plugin whose parser refused its inbound bytes
// (SQL today; an external rule plugin tomorrow) routes through here.
func synthesizeUnparseableDeny(r *config.CompiledRule) *config.CompiledRule {
	reason := "rule \"" + r.Name + "\" references a facet that the gateway's parser could not derive from the unparseable request; failing closed"
	synth := *r
	synth.Outcome = config.Outcome{
		Verdict: "deny",
		Reason:  reason,
	}
	return &synth
}

// ResolveCredential picks the credential entry that applies to req.
//
// Multi-credential endpoints (`credentials = [...]`) carry up to
// two dispatch constraints per entry: a placeholder string (matched
// against whatever the endpoint plugin's PlaceholderDetector pulled
// off the request) and a database list (matched against
// req.Database). An entry matches iff every constraint it declares
// is satisfied. Among matching entries the most-specific (highest
// number of declared constraints) wins; compile-time validation
// guarantees uniqueness of constraint signatures so equal-specificity
// ties are impossible at runtime — but if one ever shows up we
// return nil rather than silently mis-routing.
//
// Single-binding endpoints (`credential = X`) short-circuit: the
// only entry has no constraints and matches anything.
//
// Returns nil when no entry matches, or when the endpoint declares
// no credentials at all. The endpoint plugin then decides what to
// do (default-deny vs forward-unauthenticated).
func ResolveCredential(ep *config.CompiledEndpoint, req *match.Request) *config.CompiledCredential {
	if ep == nil || len(ep.Credentials) == 0 {
		return nil
	}
	if len(ep.Credentials) == 1 && ep.Credentials[0].Placeholder == "" && len(ep.Credentials[0].Databases) == 0 {
		return ep.Credentials[0]
	}
	candidates := make([]string, 0, len(ep.Credentials))
	for _, c := range ep.Credentials {
		if c.Placeholder != "" {
			candidates = append(candidates, c.Placeholder)
		}
	}
	var sent string
	if det, ok := ep.Plugin.Runtime.(PlaceholderDetector); ok && req != nil && len(candidates) > 0 {
		sent = det.DetectPlaceholder(req, candidates)
	}
	var database string
	if req != nil {
		database = req.Database
	}
	var best *config.CompiledCredential
	bestSpecificity := -1
	tiedAtBest := false
	for _, c := range ep.Credentials {
		phMatch := c.Placeholder == "" || c.Placeholder == sent
		dbMatch := len(c.Databases) == 0 || containsString(c.Databases, database)
		if !phMatch || !dbMatch {
			continue
		}
		spec := 0
		if c.Placeholder != "" {
			spec++
		}
		if len(c.Databases) > 0 {
			spec++
		}
		switch {
		case spec > bestSpecificity:
			best = c
			bestSpecificity = spec
			tiedAtBest = false
		case spec == bestSpecificity:
			tiedAtBest = true
		}
	}
	if tiedAtBest {
		// Compile-time validation should have ruled this out; refuse
		// to guess.
		return nil
	}
	return best
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
