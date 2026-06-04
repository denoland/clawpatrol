package runtime

import (
	"fmt"
	"log"
	"sort"
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
// Unevaluable fail-close: a matcher returns three-valued Decisions.
// When a rule's condition cannot be evaluated honestly — its outcome
// depends on a facet value the gateway doesn't have (bytes capped at
// the inspection buffer, parser-refused SQL fields, both surfaced as
// viral CEL unknowns), or evaluation errored at runtime — the rule is
// fired with a synthesized deny verdict instead of being silently
// skipped (skipping would let a deny rule fail open). The returned
// CompiledRule keeps the original rule's identity (name / priority)
// so logs still attribute the deny to the rule whose contract broke.
//
// Because the unknowns are value-level, a rule that merely mentions a
// truncated / unparseable facet still resolves honestly when its
// outcome doesn't depend on it: `sql.verb == 'select' && sql.database
// == 'x'` on an unparseable request with database 'y' evaluates
// `unknown && false == false` and cleanly falls through to the next
// rule. Rules keyed only on always-available facets (credential,
// peer IP, sql.statement on an unparseable query) are unaffected.
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
		switch d := r.Matcher.Match(req); d.Result {
		case match.Matched:
			return r
		case match.Unevaluable:
			return synthesizeUnevaluableDeny(r, req, d.Detail)
		}
	}
	return nil
}

// MatchRequestFailClosed wraps MatchRequest for wire frontends whose
// request bytes the gateway could not fully inspect (Truncated /
// Unparseable). On such a request, "no rule matched" may simply mean
// every rule's outcome was independent of the missing bytes
// (absorption) — not that the operator intended the bytes to flow.
// When the endpoint declares at least one enabled rule and none
// matched, this returns a synthesized catch-all deny instead of nil,
// so an uninspectable payload never rides the implicit-allow default
// past a rule set that exists. Endpoints with no rules at all keep
// their legacy pass-through default, and fully-inspected requests
// behave exactly like MatchRequest.
//
// SQL frontends (postgres, clickhouse_native) route their statement
// evaluation through this; the HTTPS path deliberately does NOT —
// rule-less LLM endpoints routinely forward >cap request bodies, and
// inspectable header/method facets remain matchable there.
func MatchRequestFailClosed(ep *config.CompiledEndpoint, req *match.Request) *config.CompiledRule {
	cr := MatchRequest(ep, req)
	if cr != nil || ep == nil || req == nil || (!req.Truncated && !req.Unparseable) {
		return cr
	}
	hasRules := false
	for _, r := range ep.Rules {
		if !r.Disabled {
			hasRules = true
			break
		}
	}
	if !hasRules {
		return nil
	}
	return &config.CompiledRule{
		Outcome: config.Outcome{
			Verdict: "deny",
			Reason: "request bytes were " + unevaluableCause(req) +
				" and no rule explicitly allowed the request; failing closed",
		},
	}
}

// synthesizeUnevaluableDeny returns a CompiledRule that mirrors r's
// identity but forces a deny verdict with a fabricated reason. Used
// by MatchRequest when a rule's match predicate can't be evaluated
// honestly — its condition depends on a facet value the gateway
// doesn't have (truncated bytes, parser-refused fields) or errored
// at runtime — so we surface a fail-closed deny attributed to the
// rule that owns the contract.
//
// The agent-visible reason names only the rule and the coarse cause.
// The matcher's full detail (the unknown facet paths, or the CEL
// evaluation error text) is deliberately kept out of it: cel-go
// errors like `no such key: <field>` would let an agent probe which
// fields a rule inspects by varying request payloads and reading
// deny reasons. The detail goes to the gateway log for the operator
// instead.
func synthesizeUnevaluableDeny(r *config.CompiledRule, req *match.Request, detail string) *config.CompiledRule {
	reason := "rule \"" + r.Name + "\" could not be evaluated against this request (" + unevaluableCause(req) + "); failing closed"
	log.Printf("rule %q unevaluable: %s", r.Name, detail)
	synth := *r
	synth.Outcome = config.Outcome{
		Verdict: "deny",
		Reason:  reason,
	}
	return &synth
}

// unevaluableCause renders the agent-safe cause of an unevaluable
// condition from the request's inspection flags. The agent already
// knows it sent an oversized or garbled payload, so naming the
// category leaks nothing; anything finer-grained stays in the
// operator log.
func unevaluableCause(req *match.Request) string {
	switch {
	case req != nil && req.Truncated && req.Unparseable:
		return "truncated at the inspection buffer and unparseable"
	case req != nil && req.Truncated:
		return "truncated at the inspection buffer"
	case req != nil && req.Unparseable:
		return "unparseable"
	default:
		return "evaluation error"
	}
}

// ResolveCredential picks the credential entry that applies to req
// for the given profile and endpoint.
//
// The profile's per-endpoint credential list (CompiledProfile.
// EndpointCredentials) carries the dispatch entries — each pairs a
// credential with a merged disambiguator map (block-side body fields
// + framework-peeled `placeholder`, overlaid with the profile's
// inline `{ credential = X, <field> = "..." }` entries). Field
// names are conventionally:
//
//   - "placeholder" — the dispatcher asks the endpoint plugin's
//     PlaceholderDetector to extract the agent-sent placeholder
//     string from the request body / headers.
//   - "user"        — matched against req.User (postgres /
//     clickhouse_native populate this from the wire-protocol
//     StartupMessage / Hello).
//   - "database"    — matched against req.Database.
//
// An entry matches iff every constraint it declares is satisfied.
// Among matching entries the most-specific (highest number of
// declared constraints) wins; compile-time validation guarantees
// signature uniqueness per (profile, endpoint) so equal-specificity
// ties are impossible at runtime — but if one ever shows up we
// return nil rather than silently mis-routing.
//
// Single-entry bindings short-circuit unconditionally: with only one
// credential on a (profile, endpoint), there's nothing to
// disambiguate. The credential's body fields (postgres_credential's
// `user`, clickhouse's `database`, etc.) still drive upstream auth,
// but the agent doesn't need to mirror those values in its
// StartupMessage / Hello to make the dispatch pick the credential.
// Multi-entry endpoints still go through the disambiguator filter
// below so placeholder-driven `pg_ro` / `pg_rw` patterns keep
// working.
//
// Returns nil when the profile is unknown OR the profile binds no
// credential to ep — the caller (endpoint plugin) decides whether to
// default-deny vs. forward-unauthenticated.
func ResolveCredential(policy *config.CompiledPolicy, profile string, ep *config.CompiledEndpoint, req *match.Request) *config.CompiledCredential {
	if ep == nil {
		return nil
	}
	entries := profileCredentialsAt(policy, profile, ep.Name)
	if len(entries) == 0 {
		return nil
	}
	if len(entries) == 1 {
		return entries[0]
	}
	// Placeholder detection: if any entry constrains "placeholder",
	// ask the endpoint plugin's detector once for the value the
	// agent embedded in this request. Cheaper than re-detecting per
	// entry; consistent across same-placeholder candidates that
	// differ on other fields.
	var sentPlaceholder string
	if det, ok := ep.Plugin.Runtime.(PlaceholderDetector); ok && req != nil {
		candidates := make([]string, 0, len(entries))
		seen := map[string]bool{}
		for _, c := range entries {
			ph := c.Disambiguators["placeholder"]
			if ph != "" && !seen[ph] {
				candidates = append(candidates, ph)
				seen[ph] = true
			}
		}
		if len(candidates) > 0 {
			sentPlaceholder = det.DetectPlaceholder(req, candidates)
		}
	}
	var best *config.CompiledCredential
	bestSpecificity := -1
	tiedAtBest := false
	for _, c := range entries {
		if !disambiguatorMatches(c.Disambiguators, req, sentPlaceholder) {
			continue
		}
		spec := len(c.Disambiguators)
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

// CredentialMismatchReason builds a one-line explanation of why
// ResolveCredential just returned nil for (profile, ep, req) despite
// the binding existing in policy. Useful for surfacing actionable
// connection errors to agents (e.g. postgres' SCRAM error path) so
// the operator sees "user 'none' doesn't match" instead of a flat
// "no credential bound". Returns "" when the profile-endpoint pair
// has no bound credentials at all — the caller falls back to its
// generic "no credential" message in that case.
func CredentialMismatchReason(policy *config.CompiledPolicy, profile string, ep *config.CompiledEndpoint, req *match.Request) string {
	if ep == nil {
		return ""
	}
	entries := profileCredentialsAt(policy, profile, ep.Name)
	if len(entries) == 0 {
		return ""
	}
	// Collect the distinct disambiguator values declared per field
	// across all entries — that's the set of values the agent could
	// have sent to make any one entry match.
	expected := map[string]map[string]struct{}{}
	for _, c := range entries {
		for field, want := range c.Disambiguators {
			if want == "" {
				continue
			}
			set, ok := expected[field]
			if !ok {
				set = map[string]struct{}{}
				expected[field] = set
			}
			set[want] = struct{}{}
		}
	}
	if len(expected) == 0 {
		return ""
	}
	fields := make([]string, 0, len(expected))
	for f := range expected {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	var parts []string
	for _, field := range fields {
		got := ""
		if req != nil {
			switch field {
			case "user":
				got = req.User
			case "database":
				got = req.Database
			}
		}
		values := make([]string, 0, len(expected[field]))
		for v := range expected[field] {
			values = append(values, v)
		}
		sort.Strings(values)
		valueList := strings.Join(values, ", ")
		if got == "" {
			parts = append(parts, fmt.Sprintf("%s missing (valid: %s)", field, valueList))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%q not in [%s]", field, got, valueList))
		}
	}
	return strings.Join(parts, "; ")
}

// disambiguatorMatches reports whether every constraint in the
// entry's disambiguator map is satisfied by the request. Unknown
// field names always fail-closed — the dispatcher won't guess at
// future fields it doesn't know how to read off req.
func disambiguatorMatches(d map[string]string, req *match.Request, sentPlaceholder string) bool {
	for field, want := range d {
		var got string
		switch field {
		case "placeholder":
			got = sentPlaceholder
		case "user":
			if req != nil {
				got = req.User
			}
		case "database":
			if req != nil {
				got = req.Database
			}
		default:
			return false
		}
		if want != got {
			return false
		}
	}
	return true
}

// profileCredentialsAt returns the per-endpoint dispatch entries for
// the named profile. When the profile is unknown but the endpoint has
// a single globally-bound credential, the singleton entry is
// synthesized so a fallback HostEndpoint match still injects auth —
// matches the pre-v15 "missing profile but only one credential" path.
func profileCredentialsAt(policy *config.CompiledPolicy, profile, epName string) []*config.CompiledCredential {
	if policy == nil {
		return nil
	}
	if prof, ok := policy.Profiles[profile]; ok {
		return prof.EndpointCredentials[epName]
	}
	ep, ok := policy.Endpoints[epName]
	if !ok {
		return nil
	}
	if len(ep.Credentials) == 1 {
		return []*config.CompiledCredential{{Credential: ep.Credentials[0]}}
	}
	return nil
}
