// Package match holds the runtime types the request handler walks
// when dispatching against the compiled policy: the Matcher interface
// every rule's compiled predicate satisfies, the family-tagged Request
// snapshot the matcher reads, and the shared helpers (glob parsing,
// list-OR semantics, body-JSON subset matching) that per-family
// matchers compose.
//
// Per-family matchers themselves live in facet packages under
// config/plugins/facets/. The match.New / match.KnownKeys family
// switch is gone — config/facet.NewMatcher and config/facet.KnownKeys
// take its place — but the helpers stay here because every facet
// composes them.
package match

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Request is the family-tagged request snapshot passed to Matcher.Match.
// The handler populates whichever family-specific fields apply and
// stashes any derived per-family metadata on Meta — its concrete type
// is owned by the facet plugin, which type-asserts inside its matcher.
type Request struct {
	Family string // e.g. "https" | "sql" | "k8s" | future plugins

	// Common
	Credential string // bare-name reference of the credential the
	// agent dispatched against, "" if none
	PeerIP string // source IP of the agent — used to scope per-device rules

	// HTTP-shaped fields, populated whenever the gateway has them
	// available. Even non-HTTP wire frontends (postgres, clickhouse
	// over TLS) leave these zero rather than fake them.
	Method  string
	URL     *url.URL
	Headers http.Header
	Body    []byte // populated when at least one rule needed it

	// Meta is the per-family derived metadata. The owning facet
	// plugin sets the concrete type — *sql.Meta for SQL, *k8s.Meta
	// for k8s, etc. — either via facet.Runtime.PrepareRequest
	// (HTTPS-family handler) or directly from a wire-frame frontend
	// (postgres/clickhouse). Matchers type-assert and fall through to
	// "no match" when the assertion fails (e.g. an https-family rule
	// running against a request whose Meta is *sql.Meta).
	Meta any
}

// Matcher walks a Request and returns true when the rule's match
// predicate is satisfied. Implementations are family-specific and
// live in their facet plugin's package.
type Matcher interface {
	Match(req *Request) bool
}

// ── shared helpers ────────────────────────────────────────────────────

// StringList coerces a match-map value (either a single string or a
// list of strings) into []string. Returns nil if the value is missing
// or wrong-shaped.
func StringList(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return append([]string(nil), x...)
	}
	return nil
}

// StringValue returns the string at key, or "" when absent / wrong shape.
func StringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Glob is one element of a list-of-globs match key. Negative entries
// (originally prefixed with "!") match when the underlying glob does
// NOT match.
type Glob struct {
	Pattern string
	Neg     bool
}

// ParseGlobs interprets a match-map value as a list of glob patterns.
// Single strings and []string both coerce; entries with a leading "!"
// become negative globs.
func ParseGlobs(raw any) []Glob {
	xs := StringList(raw)
	if xs == nil {
		return nil
	}
	out := make([]Glob, len(xs))
	for i, s := range xs {
		neg := false
		if strings.HasPrefix(s, "!") {
			neg = true
			s = s[1:]
		}
		out[i] = Glob{Pattern: s, Neg: neg}
	}
	return out
}

// Any returns true iff the candidate satisfies the list — list
// semantics are "any positive matches OR no positives AND no negatives
// match". Mixed lists compose: every "!" entry is checked
// (candidate must NOT match it); positive entries are OR'd.
//
// Examples:
//
//	["pods/exec", "pods/attach"]                   → in [...]
//	["!*/exec", "!*/attach", "!*/portforward"]     → not (any of those)
//	["foo", "!bar"]                                → matches foo AND not bar
func Any(globs []Glob, candidate string) bool {
	if len(globs) == 0 {
		return true // no constraint
	}
	hasPositive := false
	positiveOK := false
	for _, g := range globs {
		ok := PatternMatch(g.Pattern, candidate)
		if g.Neg {
			if ok {
				return false
			}
			continue
		}
		hasPositive = true
		if ok {
			positiveOK = true
		}
	}
	if hasPositive {
		return positiveOK
	}
	return true
}

// PatternMatch is a thin wrapper around path.Match that also handles
// the empty-pattern edge case (matches anything).
func PatternMatch(pattern, s string) bool {
	if pattern == "" {
		return true
	}
	if pattern == s {
		return true
	}
	if strings.ContainsAny(pattern, "*?[") {
		ok, _ := path.Match(pattern, s)
		return ok
	}
	return false
}

// EqualsIgnoreCase is for verbs and methods which are case-folded.
func EqualsIgnoreCase(a, b string) bool {
	return strings.EqualFold(a, b)
}

// LowerAll returns a copy of xs with every element lower-cased.
func LowerAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, s := range xs {
		out[i] = strings.ToLower(s)
	}
	return out
}

// AnyOfStrings reports whether at least one candidate satisfies the
// glob list. Used for SQL tables/functions where a single statement
// can name several.
func AnyOfStrings(candidates []string, globs []Glob) bool {
	for _, c := range candidates {
		if Any(globs, c) {
			return true
		}
	}
	return false
}

// SliceOverlap returns true iff at least one entry in want is in got.
// Empty want is "no constraint" → true. Matching is substring-loose
// to mirror how HTTP header values and URL query values can carry
// extra qualifiers around the canonical token.
func SliceOverlap(want, got []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		for _, g := range got {
			if w == g || strings.Contains(g, w) {
				return true
			}
		}
	}
	return false
}

// PathOf returns the URL's path, or "" when u is nil. Common enough
// across facets to live here.
func PathOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Path
}
