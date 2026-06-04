// Package match holds the runtime types the request handler walks
// when dispatching against the compiled policy: the Matcher interface
// every rule's compiled predicate satisfies and the family-tagged
// Request snapshot the matcher reads.
//
// Per-family matchers themselves live in facet packages under
// config/plugins/facets/, each of which builds a *cel.Env over the
// variables it exposes to rule conditions. The shared CEL plumbing
// lives in cel.go.
package match

import (
	"net/http"
	"net/url"
)

// Request is the family-tagged request snapshot passed to Matcher.Match.
// The handler populates whichever family-specific fields apply and
// stashes any derived per-family metadata on Meta — its concrete type
// is owned by the facet plugin, which type-asserts inside its matcher.
type Request struct {
	Family string // e.g. "http" | "sql" | "k8s" | future plugins

	// Common
	Credential string // bare-name reference of the credential the
	// agent dispatched against, "" if none
	PeerIP string // source IP of the agent — used to scope per-device rules

	// Database is the agent-declared target database. Postgres reads
	// it from the StartupMessage `database` parameter (falling back to
	// `user` per pg convention); clickhouse_native from
	// Hello.Database; clickhouse_https from `?database=` query (with
	// X-ClickHouse-Database as fallback). Empty when the protocol
	// carries no database concept. Two consumers read it: rules via
	// the `sql.database` CEL facet field, and runtime.ResolveCredential
	// to filter credentials whose `database`/`databases` constraint
	// pins them to specific databases.
	Database string

	// User is the agent-declared upstream user. Postgres reads it
	// from the StartupMessage `user` parameter; clickhouse_native
	// from Hello.Username; ssh from the connection's username field.
	// Empty when the protocol carries no user concept or the wire
	// frontend hasn't extracted it yet. Consumed by
	// runtime.ResolveCredential to pick a credential whose
	// disambiguator `user` constraint matches — the analogue of
	// Database for protocols that route credentials by user identity
	// rather than database name.
	User string

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

	// Truncated is set by a wire frontend when the bytes it could
	// expose to the matcher were capped by a per-plugin inspection
	// buffer (HTTPS body cap, postgres frame cap, clickhouse query
	// body cap). The matcher marks every truncatable facet path as a
	// CEL unknown on such a request, so a condition whose outcome
	// depends on the capped bytes evaluates Unevaluable (→ the
	// dispatcher fails closed), while a condition that resolves on
	// its other predicates still matches or no-matches honestly.
	Truncated bool

	// Unparseable is set by a wire frontend when its SQL parser
	// refuses the Query bytes outright (the statement is still on
	// Meta.Statement, but Verb / Tables / Functions are left zero
	// because the parser couldn't derive them). The matcher marks
	// every parser-derived facet path as a CEL unknown on such a
	// request — a condition whose outcome depends on one evaluates
	// Unevaluable, while rules keyed only on connection-level facets
	// (credential, peer_ip) or on the raw statement still fire
	// normally.
	//
	// Differs from Truncated in two ways: (a) the statement text
	// IS populated when Unparseable=true, so `sql.statement` rules
	// continue to evaluate honestly; (b) the trigger is parser
	// rejection, not byte-cap truncation, so wire frontends with
	// no parser leave it false.
	Unparseable bool
}

// Result is the three-valued outcome of evaluating a rule's
// condition against a request.
type Result int

const (
	// NoMatch reports that the condition evaluated cleanly to false.
	NoMatch Result = iota
	// Matched reports that the condition evaluated cleanly to true.
	Matched
	// Unevaluable reports that the condition's outcome could not be
	// determined honestly — it depends on a facet value the gateway
	// doesn't have (truncated bytes, parser-refused fields), or
	// evaluation errored at runtime (missing JSON key, type
	// mismatch). The dispatcher fails closed on this result: an
	// unevaluable rule synthesizes a deny rather than being silently
	// skipped, because "skipped" would let a deny rule fail open.
	Unevaluable
)

// ResultOf converts a boolean match expectation to a Result: true
// is Matched, false is NoMatch. A convenience for callers (mostly
// tests) asserting two-valued outcomes; Unevaluable never maps from
// a bool.
func ResultOf(matched bool) Result {
	if matched {
		return Matched
	}
	return NoMatch
}

// Decision is a Result plus, for Unevaluable, a human-readable
// detail naming what made the condition unevaluable (the unknown
// facet paths, or the CEL evaluation error). Detail is "" for
// NoMatch / Matched.
type Decision struct {
	Result Result
	Detail string
}

// Matcher evaluates a rule's match predicate against a Request and
// returns a three-valued Decision. Implementations are
// family-specific and live in their facet plugin's package.
//
// InspectsTruncatableFacet reports whether the matcher's compiled
// condition reads any field of the request whose value could be
// truncated by a wire frontend's inspection buffer (HTTPS body /
// body_json, SQL verb / tables / functions / statement, SSH stdin).
// It does NOT drive verdicts — those come from Match's Unevaluable
// result — it is the compile-time laziness signal: Compile rolls it
// up into CompiledEndpoint.InspectsTruncatable so wire frontends
// know whether any rule needs the capped bytes buffered at all
// (e.g. the ssh endpoint only takes the stdin-buffering path when
// some rule reads ssh.stdin).
type Matcher interface {
	Match(req *Request) Decision
	InspectsTruncatableFacet() bool
}

// PathOf returns the URL's path, or "" when u is nil. Common enough
// across facets to live here.
func PathOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Path
}
