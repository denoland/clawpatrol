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
	// body cap). The dispatcher reads it together with each rule's
	// InspectsTruncatableFacet() to synthesize a fail-closed deny on
	// any rule whose CEL condition reads bytes that aren't there —
	// rules that don't read the truncated facet still fire on their
	// other predicates.
	Truncated bool

	// Unparseable is set by a wire frontend when its SQL parser
	// refuses the Query bytes outright (the statement is still on
	// Meta.Statement, but Verb / Tables / Functions are left zero
	// because the parser couldn't derive them). The dispatcher reads
	// it together with each rule's InspectsUnparseableFacet() to
	// synthesize a fail-closed deny on any rule whose CEL condition
	// references a parser-derived SQL facet that wasn't populated —
	// rules keyed only on connection-level facets (credential,
	// peer_ip) or on the raw statement still fire normally.
	//
	// Differs from Truncated in two ways: (a) the statement text
	// IS populated when Unparseable=true, so `sql.statement` rules
	// continue to evaluate honestly; (b) the trigger is parser
	// rejection, not byte-cap truncation, so wire frontends with
	// no parser leave it false.
	Unparseable bool

	// actMap is both the per-Request facet activation cache AND the
	// activation map facet.Compose hands to cel.Program.Eval. Each
	// facet's AddActivation hook stamps its (possibly expensive —
	// body_json parsing, header map copy) Fields value here the first
	// time it runs; subsequent rules in the same endpoint reuse the
	// cached value and skip the build path entirely. Keyed by CEL
	// variable name ("http", "k8s", "sql") so composed environments
	// (the k8s family layers http+k8s) cache each facet independently.
	//
	// Unifying the cache with the activation map (previously two
	// separate map[string]any per request — the cache plus a freshly
	// built act map per Match call) cuts one map allocation per rule
	// evaluated. For endpoints with many rules the savings dominate
	// the per-Match allocation profile; see
	// BenchmarkMatchRequestHTTPSSmallBody in
	// internal/config/runtime/dispatch_bench_test.go.
	//
	// Lazy-initialized via ActivationMap so a Request that never
	// matches still costs zero map allocations. Cleared by
	// ResetActivationCache for tests that reuse a Request snapshot
	// across mutations.
	actMap map[string]any
}

// ActivationMap returns the per-Request activation map, lazily
// initialised on first access. facet.Compose passes the returned map
// into cel.Program.Eval as the CEL activation, and each facet's
// AddActivation hook reads/writes it directly to memoise its
// activation value across the rules of one endpoint.
//
// Returns nil when r is nil so the gateway's early-validation paths
// (which sometimes hold a nil request) stay panic-free; the facet
// build closure interprets a nil result as "refuse to match".
func (r *Request) ActivationMap() map[string]any {
	if r == nil {
		return nil
	}
	if r.actMap == nil {
		r.actMap = make(map[string]any, 2)
	}
	return r.actMap
}

// CachedActivation returns the facet activation value the matching
// facet's AddActivation hook stamped on the activation map, or nil if
// none has been built yet. Facet hooks call it before doing any
// per-rule work so the expensive snapshot happens at most once per
// request. Kept as a method on Request for the same nil-receiver
// tolerance the gateway's early-validation paths rely on.
func (r *Request) CachedActivation(facet string) any {
	if r == nil || r.actMap == nil {
		return nil
	}
	return r.actMap[facet]
}

// SetCachedActivation memoises v as the activation value for facet.
// Subsequent calls to CachedActivation(facet) return v until the
// Request is discarded or ResetActivationCache is invoked. Writes go
// through ActivationMap so the lazy-init shape is consistent across
// callers; a nil receiver is a silent no-op.
func (r *Request) SetCachedActivation(facet string, v any) {
	if r == nil {
		return
	}
	if r.actMap == nil {
		r.actMap = make(map[string]any, 2)
	}
	r.actMap[facet] = v
}

// ResetActivationCache drops every cached facet activation on the
// Request. The dispatcher does not need to call it — a fresh Request
// has an empty cache, and the cache is short-lived for the lifetime
// of a single wire request. Tests that reuse a Request and mutate its
// body / meta between match invocations must call it after each
// mutation so the next match rebuilds activation values from the
// current state instead of returning the snapshot from a prior call.
func (r *Request) ResetActivationCache() {
	if r == nil {
		return
	}
	r.actMap = nil
}

// Matcher walks a Request and returns true when the rule's match
// predicate is satisfied. Implementations are family-specific and
// live in their facet plugin's package.
//
// InspectsTruncatableFacet reports whether the matcher's compiled
// condition reads any field of the request whose value could be
// truncated by a wire frontend's inspection buffer (HTTPS body /
// body_json, SQL verb / tables / functions / statement). The
// dispatcher gates on this together with Request.Truncated to fail
// closed on policy-bypass-by-truncation: a rule that asks about the
// body of a request whose body was capped is auto-denied; a rule
// that only reads the request method or credential is allowed to
// run its own Match against whatever bytes did fit.
type Matcher interface {
	Match(req *Request) bool
	InspectsTruncatableFacet() bool
	// InspectsUnparseableFacet reports whether the matcher's compiled
	// condition reads any field of the request whose value the
	// frontend's parser would leave zero on parse failure (SQL verb,
	// tables, functions). The dispatcher gates on this together with
	// Request.Unparseable to fail closed on policy-bypass-by-unparser:
	// a rule that asks about the verb of a query the parser rejected
	// is auto-denied; a rule that only reads the raw statement or
	// the credential is allowed to run its own Match.
	InspectsUnparseableFacet() bool
}

// PathOf returns the URL's path, or "" when u is nil. Common enough
// across facets to live here.
func PathOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Path
}
