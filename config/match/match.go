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
}

// Matcher walks a Request and returns true when the rule's match
// predicate is satisfied. Implementations are family-specific and
// live in their facet plugin's package.
//
// InspectsTruncatableFacet reports whether the matcher's compiled
// condition reads any field of the request whose value could be
// truncated by a wire frontend's inspection buffer (HTTPS body /
// body_json, SQL verb / tables / function / statement). The
// dispatcher gates on this together with Request.Truncated to fail
// closed on policy-bypass-by-truncation: a rule that asks about the
// body of a request whose body was capped is auto-denied; a rule
// that only reads the request method or credential is allowed to
// run its own Match against whatever bytes did fit.
type Matcher interface {
	Match(req *Request) bool
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
