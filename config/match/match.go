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
// stashes any derived per-family metadata on Metas — each entry's
// concrete type is owned by the facet plugin that registered the
// family name, and matchers type-assert inside their family's slot.
type Request struct {
	// Families lists every facet family that may match this request.
	// The first entry is the primary family (the wire protocol the
	// gateway dispatched against); subsequent entries are auxiliary
	// facets attached to the same action. A rule's matcher uses its
	// own family's slot in Metas and falls through cleanly when the
	// slot is absent.
	Families []string

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

	// Metas holds the per-family derived metadata keyed by family
	// name. The owning facet plugin sets the concrete type —
	// *sql.Meta under "sql", *k8s.Meta under "k8s", *llm.Meta under
	// "llm", and so on — either via facet.Runtime.PrepareRequest
	// (HTTPS-family handler) or directly from a wire-frame frontend
	// (postgres/clickhouse). Matchers type-assert against their own
	// family's slot and fall through to "no match" when the slot is
	// absent.
	Metas map[string]any

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

// PrimaryFamily returns the first family on the request, or "" when
// none has been set. The primary family is the wire protocol the
// gateway dispatched against; auxiliary facet families trail in
// Families[1:].
func (r *Request) PrimaryFamily() string {
	if r == nil || len(r.Families) == 0 {
		return ""
	}
	return r.Families[0]
}

// HasFamily reports whether the request carries the named family in
// any position. Matchers can use it to short-circuit before
// type-asserting against Metas.
func (r *Request) HasFamily(name string) bool {
	if r == nil {
		return false
	}
	for _, f := range r.Families {
		if f == name {
			return true
		}
	}
	return false
}

// Meta returns the per-family metadata slot for the named family, or
// nil when the request carries none. Use this from family matchers
// instead of poking req.Metas directly so a nil map and a missing
// key both fall through to "no match" cleanly.
func (r *Request) Meta(family string) any {
	if r == nil || r.Metas == nil {
		return nil
	}
	return r.Metas[family]
}

// SetMeta stashes per-family metadata for the named family. Allocates
// the map on first call so callers don't have to.
func (r *Request) SetMeta(family string, m any) {
	if r == nil {
		return
	}
	if r.Metas == nil {
		r.Metas = make(map[string]any, 2)
	}
	r.Metas[family] = m
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
}

// PathOf returns the URL's path, or "" when u is nil. Common enough
// across facets to live here.
func PathOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Path
}
