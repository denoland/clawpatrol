// Package match holds the runtime types the request handler walks
// when dispatching against the compiled policy: a Request shape per
// protocol family and a Matcher interface implemented by per-family
// matchers (HTTPMatcher, SQLMatcher, K8sMatcher).
//
// Matchers are constructed at Compile time from a rule's match map
// and stored on each CompiledRule, so request-time dispatch is a
// straight Match(req) bool call with zero re-parsing. Glob patterns,
// negation (`!prefix`), and list-as-OR semantics live here.
package match

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Request is the family-tagged request snapshot passed to Matcher.Match.
// The handler populates whichever family-specific fields apply.
type Request struct {
	Family string // "https" | "sql" | "k8s"

	// Common
	Credential string // bare-name reference of the credential the
	// agent dispatched against, "" if none

	// HTTP / K8s
	Method  string
	URL     *url.URL
	Headers http.Header
	Body    []byte // populated when at least one rule needed it

	// K8s — derived from URL.Path at dispatch time
	K8s *K8sMeta

	// SQL — derived from the postgres / clickhouse wire frame
	SQL *SQLMeta
}

// K8sMeta is the (verb, resource, namespace, name) tuple derived from
// a Kubernetes API path. Empty fields when the request isn't k8s-shaped.
type K8sMeta struct {
	Verb      string // get | list | watch | create | update | patch | delete
	Resource  string // "pods", "secrets", or "<resource>/<subresource>"
	Namespace string
	Name      string
	// Params carries flat string params from the URL query (e.g.
	// `stdin = "true"` for `kubectl exec --stdin`). One value per
	// key; multi-value query params collapse to the first.
	Params map[string]string
}

// SQLMeta describes one parsed SQL statement. The pg / clickhouse
// front-ends populate it before walking the rule list.
type SQLMeta struct {
	Verb       string   // select | insert | update | delete | merge | ...
	Tables     []string // unqualified table names referenced
	Functions  []string // unqualified function names called
	Statement  string   // the raw text — exposed for `statement` /
	// `statement_regex` matchers
}

// Matcher walks a Request and returns true when the rule's match
// predicate is satisfied. Implementations are family-specific.
type Matcher interface {
	Match(req *Request) bool
}

// New compiles a rule's generic match map into a typed Matcher per
// family. An empty map matches every request (the v14 "default" rule
// pattern). Unknown keys are tolerated here — Validate has already
// rejected typos at load time.
func New(family string, raw map[string]any) (Matcher, error) {
	switch family {
	case "https":
		return newHTTP(raw)
	case "sql":
		return newSQL(raw)
	case "k8s":
		return newK8s(raw)
	}
	return nil, fmt.Errorf("unknown family %q", family)
}

// ── shared helpers ────────────────────────────────────────────────────

// stringList coerces a match-map value (either a single string or a
// list of strings) into []string. Returns nil if the value is missing
// or wrong-shaped.
func stringList(v any) []string {
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

// stringValue returns the string at key, or "" when absent / wrong shape.
func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// glob is one element of a list-of-globs match facet. Negative entries
// (originally prefixed with "!") match when the underlying glob does
// NOT match.
type glob struct {
	pattern string
	neg     bool
}

func parseGlobs(raw any) []glob {
	xs := stringList(raw)
	if xs == nil {
		return nil
	}
	out := make([]glob, len(xs))
	for i, s := range xs {
		neg := false
		if strings.HasPrefix(s, "!") {
			neg = true
			s = s[1:]
		}
		out[i] = glob{pattern: s, neg: neg}
	}
	return out
}

// matchAny returns true iff the candidate satisfies the list — list
// semantics are "any positive matches OR no positives AND no negatives
// match". Mixed lists compose: every "!" entry is checked
// (candidate must NOT match it); positive entries are OR'd.
//
// Examples:
//
//	["pods/exec", "pods/attach"]                   → in [...]
//	["!*/exec", "!*/attach", "!*/portforward"]     → not (any of those)
//	["foo", "!bar"]                                → matches foo AND not bar
func matchAny(globs []glob, candidate string) bool {
	if len(globs) == 0 {
		return true // no constraint
	}
	hasPositive := false
	positiveOK := false
	for _, g := range globs {
		ok := matchGlob(g.pattern, candidate)
		if g.neg {
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

// matchGlob is a thin wrapper around path.Match that also handles
// the empty-pattern edge case (matches anything).
func matchGlob(pattern, s string) bool {
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

// equalsIgnoreCase is for verbs and methods which are case-folded.
func equalsIgnoreCase(a, b string) bool {
	return strings.EqualFold(a, b)
}

// ── HTTP ──────────────────────────────────────────────────────────────

type httpMatcher struct {
	method       []string // case-insensitive verb list; empty = any
	path         []glob
	query        map[string][]string
	headers      map[string][]string
	bodyContains string
	bodyJSON     map[string]any
	credential   string
}

func newHTTP(raw map[string]any) (Matcher, error) {
	m := &httpMatcher{
		method:       stringList(raw["method"]),
		path:         parseGlobs(raw["path"]),
		bodyContains: stringValue(raw["body_contains"]),
		credential:   stringValue(raw["credential"]),
	}
	if q, ok := raw["query"].(map[string]any); ok {
		m.query = map[string][]string{}
		for k, v := range q {
			m.query[k] = stringList(v)
		}
	}
	if h, ok := raw["headers"].(map[string]any); ok {
		m.headers = map[string][]string{}
		for k, v := range h {
			m.headers[k] = stringList(v)
		}
	}
	if bj, ok := raw["body_json"].(map[string]any); ok {
		m.bodyJSON = bj
	}
	return m, nil
}

func (m *httpMatcher) Match(req *Request) bool {
	if m.credential != "" && req.Credential != m.credential {
		return false
	}
	if len(m.method) > 0 {
		ok := false
		for _, want := range m.method {
			if equalsIgnoreCase(req.Method, want) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.path) > 0 && !matchAny(m.path, pathOf(req.URL)) {
		return false
	}
	for k, wants := range m.query {
		got := req.URL.Query()[k]
		if !sliceOverlap(wants, got) {
			return false
		}
	}
	for k, wants := range m.headers {
		got := req.Headers.Values(k)
		if !sliceOverlap(wants, got) {
			return false
		}
	}
	if m.bodyContains != "" {
		if !strings.Contains(string(req.Body), m.bodyContains) {
			return false
		}
	}
	if len(m.bodyJSON) > 0 {
		// body_json is matched as a strict subset: every key/value
		// pair must be present in the request body. We rely on the
		// caller having set req.Body — bodyJSON in a rule means the
		// runtime must buffer the body.
		if !matchBodyJSON(req.Body, m.bodyJSON) {
			return false
		}
	}
	return true
}

func pathOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Path
}

// sliceOverlap returns true iff at least one entry in want is in got.
// Empty want is "no constraint" → true.
func sliceOverlap(want, got []string) bool {
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

// ── SQL ───────────────────────────────────────────────────────────────

type sqlMatcher struct {
	verb           []string
	tables         []glob
	function       []glob
	statement      string // glob pattern
	statementRegex *regexp.Regexp
	credential     string
}

func newSQL(raw map[string]any) (Matcher, error) {
	m := &sqlMatcher{
		verb:       lowerAll(stringList(raw["verb"])),
		tables:     parseGlobs(raw["tables"]),
		function:   parseGlobs(raw["function"]),
		statement:  stringValue(raw["statement"]),
		credential: stringValue(raw["credential"]),
	}
	if r := stringValue(raw["statement_regex"]); r != "" {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("statement_regex: %w", err)
		}
		m.statementRegex = re
	}
	return m, nil
}

func (m *sqlMatcher) Match(req *Request) bool {
	if req.SQL == nil {
		return false
	}
	if m.credential != "" && req.Credential != m.credential {
		return false
	}
	if len(m.verb) > 0 {
		ok := false
		for _, v := range m.verb {
			if equalsIgnoreCase(req.SQL.Verb, v) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.tables) > 0 {
		if !anyOfStrings(req.SQL.Tables, m.tables) {
			return false
		}
	}
	if len(m.function) > 0 {
		if !anyOfStrings(req.SQL.Functions, m.function) {
			return false
		}
	}
	if m.statement != "" && !matchGlob(m.statement, req.SQL.Statement) {
		return false
	}
	if m.statementRegex != nil && !m.statementRegex.MatchString(req.SQL.Statement) {
		return false
	}
	return true
}

// anyOfStrings: at least one candidate satisfies the glob list. Used
// for tables / functions where a SELECT can name several.
func anyOfStrings(candidates []string, globs []glob) bool {
	for _, c := range candidates {
		if matchAny(globs, c) {
			return true
		}
	}
	return false
}

func lowerAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, s := range xs {
		out[i] = strings.ToLower(s)
	}
	return out
}

// ── K8s ───────────────────────────────────────────────────────────────

type k8sMatcher struct {
	resource   []glob
	verb       []string
	namespace  []glob
	name       []glob
	params     map[string]string
	credential string
}

func newK8s(raw map[string]any) (Matcher, error) {
	m := &k8sMatcher{
		resource:   parseGlobs(raw["resource"]),
		verb:       lowerAll(stringList(raw["verb"])),
		namespace:  parseGlobs(raw["namespace"]),
		name:       parseGlobs(raw["name"]),
		credential: stringValue(raw["credential"]),
	}
	if p, ok := raw["params"].(map[string]any); ok {
		m.params = map[string]string{}
		for k, v := range p {
			m.params[k] = stringValue(v)
		}
	}
	return m, nil
}

func (m *k8sMatcher) Match(req *Request) bool {
	if req.K8s == nil {
		return false
	}
	if m.credential != "" && req.Credential != m.credential {
		return false
	}
	if len(m.resource) > 0 && !matchAny(m.resource, req.K8s.Resource) {
		return false
	}
	if len(m.verb) > 0 {
		ok := false
		for _, v := range m.verb {
			if equalsIgnoreCase(req.K8s.Verb, v) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.namespace) > 0 && !matchAny(m.namespace, req.K8s.Namespace) {
		return false
	}
	if len(m.name) > 0 && !matchAny(m.name, req.K8s.Name) {
		return false
	}
	for k, want := range m.params {
		if req.K8s.Params[k] != want {
			return false
		}
	}
	return true
}
