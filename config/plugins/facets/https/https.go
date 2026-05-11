// Package https is the HTTPS protocol-family facet. It owns the
// HTTPS match-key set (method/path/query/headers/body_json/
// body_contains/credential), the matcher that walks an HTTP-shaped
// match.Request, and the per-family report fields the dashboard
// renders for an HTTPS request.
//
// HTTPS leaves match.Request.Meta nil — every key the matcher reads
// comes from the request snapshot the gateway already populates
// (Method, URL, Headers, Body). PrepareRequest is therefore a no-op.
package https

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/plugins/rules"
)

// Facet is the HTTPS facet Runtime. Singleton; held by the registry
// for the lifetime of the process.
type Facet struct{}

// Name reports the family identifier this facet handles.
func (Facet) Name() string { return "https" }

// RuleType reports the HCL rule label that targets this facet.
func (Facet) RuleType() string { return "http_rule" }

// EndpointFamilies enumerates endpoint families a rule of this facet
// may attach to. Kubernetes endpoints are also `https`-family because
// the kubernetes API is HTTPS-shaped; they get their k8s-specific
// matchers through k8s_rule, not through http_rule.
func (Facet) EndpointFamilies() []string { return []string{"https"} }

// Transport reports the gateway-side dispatch handler this facet uses.
func (Facet) Transport() string { return "https-mitm" }

// HITLQueryLabel is the dashboard / Slack label for an HTTPS request.
func (Facet) HITLQueryLabel() string { return "Path" }

// HostIsResource reports that an HTTPS request's Host is already a
// meaningful resource label (api.anthropic.com, etc.).
func (Facet) HostIsResource() bool { return true }

// MatchKeys lists every key allowed in an http_rule's match{} block.
func (Facet) MatchKeys() []facet.MatchKeySpec {
	return []facet.MatchKeySpec{
		{Name: "method", Kind: facet.MatchStringList},
		{Name: "path", Kind: facet.MatchGlobList},
		{Name: "query", Kind: facet.MatchStringMap},
		{Name: "headers", Kind: facet.MatchStringMap},
		{Name: "body_json", Kind: facet.MatchObject},
		{Name: "body_contains", Kind: facet.MatchString},
		{Name: "credential", Kind: facet.MatchCredentialRef},
	}
}

// ReportFields declares the per-family columns the HTTPS facet
// emits onto an event for logging and dashboard rendering.
func (Facet) ReportFields() []facet.ReportFieldSpec {
	return []facet.ReportFieldSpec{
		{Name: "method", Kind: facet.ReportString, Label: "Method"},
		{Name: "path", Kind: facet.ReportString, Label: "Path"},
		{Name: "status", Kind: facet.ReportInt, Label: "Status"},
	}
}

// PrepareRequest is a no-op for HTTPS — the matcher reads directly
// from the request snapshot the gateway already populates.
func (Facet) PrepareRequest(*match.Request) {}

// Report extracts the HTTPS report fields from a request. Status
// isn't known until the response writes; the gateway fills it in
// after Report runs.
func (Facet) Report(req *match.Request) map[string]any {
	if req == nil {
		return nil
	}
	return map[string]any{
		"method": req.Method,
		"path":   match.PathOf(req.URL),
	}
}

// NewMatcher compiles an http_rule match map into a Matcher. The
// shape mirrors what config/match's old newHTTP produced; the
// only change is that the source code lives in the facet package
// that owns the HTTPS family.
func (Facet) NewMatcher(raw map[string]any) (match.Matcher, error) {
	m := &httpMatcher{
		method:       match.StringList(raw["method"]),
		path:         match.ParseGlobs(raw["path"]),
		bodyContains: match.StringValue(raw["body_contains"]),
		credential:   match.StringValue(raw["credential"]),
	}
	if q, ok := raw["query"].(map[string]any); ok {
		m.query = map[string][]string{}
		for k, v := range q {
			m.query[k] = match.StringList(v)
		}
	}
	if h, ok := raw["headers"].(map[string]any); ok {
		m.headers = map[string][]string{}
		for k, v := range h {
			m.headers[k] = match.StringList(v)
		}
	}
	if bj, ok := raw["body_json"].(map[string]any); ok {
		m.bodyJSON = bj
	}
	return m, nil
}

// httpMatcher is the compiled HTTPS predicate. Identical semantics
// to the pre-facet config/match implementation.
type httpMatcher struct {
	method       []string // case-insensitive verb list; empty = any
	path         []match.Glob
	query        map[string][]string
	headers      map[string][]string
	bodyContains string
	bodyJSON     map[string]any
	credential   string
}

func (m *httpMatcher) Match(req *match.Request) bool {
	if m.credential != "" && req.Credential != m.credential {
		return false
	}
	if len(m.method) > 0 {
		ok := false
		for _, want := range m.method {
			if match.EqualsIgnoreCase(req.Method, want) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.path) > 0 && !match.Any(m.path, match.PathOf(req.URL)) {
		return false
	}
	for k, wants := range m.query {
		got := queryValues(req.URL, k)
		if !match.SliceOverlap(wants, got) {
			return false
		}
	}
	for k, wants := range m.headers {
		got := headerValues(req.Headers, k)
		if !match.SliceOverlap(wants, got) {
			return false
		}
	}
	if m.bodyContains != "" {
		if !containsBody(req.Body, m.bodyContains) {
			return false
		}
	}
	if len(m.bodyJSON) > 0 {
		// body_json is matched as a strict subset: every key/value
		// pair must be present in the request body. We rely on the
		// caller having set req.Body — bodyJSON in a rule means the
		// runtime must buffer the body.
		if !match.BodyJSON(req.Body, m.bodyJSON) {
			return false
		}
	}
	return true
}

func queryValues(u *url.URL, key string) []string {
	if u == nil {
		return nil
	}
	return u.Query()[key]
}

func headerValues(h http.Header, key string) []string {
	if h == nil {
		return nil
	}
	return h.Values(key)
}

func containsBody(body []byte, needle string) bool {
	return strings.Contains(string(body), needle)
}

func init() {
	f := Facet{}
	facet.Register(f)
	config.Register(rules.PluginFor(f))
}
