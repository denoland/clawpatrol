// Package k8s is the Kubernetes protocol-family facet. It owns the
// k8s match-key set (resource/verb/namespace/name/params/credential),
// the matcher that walks a parsed Kubernetes API request, the Meta
// type derived from the request URL, the path parser that produces
// that Meta, and the per-family report fields the dashboard shows
// for a k8s call.
//
// Kubernetes traffic is HTTPS at the wire level, so the gateway's
// HTTPS handler populates match.Request.Method/URL/Headers before
// calling PrepareRequest. PrepareRequest then decomposes the URL
// path into (verb, resource, namespace, name, params) and stashes
// the result on req.Meta for the k8s matcher to read.
package k8s

import (
	"net/url"
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/plugins/rules"
)

// Meta is the (verb, resource, namespace, name, params) tuple
// derived from a Kubernetes API path. Empty fields when the request
// isn't k8s-shaped.
type Meta struct {
	Verb      string // get | list | watch | create | update | patch | delete
	Resource  string // "pods", "secrets", or "<resource>/<subresource>"
	Namespace string
	Name      string
	// Params carries flat string params from the URL query (e.g.
	// `stdin = "true"` for `kubectl exec --stdin`). One value per
	// key; multi-value query params collapse to the first.
	Params map[string]string
}

// Facet is the k8s facet Runtime.
type Facet struct{}

// Name reports the family identifier this facet handles.
func (Facet) Name() string { return "k8s" }

// RuleType reports the HCL rule label that targets this facet.
func (Facet) RuleType() string { return "k8s_rule" }

// EndpointFamilies enumerates endpoint families a k8s_rule may attach
// to.
func (Facet) EndpointFamilies() []string { return []string{"k8s"} }

// Transport reports the gateway-side dispatch handler this facet uses.
// Kubernetes traffic is HTTPS on the wire, so it shares the https-mitm
// path with the https facet.
func (Facet) Transport() string { return "https-mitm" }

// HITLQueryLabel is the dashboard / Slack label for a kubernetes
// request.
func (Facet) HITLQueryLabel() string { return "Resource" }

// HostIsResource reports that a k8s request's Host is typically the
// apiserver address (a VIP or IP), not a label the operator would
// recognise — the operator's endpoint name is more useful.
func (Facet) HostIsResource() bool { return false }

// MatchKeys lists every key allowed in a k8s_rule's match{} block.
func (Facet) MatchKeys() []facet.MatchKeySpec {
	return []facet.MatchKeySpec{
		{Name: "resource", Kind: facet.MatchGlobList},
		{Name: "verb", Kind: facet.MatchStringList},
		{Name: "namespace", Kind: facet.MatchGlobList},
		{Name: "name", Kind: facet.MatchGlobList},
		{Name: "params", Kind: facet.MatchStringMap},
		{Name: "credential", Kind: facet.MatchCredentialRef},
	}
}

// ReportFields declares the per-family columns the k8s facet emits.
func (Facet) ReportFields() []facet.ReportFieldSpec {
	return []facet.ReportFieldSpec{
		{Name: "verb", Kind: facet.ReportString, Label: "Verb"},
		{Name: "resource", Kind: facet.ReportString, Label: "Resource"},
		{Name: "namespace", Kind: facet.ReportString, Label: "Namespace"},
		{Name: "name", Kind: facet.ReportString, Label: "Name"},
		{Name: "params", Kind: facet.ReportStringMap, Label: "Params"},
	}
}

// PrepareRequest derives the k8s Meta from the request URL and method
// and stashes it on req.Meta. Called by the gateway before any
// matcher runs for a k8s-family request.
func (Facet) PrepareRequest(req *match.Request) {
	if req == nil || req.URL == nil {
		return
	}
	req.Meta = parsePath(req.Method, req.URL.RequestURI())
}

// Report extracts the k8s report fields from a request.
func (Facet) Report(req *match.Request) map[string]any {
	m, _ := req.Meta.(*Meta)
	if m == nil {
		return nil
	}
	return map[string]any{
		"verb":      m.Verb,
		"resource":  m.Resource,
		"namespace": m.Namespace,
		"name":      m.Name,
		"params":    m.Params,
	}
}

// NewMatcher compiles a k8s_rule match map into a Matcher.
func (Facet) NewMatcher(raw map[string]any) (match.Matcher, error) {
	m := &k8sMatcher{
		resource:   match.ParseGlobs(raw["resource"]),
		verb:       match.LowerAll(match.StringList(raw["verb"])),
		namespace:  match.ParseGlobs(raw["namespace"]),
		name:       match.ParseGlobs(raw["name"]),
		credential: match.StringValue(raw["credential"]),
	}
	if p, ok := raw["params"].(map[string]any); ok {
		m.params = map[string]string{}
		for k, v := range p {
			m.params[k] = match.StringValue(v)
		}
	}
	return m, nil
}

type k8sMatcher struct {
	resource   []match.Glob
	verb       []string
	namespace  []match.Glob
	name       []match.Glob
	params     map[string]string
	credential string
}

func (m *k8sMatcher) Match(req *match.Request) bool {
	meta, _ := req.Meta.(*Meta)
	if meta == nil {
		return false
	}
	if m.credential != "" && req.Credential != m.credential {
		return false
	}
	if len(m.resource) > 0 && !match.Any(m.resource, meta.Resource) {
		return false
	}
	if len(m.verb) > 0 {
		ok := false
		for _, v := range m.verb {
			if match.EqualsIgnoreCase(meta.Verb, v) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.namespace) > 0 && !match.Any(m.namespace, meta.Namespace) {
		return false
	}
	if len(m.name) > 0 && !match.Any(m.name, meta.Name) {
		return false
	}
	for k, want := range m.params {
		if meta.Params[k] != want {
			return false
		}
	}
	return true
}

// parsePath best-effort decomposes a Kubernetes API request into the
// (verb, resource, namespace, name, params) tuple the k8s matcher
// walks. Returns nil when the URL isn't k8s-shaped.
//
// Supported shapes:
//
//	/api/v1/<resource>                              → list
//	/api/v1/<resource>/<name>                       → get / update / patch / delete
//	/api/v1/namespaces/<ns>/<resource>              → list in ns
//	/api/v1/namespaces/<ns>/<resource>/<name>       → single resource
//	/api/v1/namespaces/<ns>/<resource>/<name>/<sub> → subresource (exec / portforward / etc.)
//	/apis/<group>/<v>/...                           → same shapes under named groups
//
// Verb derives from the HTTP method (GET → list/get/watch, POST →
// create, PUT → update, PATCH → patch, DELETE → delete). GET
// requests with watch=true are normalized to watch. kubectl uses
// POST to /api/v1/.../<name>/exec so the matcher relies on Resource
// ending in "/exec" rather than special-casing the verb.
func parsePath(method, rawURL string) *Meta {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return nil
	}
	switch parts[0] {
	case "api":
		parts = parts[2:]
	case "apis":
		if len(parts) < 3 {
			return nil
		}
		parts = parts[3:]
	default:
		return nil
	}
	if len(parts) == 0 {
		return nil
	}
	m := &Meta{}
	if parts[0] == "namespaces" && len(parts) >= 2 {
		m.Namespace = parts[1]
		parts = parts[2:]
	}
	if len(parts) == 0 {
		return m
	}
	m.Resource = parts[0]
	parts = parts[1:]
	if len(parts) > 0 {
		m.Name = parts[0]
		parts = parts[1:]
	}
	if len(parts) > 0 {
		m.Resource = m.Resource + "/" + parts[0]
	}
	switch strings.ToUpper(method) {
	case "GET":
		if m.Name == "" {
			m.Verb = "list"
		} else {
			m.Verb = "get"
		}
	case "POST":
		m.Verb = "create"
	case "PUT":
		m.Verb = "update"
	case "PATCH":
		m.Verb = "patch"
	case "DELETE":
		m.Verb = "delete"
	}
	if q := u.Query(); len(q) > 0 {
		m.Params = make(map[string]string, len(q))
		for k, v := range q {
			if len(v) > 0 {
				m.Params[k] = v[0]
			}
		}
	}
	if strings.EqualFold(method, "GET") && strings.EqualFold(m.Params["watch"], "true") {
		m.Verb = "watch"
	}
	return m
}

func init() {
	f := Facet{}
	facet.Register(f)
	config.Register(rules.PluginFor(f))
}
