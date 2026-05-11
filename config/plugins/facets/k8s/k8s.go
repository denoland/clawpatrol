// Package k8s is the Kubernetes protocol-family facet. It owns the
// k8s CEL environment (resource / verb / namespace / name / params,
// exposed as fields on the `k8s` variable), the matcher that walks a
// parsed Kubernetes API request, the Meta type derived from the
// request URL, the path parser that produces that Meta, and the
// per-family report fields the dashboard shows for a k8s call.
//
// Kubernetes traffic is HTTPS at the wire level, so the gateway's
// HTTPS handler populates match.Request.Method/URL/Headers before
// calling PrepareRequest. PrepareRequest then decomposes the URL
// path into (verb, resource, namespace, name, params) and stashes
// the result on req.Meta for the k8s matcher to read.
package k8s

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
)

// K8sFields is the CEL-facing view of a kubernetes request. Exposed
// as the `k8s` variable in rule conditions (`k8s.verb`,
// `k8s.namespace`, etc.). Tag-driven field naming keeps the Go field
// names idiomatic while preserving the on-the-wire CEL names.
type K8sFields struct {
	Verb      string            `cel:"verb"`
	Resource  string            `cel:"resource"`
	Namespace string            `cel:"namespace"`
	Name      string            `cel:"name"`
	Params    map[string]string `cel:"params"`
}

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

// EndpointFamilies enumerates endpoint families a k8s rule may attach
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

// celEnv is the k8s CEL environment. Built once at init.
var celEnv *cel.Env

func init() {
	env, err := cel.NewEnv(
		ext.Sets(),
		ext.NativeTypes(
			reflect.TypeFor[K8sFields](),
			ext.ParseStructTags(true),
		),
		cel.Variable("k8s", cel.ObjectType("k8s.K8sFields")),
	)
	if err != nil {
		panic(fmt.Sprintf("k8s facet: cel env: %v", err))
	}
	celEnv = env

	facet.Register(Facet{})
}

// NewMatcher compiles a CEL condition into a Matcher. An empty
// condition is the catch-all match-everything case.
func (Facet) NewMatcher(condition string) (match.Matcher, error) {
	if condition == "" {
		return match.PassThrough{}, nil
	}
	return match.CompileCondition(celEnv, condition, buildActivation)
}

func buildActivation(req *match.Request) map[string]any {
	if req == nil {
		return nil
	}
	meta, _ := req.Meta.(*Meta)
	if meta == nil {
		return nil
	}
	params := meta.Params
	if params == nil {
		params = map[string]string{}
	}
	return map[string]any{
		"k8s": &K8sFields{
			Verb:      strings.ToLower(meta.Verb),
			Resource:  meta.Resource,
			Namespace: meta.Namespace,
			Name:      meta.Name,
			Params:    params,
		},
	}
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
// Non-resource URIs that kubectl / client-go probe reflexively
// before any resource call (`/api`, `/apis`, `/api/<v>`, `/apis/<g>`,
// `/apis/<g>/<v>`, `/healthz`, `/livez`, `/readyz`, `/version`,
// `/openapi/...`, `/metrics`) parse as `verb = "meta"` with empty
// resource. Configs allow them with `k8s.verb == "meta"` rather than
// folding them into `list` / `get`.
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
	if isMetaPath(strings.Trim(u.Path, "/")) {
		return &Meta{Verb: "meta"}
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

// isMetaPath reports whether p (URL path, leading/trailing slashes
// trimmed) targets a non-resource k8s URI — API discovery, health
// probes, version, OpenAPI schema, prometheus scrape. These are
// hit reflexively by kubectl / client-go before any resource call.
func isMetaPath(p string) bool {
	switch p {
	case "api", "apis", "healthz", "livez", "readyz", "version",
		"metrics", "openapi":
		return true
	}
	if strings.HasPrefix(p, "openapi/") {
		return true
	}
	// /api/<v> with nothing after.
	if rest, ok := strings.CutPrefix(p, "api/"); ok {
		return !strings.Contains(rest, "/")
	}
	// /apis/<g> or /apis/<g>/<v>, nothing after.
	if rest, ok := strings.CutPrefix(p, "apis/"); ok {
		return strings.Count(rest, "/") <= 1
	}
	return false
}
