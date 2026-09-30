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
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"

	// Composed facet: the k8s family adds both the http and k8s
	// facets to its actions (a kubernetes API call is an HTTPS
	// request underneath, so it carries http.* bindings alongside
	// its native k8s.* fields), and facet.Compose pulls in the http
	// facet's CELContrib when building a k8s rule's env.
	// Blank-importing https here guarantees its init() (which calls
	// facet.Register) has run before the first k8s rule compiles —
	// otherwise direct k8s-package imports (tests, downstream code)
	// silently produce a nil matcher.
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/https"
)

// Fields is the CEL-facing view of a kubernetes request. Exposed
// as the `k8s` variable in rule conditions (`k8s.verb`,
// `k8s.namespace`, etc.). Tag-driven field naming keeps the Go field
// names idiomatic while preserving the on-the-wire CEL names.
type Fields struct {
	Verb      string            `cel:"verb"`
	Resource  string            `cel:"resource"`
	Namespace string            `cel:"namespace"`
	Name      string            `cel:"name"`
	Params    map[string]string `cel:"params"`
}

// Meta is the (verb, resource, namespace, name, params) tuple
// derived from a Kubernetes API path. A request whose path shape the
// parser can't decompose has no Meta at all (parsePath returns nil),
// which fails the match closed — see parsePath.
type Meta struct {
	// Verb is one of get | list | watch | create | update | patch |
	// delete | proxy | meta. `proxy` and `watch` can come from a
	// path-prefix segment; every other resource verb is derived from
	// the HTTP method.
	Verb      string
	Resource  string // "pods", "secrets", or "<resource>/<subresource>"
	Namespace string
	Name      string
	// Params carries flat string params from the URL query (e.g.
	// `stdin = "true"` for `kubectl exec --stdin`). One value per
	// key; multi-value query params collapse to the first. The params
	// the apiserver reads as booleans carry a canonical "true" /
	// "false" (see normalizeBoolParams); every other param is the
	// bytes that arrived.
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

func init() {
	facet.Register(Facet{})
}

// CELContrib declares the k8s facet's CEL contribution: the `k8s`
// variable backed by Fields, the activation builder that snapshots
// the parsed Meta into one, and the lowercased-paths list for k8s
// .verb.
//
// k8s Meta is derived entirely from the request URL + method, not
// from buffered request bytes, so no k8s.* field is truncatable.
// Body-affected fields the k8s rule can reach travel through the
// http facet the k8s family composes alongside its own — http.body
// and http.body_json fail-close on truncation for k8s rules too,
// without any per-facet plumbing here.
func (Facet) CELContrib() facet.CELContrib {
	return facet.CELContrib{
		EnvOptions: []cel.EnvOption{
			ext.NativeTypes(
				reflect.TypeFor[Fields](),
				ext.ParseStructTags(true),
			),
			cel.Variable("k8s", cel.ObjectType("k8s.Fields")),
		},
		AddActivation:   addActivation,
		LowercasedPaths: []string{"k8s.verb"},
		// k8s has no parser; Request.Unparseable marks nothing
		// unknown for k8s rules. UnparseablePaths stays nil so no
		// k8s.* field is poisoned on an unparseable request. Composed
		// http.* fields keep their own truncation contract through the
		// http facet's TruncatablePaths.
	}
}

// NewMatcher compiles a CEL condition into a Matcher. Delegates to
// the package-level composer so every facet the k8s family composes
// layers in — a k8s_rule can reference http.method etc. in addition
// to k8s.verb because the k8s family adds the http facet alongside
// its own.
func (f Facet) NewMatcher(condition string) (match.Matcher, error) {
	m, _, err := facet.Compose(f.Name(), condition)
	return m, err
}

func addActivation(req *match.Request, act map[string]any) bool {
	if req == nil {
		return false
	}
	meta, _ := req.Meta.(*Meta)
	if meta == nil {
		return false
	}
	params := meta.Params
	if params == nil {
		params = map[string]string{}
	}
	act["k8s"] = &Fields{
		Verb:      strings.ToLower(meta.Verb),
		Resource:  meta.Resource,
		Namespace: meta.Namespace,
		Name:      meta.Name,
		Params:    params,
	}
	return true
}

// specialVerbs are the verbs kube-apiserver takes from a path-prefix
// segment instead of from the HTTP method, mirroring its
// RequestInfoFactory. The segment names the verb and is not part of
// the resource path: `/api/v1/watch/namespaces/<ns>/secrets` is a
// watch of secrets, and `/api/v1/proxy/nodes/<node>/<path>` proxies
// an arbitrary HTTP request at the node's kubelet.
var specialVerbs = map[string]bool{"watch": true, "proxy": true}

// specialVerbsNoSubresources lists the special verbs whose trailing
// path segments are the proxied request's own path rather than a
// subresource of the addressed object.
var specialVerbsNoSubresources = map[string]bool{"proxy": true}

// namespaceSubresources are the segments that can follow a namespace
// name while still addressing the namespace object itself, so the
// segment after them is not a resource inside the namespace.
var namespaceSubresources = map[string]bool{"status": true, "finalize": true}

// parsePath decomposes a Kubernetes API request into the (verb,
// resource, namespace, name, params) tuple the k8s matcher walks.
//
// Supported shapes:
//
//	/api/v1/<resource>                              → list
//	/api/v1/<resource>/<name>                       → get / update / patch / delete
//	/api/v1/namespaces/<ns>/<resource>              → list in ns
//	/api/v1/namespaces/<ns>/<resource>/<name>       → single resource
//	/api/v1/namespaces/<ns>/<resource>/<name>/<sub> → subresource (exec / portforward / etc.)
//	/api/v1/<special verb>/...                      → same shapes, verb from the path
//	/apis/<group>/<v>/...                           → same shapes under named groups
//
// Non-resource URIs that kubectl / client-go probe reflexively
// before any resource call (`/api`, `/apis`, `/api/<v>`, `/apis/<g>`,
// `/apis/<g>/<v>`, `/healthz`, `/livez`, `/readyz`, `/version`,
// `/openapi/...`, `/metrics`) parse as `verb = "meta"` with empty
// resource. Configs allow them with `k8s.verb == "meta"` rather than
// folding them into `list` / `get`.
//
// Verb comes from the path when the first segment after the API
// group is one of specialVerbs, and otherwise from the HTTP method
// (GET/HEAD → list/get/watch, POST → create, PUT → update, PATCH →
// patch, DELETE → delete). A read carrying a true `watch` param is a
// watch. kubectl uses POST to /api/v1/.../<name>/exec so the matcher
// relies on Resource ending in "/exec" rather than special-casing the
// verb. A nameless DELETE keeps the verb `delete` (the apiserver
// reports it as `deletecollection`) so one `verb == 'delete'` rule
// covers the single-object and whole-collection forms alike.
//
// Returns nil for anything it cannot decompose into that tuple: a
// path that isn't k8s-shaped, a path-prefix verb addressing nothing,
// or a method the apiserver derives no verb from. nil is the refusal
// the rest of the facet is built on — addActivation declines to build
// an activation without a Meta, so every k8s rule evaluates
// Unevaluable and the dispatcher synthesizes a deny. Populating the
// tuple with a guess instead would be worse than refusing: wrong-but-
// present facts evaluate cleanly to false, a deny keyed on them
// misses, and rules are first-match-wins with no deny precedence, so
// nothing downstream catches the request.
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
	if specialVerbs[parts[0]] {
		// The apiserver rejects a bare path-prefix verb with nothing
		// to address ("unable to determine kind and namespace").
		if len(parts) < 2 {
			return nil
		}
		m.Verb = parts[0]
		parts = parts[1:]
	}
	if parts[0] == "namespaces" && len(parts) > 1 {
		m.Namespace = parts[1]
		// A further segment addresses a resource inside the namespace
		// unless it is one of the namespace object's own
		// subresources, in which case the request still targets the
		// namespace itself.
		if len(parts) > 2 && !namespaceSubresources[parts[2]] {
			parts = parts[2:]
		}
	}
	if parts[0] == "" {
		// An empty segment means this isn't the path the apiserver's
		// own splitter will route; refuse rather than emit a resource
		// we're not sure of.
		return nil
	}
	m.Resource = parts[0]
	if len(parts) > 1 {
		m.Name = parts[1]
	}
	if len(parts) > 2 && !specialVerbsNoSubresources[m.Verb] {
		m.Resource = m.Resource + "/" + parts[2]
	}
	if m.Verb == "" {
		verb, ok := verbFromMethod(method, m.Name)
		if !ok {
			return nil
		}
		m.Verb = verb
	}
	if q := u.Query(); len(q) > 0 {
		m.Params = make(map[string]string, len(q))
		for k, v := range q {
			if len(v) > 0 {
				m.Params[k] = v[0]
			}
		}
		normalizeBoolParams(m.Params)
	}
	if v, ok := m.Params["watch"]; ok && apiserverBool(v) &&
		(m.Verb == "get" || m.Verb == "list") {
		m.Verb = "watch"
	}
	return m
}

// verbFromMethod maps an HTTP method to the resource verb
// kube-apiserver derives from it. A GET or HEAD without a name reads
// a whole collection, which the apiserver reports as `list`. ok is
// false for a method that yields no resource verb — parsePath refuses
// such a request rather than handing the matcher a verb-less tuple.
func verbFromMethod(method, name string) (string, bool) {
	switch strings.ToUpper(method) {
	case "GET", "HEAD":
		if name == "" {
			return "list", true
		}
		return "get", true
	case "POST":
		return "create", true
	case "PUT":
		return "update", true
	case "PATCH":
		return "patch", true
	case "DELETE":
		return "delete", true
	}
	return "", false
}

// boolParams are the query params kube-apiserver decodes into a bool
// field of a request-options struct (ListOptions, DeleteOptions,
// PatchOptions, PodExecOptions / PodAttachOptions, PodLogOptions).
// Their values are canonicalised; see normalizeBoolParams.
var boolParams = map[string]bool{
	// ListOptions / WatchOptions.
	"watch":               true,
	"allowWatchBookmarks": true,
	"sendInitialEvents":   true,
	// DeleteOptions.
	"orphanDependents": true,
	"ignoreStoreReadErrorWithClusterBreakingPotential": true,
	// PatchOptions / CreateOptions / UpdateOptions.
	"force": true,
	// PodExecOptions / PodAttachOptions.
	"stdin":  true,
	"stdout": true,
	"stderr": true,
	"tty":    true,
	// PodLogOptions.
	"follow":                       true,
	"previous":                     true,
	"timestamps":                   true,
	"insecureSkipTLSVerifyBackend": true,
}

// normalizeBoolParams rewrites every boolParams entry in p to the
// canonical "true" / "false" the apiserver will act on, so a rule can
// be written against one spelling and still see the request the
// apiserver sees. A param the apiserver reads as something other than
// a bool (`limit=1`, `container=app`, `dryRun=All`) keeps the bytes
// that arrived — canonicalising those would corrupt them.
func normalizeBoolParams(p map[string]string) {
	for k, v := range p {
		if boolParams[k] {
			p[k] = strconv.FormatBool(apiserverBool(v))
		}
	}
}

// apiserverBool reports how kube-apiserver reads a boolean query
// param value. Its url.Values decoder
// (runtime.Convert_Slice_string_To_bool) resolves exactly "0" and a
// case-insensitive "false" to false, and every other value that is
// present to true — "1", "t", "TRUE", "yes", "off", and the empty
// value of a bare `?watch`. Reading only the literal "true" as true
// would leave `?watch=1` parsed as a plain list, streaming a watch
// past a rule that bans one.
func apiserverBool(v string) bool {
	return v != "0" && !strings.EqualFold(v, "false")
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
