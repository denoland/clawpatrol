// Package https is the HTTPS protocol-family facet. It owns the
// HTTPS CEL environment (method / path / query / headers / body /
// body_json, exposed as fields on the `http` variable), the matcher
// that walks an HTTP-shaped match.Request, and the per-family report
// fields the dashboard renders for an HTTPS request.
//
// HTTPS leaves match.Request.Meta nil — every variable the matcher
// reads comes from the request snapshot the gateway already
// populates (Method, URL, Headers, Body). PrepareRequest is
// therefore a no-op.
package https

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
)

// Fields is the CEL-facing view of an HTTPS request. Exposed
// as the `http` variable in rule conditions (`http.method`,
// `http.path`, `http.body_json`, etc.). The facet name matches the
// CEL variable (`http`); the endpoint plugin keeps the HCL label
// `https` since that names the wire (TLS).
//
// BodyJSON is *structpb.Value rather than `any` because cel-go's
// NativeTypes converter drops interface-typed struct fields silently;
// google.protobuf.Value gives the field the dyn-shape the operator
// expects when writing `http.body_json.archived == true` style
// predicates.
type Fields struct {
	Method   string              `cel:"method"`
	Path     string              `cel:"path"`
	Query    map[string][]string `cel:"query"`
	Headers  map[string][]string `cel:"headers"`
	Body     string              `cel:"body"`
	BodyJSON *structpb.Value     `cel:"body_json"`
}

// Facet is the HTTPS facet Runtime. Singleton; held by the registry
// for the lifetime of the process.
type Facet struct{}

// Name reports the family identifier this facet handles.
func (Facet) Name() string { return "http" }

// EndpointFamilies enumerates endpoint families a rule of this facet
// may attach to.
func (Facet) EndpointFamilies() []string { return []string{"http"} }

// Transport reports the gateway-side dispatch handler this facet uses.
func (Facet) Transport() string { return "https-mitm" }

// HITLQueryLabel is the dashboard / Slack label for an HTTPS request.
func (Facet) HITLQueryLabel() string { return "Path" }

// HostIsResource reports that an HTTPS request's Host is already a
// meaningful resource label (api.anthropic.com, etc.).
func (Facet) HostIsResource() bool { return true }

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

func init() {
	facet.Register(Facet{})
}

// CELContrib declares the HTTPS facet's CEL contribution: the `http`
// variable backed by Fields, the activation builder that snapshots a
// request into one, and the path lists CompileCondition needs.
//
// lowercasedPaths: http.method's activation value is normalized to
// lowercase, so CompileCondition pre-lowercases the literal in `http
// .method == "POST"` at rule-load time. Other HTTPS fields stay
// case-sensitive (paths, headers, body bytes are operator-controlled).
//
// truncatablePaths: http.body and http.body_json come from the buffer
// the gateway capped at maxHTTPMatchBody (main.go); a rule that
// reads either on a request whose body overflowed can't be evaluated
// honestly, so the dispatcher synthesizes a deny. Fields whose value
// is body-independent (method, path, query, headers) are
// intentionally absent — `http.method == "GET"` still fires on its
// own predicate even when the body was capped. Because the k8s
// family composes the http facet alongside its own, a k8s_rule that
// references http.body also fail-closes on truncation; the
// truncatable-fields registry follows from the composition with no
// per-family plumbing.
func (Facet) CELContrib() facet.CELContrib {
	return facet.CELContrib{
		EnvOptions: []cel.EnvOption{
			ext.NativeTypes(
				reflect.TypeFor[Fields](),
				ext.ParseStructTags(true),
			),
			cel.Variable("http", cel.ObjectType("https.Fields")),
		},
		AddActivation:    addActivation,
		LowercasedPaths:  []string{"http.method"},
		TruncatablePaths: []string{"http.body", "http.body_json"},
		// HTTPS has no parser-failure mode: every field (method,
		// headers, body, body_json) is decoded directly from the wire,
		// not derived by a parser that could refuse the input.
		// UnparseablePaths stays nil so the dispatcher's Unparseable
		// gate is a no-op for HTTPS rules.
	}
}

// NewMatcher compiles a CEL condition into a Matcher. Delegates to
// the package-level composer so every facet the http family composes
// layers in (only the http facet itself today — the http family
// doesn't compose any other facet).
func (f Facet) NewMatcher(condition string) (match.Matcher, error) {
	m, _, err := facet.Compose(f.Name(), condition)
	return m, err
}

func addActivation(req *match.Request, act map[string]any) bool {
	if req == nil {
		return false
	}
	// Reuse the cached Fields when an earlier rule on this Request
	// already built one. act doubles as the per-Request activation
	// cache (see match.Request.ActivationMap), so the membership check
	// also lets the second-and-later rules of an endpoint skip the
	// whole body_json parse, header copy, and query parse path.
	if cached, ok := act["http"].(*Fields); ok && cached != nil {
		return true
	}
	// HTTP method is lowercased here (and declared in lowercasedPaths)
	// so rules can write either "POST" or "post" — CompileCondition
	// normalizes the want-side literals to lowercase at rule-load time.
	f := &Fields{
		Method:  strings.ToLower(req.Method),
		Path:    match.PathOf(req.URL),
		Headers: passthroughHeaders(req.Headers),
		Body:    string(req.Body),
	}
	// url.URL.Query() always allocates a fresh Values map, even when
	// the URL has no query string. Skip it on the empty case so the
	// common path (GET /resource, POST /resource with body-only) lands
	// the shared emptyValues map instead of paying for an idle
	// ParseQuery round-trip.
	if req.URL != nil && req.URL.RawQuery != "" {
		f.Query = req.URL.Query()
	}
	if f.Query == nil {
		f.Query = emptyValues
	}
	// body_json is parsed eagerly when the body looks like JSON. The
	// cost is bounded by request body size, which the gateway already
	// limits. Empty body / parse error → an empty struct value, so
	// `http.body_json.<field>` evaluates to null rather than blowing
	// up at request time.
	f.BodyJSON = parseBodyJSON(req.Body)
	act["http"] = f
	return true
}

// emptyBodyJSON is the shared fallback for empty / non-JSON / invalid
// bodies. Pre-built once so every GET (and every POST that fails to
// parse, and every request whose rules never reference body_json)
// reuses the same value instead of allocating a fresh empty Struct +
// Value wrapper per call. CEL treats the activation snapshot as
// read-only, so the singleton is safe to share across requests.
var emptyBodyJSON = structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{}})

// parseBodyJSON converts a raw request body into a *structpb.Value
// for the body_json field. JSON-shaped input lands as the matching
// structpb tree (objects → Struct, arrays → List, scalars → their
// natural type); non-JSON / empty input falls back to the cached empty
// struct so field accesses yield null.
//
// Implementation history: we tried a direct
// encoding/json.Decoder.Token() → *structpb.Value walker (skipping
// the intermediate map[string]any / []any tree). It was strictly
// worse — Decoder boxes every token into a fresh interface{} value
// (one alloc per scalar, plus a heap-resident Decoder state struct
// per call), while json.Unmarshal amortises those costs across the
// whole input. The bulk decode + NewValue conversion is the cheapest
// shape stdlib + structpb give us today.
func parseBodyJSON(body []byte) *structpb.Value {
	if len(body) == 0 {
		return emptyBodyJSON
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return emptyBodyJSON
	}
	v, err := structpb.NewValue(raw)
	if err != nil {
		return emptyBodyJSON
	}
	return v
}

// emptyValues is the shared empty map returned for the no-headers /
// no-query branches. CEL only reads from these maps, so a single
// pre-built read-only empty map is safe to share across requests —
// avoids one alloc per matcher build when the caller has no headers
// or no query string. Two activation fields (Headers, Query) both
// fall back to this same value.
var emptyValues = map[string][]string{}

// passthroughHeaders returns the request headers as the activation's
// map[string][]string view, falling back to the shared empty map
// when the request carries no headers so CEL key access never
// panics. CEL only reads from the map, so we can share the caller's
// storage without copying — saves an O(headers) allocation per match.
func passthroughHeaders(m map[string][]string) map[string][]string {
	if m == nil {
		return emptyValues
	}
	return m
}
