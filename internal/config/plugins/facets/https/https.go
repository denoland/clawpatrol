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
// the gateway capped at maxHTTPMatchBody (main.go). On a request
// whose body overflowed, both paths are marked CEL-unknown; a
// condition whose outcome depends on the capped bytes evaluates
// Unevaluable and the dispatcher synthesizes a deny. Fields whose
// value is body-independent (method, path, query, headers) are
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
		// UnparseablePaths stays nil so Request.Unparseable marks
		// nothing unknown for HTTPS rules.
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
	// HTTP method is lowercased here (and declared in lowercasedPaths)
	// so rules can write either "POST" or "post" — CompileCondition
	// normalizes the want-side literals to lowercase at rule-load time.
	f := &Fields{
		Method:  strings.ToLower(req.Method),
		Path:    match.PathOf(req.URL),
		Headers: mapToCEL(req.Headers),
		Body:    string(req.Body),
	}
	if req.URL != nil {
		f.Query = mapToCEL(req.URL.Query())
	} else {
		f.Query = map[string][]string{}
	}
	// body_json is parsed eagerly when the body looks like JSON. The
	// cost is bounded by request body size, which the gateway already
	// limits. Empty body / parse error → an empty struct value.
	// NOTE: selecting a field the payload doesn't carry is a CEL
	// eval error, and eval errors fail closed (Unevaluable → deny).
	// Rules over optional fields must guard with has():
	// `has(http.body_json.archived) && http.body_json.archived == true`.
	f.BodyJSON = parseBodyJSON(req.Body)
	act["http"] = f
	return true
}

// parseBodyJSON converts a raw request body into a *structpb.Value
// for the body_json field. JSON-shaped input lands as the matching
// structpb tree (objects → Struct, arrays → List, scalars → their
// natural type); non-JSON / empty input falls back to an empty
// struct. Selecting a missing field off the struct is a CEL eval
// error — fail-closed per the strict Unevaluable contract — so
// conditions over optional fields need a has() guard.
func parseBodyJSON(body []byte) *structpb.Value {
	empty := structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{}})
	if len(body) == 0 {
		return empty
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return empty
	}
	v, err := structpb.NewValue(raw)
	if err != nil {
		return empty
	}
	return v
}

// mapToCEL converts a net/http map-of-string-list to a plain
// map[string][]string with empty defaults so CEL key access never
// panics.
func mapToCEL(m map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
