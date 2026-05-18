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
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
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

// celEnv is the HTTPS CEL environment. Built once at init.
var celEnv *cel.Env

func init() {
	env, err := cel.NewEnv(
		ext.Sets(),
		ext.NativeTypes(
			reflect.TypeFor[Fields](),
			ext.ParseStructTags(true),
		),
		cel.Variable("http", cel.ObjectType("https.Fields")),
	)
	if err != nil {
		panic(fmt.Sprintf("https facet: cel env: %v", err))
	}
	celEnv = env

	facet.Register(Facet{})
}

// lowercasedPaths declares the HTTPS fields whose activation values
// are always lowercase. CompileCondition uses this to normalize the
// matching string literals in the rule source at compile time, so
// `http.method == "POST"` matches a POST request even though the
// activation reports `method = "post"`.
var lowercasedPaths = []string{"http.method"}

// truncatablePaths declares the HTTPS fields whose activation values
// come from the request body the gateway buffered against its
// inspection cap (maxHTTPMatchBody in main.go). A condition that
// reads either field on a request whose body overflowed the cap can
// no longer be evaluated faithfully — the dispatcher synthesizes a
// deny instead of letting the matcher see a truncated prefix.
//
// Fields whose value is independent of the body (method, path,
// query, headers) are intentionally absent: a rule like
// `http.method == "GET"` still fires on its own predicate even when
// the body was capped.
var truncatablePaths = []string{"http.body", "http.body_json"}

// NewMatcher compiles a CEL condition into a Matcher. An empty
// condition is the catch-all match-everything case.
func (Facet) NewMatcher(condition string) (match.Matcher, error) {
	if condition == "" {
		return match.PassThrough{}, nil
	}
	// HTTPS has no parser-failure mode: every facet (method, headers,
	// body, body_json) is decoded directly from the wire, not derived
	// by a parser that could refuse the input. Pass nil for
	// unparseablePaths so the dispatcher's Unparseable gate is a no-op
	// for HTTPS rules.
	return match.CompileCondition(celEnv, condition, buildActivation, lowercasedPaths, truncatablePaths, nil)
}

func buildActivation(req *match.Request) map[string]any {
	if req == nil {
		return nil
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
	// limits. Empty body / parse error → an empty struct value, so
	// `http.body_json.<field>` evaluates to null rather than blowing
	// up at request time.
	f.BodyJSON = parseBodyJSON(req.Body)
	return map[string]any{"http": f}
}

// parseBodyJSON converts a raw request body into a *structpb.Value
// for the body_json field. JSON-shaped input lands as the matching
// structpb tree (objects → Struct, arrays → List, scalars → their
// natural type); non-JSON / empty input falls back to an empty
// struct so field accesses yield null.
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
