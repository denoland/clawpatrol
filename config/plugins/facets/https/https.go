// Package https is the HTTPS protocol-family facet. It owns the
// HTTPS CEL environment (method / path / query / headers / body /
// body_json), the matcher that walks an HTTP-shaped match.Request,
// and the per-family report fields the dashboard renders for an
// HTTPS request.
//
// HTTPS leaves match.Request.Meta nil — every variable the matcher
// reads comes from the request snapshot the gateway already
// populates (Method, URL, Headers, Body). PrepareRequest is
// therefore a no-op.
package https

import (
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"

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
		cel.Variable("method", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("query", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("headers", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("body", cel.StringType),
		cel.Variable("body_json", cel.DynType),
	)
	if err != nil {
		panic(fmt.Sprintf("https facet: cel env: %v", err))
	}
	celEnv = env

	f := Facet{}
	facet.Register(f)
	config.Register(rules.PluginFor(f))
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
	act := map[string]any{
		"method": req.Method,
		"path":   match.PathOf(req.URL),
	}
	if req.URL != nil {
		act["query"] = mapToCEL(req.URL.Query())
	} else {
		act["query"] = map[string][]string{}
	}
	act["headers"] = mapToCEL(req.Headers)
	act["body"] = string(req.Body)
	// body_json is parsed lazily; provide a deferred value via
	// a thunk-shaped wrapper. CEL doesn't support lazy bindings
	// directly, so we parse upfront only when the body looks like
	// JSON. The cost is bounded by request body size, which the
	// gateway already limits.
	if len(req.Body) > 0 {
		var v any
		if err := json.Unmarshal(req.Body, &v); err == nil {
			act["body_json"] = v
		} else {
			act["body_json"] = map[string]any{}
		}
	} else {
		act["body_json"] = map[string]any{}
	}
	return act
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
