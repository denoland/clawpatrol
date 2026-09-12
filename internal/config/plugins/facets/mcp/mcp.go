// Package mcp is the Model Context Protocol facet. It owns the mcp CEL
// environment (kind / method / tool_name / resource_uri / session_id /
// protocol_version, exposed as fields on the `mcp` variable), the
// matcher that walks an MCP-over-HTTP request, the Meta type derived
// from the request, and the per-family report fields the dashboard
// shows for an MCP call.
//
// Remote MCP traffic is HTTPS at the wire level, so the gateway's
// HTTPS handler populates match.Request.Method/URL/Headers/Body before
// calling PrepareRequest. PrepareRequest then classifies the request
// (rpc / listen / terminate / other) from the request line and
// headers, parses a single JSON-RPC object out of an rpc POST body,
// and stashes the result on req.Meta for the mcp matcher to read.
//
// The mcp family composes the http facet alongside its own (a remote
// MCP call is an HTTPS request underneath, so it carries http.method /
// http.path / http.headers / http.body / http.body_json), so a rule of
// family mcp can read both mcp.* and http.* fields.
package mcp

import (
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"

	// Composed facet: the mcp family adds both the http and mcp facets
	// to its actions. Blank-importing https here guarantees its init()
	// (facet.Register) has run before the first mcp rule compiles —
	// otherwise direct mcp-package imports (tests, downstream code)
	// silently produce a nil matcher.
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/https"
)

// Request-classification kinds. Derived purely from the request line
// and headers, so they are always evaluable — never poisoned by body
// truncation.
const (
	// KindRPC is a JSON-RPC request: a POST carrying a JSON body.
	KindRPC = "rpc"
	// KindListen is the Streamable HTTP / SSE server-push channel: a
	// GET asking for an event stream.
	KindListen = "listen"
	// KindTerminate is a Streamable HTTP session teardown: a DELETE
	// carrying an Mcp-Session-Id header.
	KindTerminate = "terminate"
	// KindOther is anything else on an MCP endpoint.
	KindOther = "other"
)

// Fields is the CEL-facing view of an MCP request. Exposed as the
// `mcp` variable in rule conditions (`mcp.kind`, `mcp.method`,
// `mcp.tool_name`, etc.).
//
// kind / protocol_version / session_id are request-line/header
// derived and therefore always evaluable. method / id / tool_name /
// resource_uri / prompt_name / is_notification are body-derived and
// fail closed on a truncated / unparseable / batched body (see
// CELContrib and PrepareRequest).
type Fields struct {
	Kind            string `cel:"kind"`
	ProtocolVersion string `cel:"protocol_version"`
	SessionID       string `cel:"session_id"`
	Method          string `cel:"method"`
	ID              string `cel:"id"`
	ToolName        string `cel:"tool_name"`
	ResourceURI     string `cel:"resource_uri"`
	PromptName      string `cel:"prompt_name"`
	IsNotification  bool   `cel:"is_notification"`
}

// Meta is the per-request MCP metadata PrepareRequest derives from the
// request line, headers, and (for rpc POSTs) the JSON-RPC body.
type Meta struct {
	Kind            string
	ProtocolVersion string
	SessionID       string
	Method          string
	ID              string
	ToolName        string
	ResourceURI     string
	PromptName      string
	IsNotification  bool

	// ProtocolInvalid marks an rpc POST whose body could not be parsed
	// into a single well-formed JSON-RPC object — malformed JSON, a
	// JSON-RPC batch array, or a body truncated at the inspection
	// buffer. The dispatcher denies such an action before any allow
	// rule can match (fail closed); see PrepareRequest and the
	// gateway's protocol-invalid gate.
	ProtocolInvalid bool
	// ProtocolInvalidReason is a short, agent-safe cause for a
	// ProtocolInvalid request, surfaced as the deny event's reason
	// (e.g. "mcp_protocol_invalid: JSON-RPC batch arrays are not
	// supported"). Empty when ProtocolInvalid is false.
	ProtocolInvalidReason string
}

// Facet is the MCP facet Runtime. Singleton; held by the registry for
// the lifetime of the process.
type Facet struct{}

// Name reports the family identifier this facet handles.
func (Facet) Name() string { return "mcp" }

// EndpointFamilies enumerates endpoint families an mcp rule may attach
// to.
func (Facet) EndpointFamilies() []string { return []string{"mcp"} }

// Transport reports the gateway-side dispatch handler this facet uses.
// Remote MCP traffic is HTTPS on the wire, so it shares the https-mitm
// path with the https and k8s facets.
func (Facet) Transport() string { return "https-mitm" }

// HITLQueryLabel is the dashboard / Slack label for an MCP request.
func (Facet) HITLQueryLabel() string { return "Method" }

// HostIsResource reports that a remote MCP request's Host is already a
// meaningful resource label (mcp.notion.com, api.grain.com, etc.).
func (Facet) HostIsResource() bool { return true }

// ReportFields declares the per-family columns the MCP facet emits.
func (Facet) ReportFields() []facet.ReportFieldSpec {
	return []facet.ReportFieldSpec{
		{Name: "kind", Kind: facet.ReportString, Label: "Kind"},
		{Name: "method", Kind: facet.ReportString, Label: "Method"},
		{Name: "tool_name", Kind: facet.ReportString, Label: "Tool"},
		{Name: "resource_uri", Kind: facet.ReportString, Label: "Resource URI"},
		{Name: "session_id", Kind: facet.ReportString, Label: "Session"},
	}
}

// PrepareRequest classifies the MCP request and (for rpc POSTs) parses
// a single JSON-RPC object out of the buffered body, stashing the
// result on req.Meta. Called by the gateway before any matcher runs
// for an mcp-family request.
func (Facet) PrepareRequest(req *match.Request) {
	if req == nil {
		return
	}
	m := &Meta{
		Kind:            classifyKind(req),
		ProtocolVersion: header(req, "MCP-Protocol-Version"),
		SessionID:       header(req, "Mcp-Session-Id"),
	}
	if m.Kind == KindRPC {
		parseRPCBody(req, m)
	}
	req.Meta = m
	// Propagate the MCP-specific protocol-invalid signal to the shared
	// request flag the dispatcher reads. This is the fail-closed
	// boundary: it denies the whole action before any allow rule (a
	// catch-all, http.method, or mcp.kind allow) can match — stronger
	// than the per-path req.Truncated / req.Unparseable poisoning
	// parseRPCBody also sets for diagnostics.
	if m.ProtocolInvalid {
		req.ProtocolInvalid = true
		req.ProtocolInvalidReason = m.ProtocolInvalidReason
	}
}

// Report extracts the MCP report fields from a request.
func (Facet) Report(req *match.Request) map[string]any {
	m, _ := req.Meta.(*Meta)
	if m == nil {
		return nil
	}
	return map[string]any{
		"kind":         m.Kind,
		"method":       m.Method,
		"tool_name":    m.ToolName,
		"resource_uri": m.ResourceURI,
		"session_id":   m.SessionID,
	}
}

func init() {
	facet.Register(Facet{})
}

// CELContrib declares the MCP facet's CEL contribution: the `mcp`
// variable backed by Fields, the activation builder that snapshots the
// parsed Meta into one, and the path lists CompileCondition needs.
//
// Body-derived fields (method, id, tool_name, resource_uri,
// prompt_name, is_notification) are listed in both TruncatablePaths
// and UnparseablePaths: a truncated body sets req.Truncated and an
// unparseable/batched body sets req.Unparseable, and either marks
// these paths CEL-unknown so any rule whose outcome depends on one
// evaluates Unevaluable. The header-derived fields (kind,
// protocol_version, session_id) are intentionally absent — they are
// always available even when the body is missing or capped.
func (Facet) CELContrib() facet.CELContrib {
	bodyDerived := []string{
		"mcp.method", "mcp.id", "mcp.tool_name",
		"mcp.resource_uri", "mcp.prompt_name", "mcp.is_notification",
	}
	return facet.CELContrib{
		EnvOptions: []cel.EnvOption{
			ext.NativeTypes(
				reflect.TypeFor[Fields](),
				ext.ParseStructTags(true),
			),
			cel.Variable("mcp", cel.ObjectType("mcp.Fields")),
		},
		AddActivation:    addActivation,
		LowercasedPaths:  []string{"mcp.kind"},
		TruncatablePaths: bodyDerived,
		UnparseablePaths: bodyDerived,
	}
}

// NewMatcher compiles a CEL condition into a Matcher. Delegates to the
// package-level composer so the http facet the mcp family composes
// layers in — an mcp rule can reference http.method etc. alongside
// mcp.kind.
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
	act["mcp"] = &Fields{
		Kind:            strings.ToLower(meta.Kind),
		ProtocolVersion: meta.ProtocolVersion,
		SessionID:       meta.SessionID,
		Method:          meta.Method,
		ID:              meta.ID,
		ToolName:        meta.ToolName,
		ResourceURI:     meta.ResourceURI,
		PromptName:      meta.PromptName,
		IsNotification:  meta.IsNotification,
	}
	return true
}

// classifyKind derives mcp.kind from the request line and headers,
// independent of the body. See the Kind* constants.
func classifyKind(req *match.Request) string {
	switch strings.ToUpper(req.Method) {
	case "POST":
		return KindRPC
	case "GET":
		if acceptsEventStream(req) {
			return KindListen
		}
		return KindOther
	case "DELETE":
		if header(req, "Mcp-Session-Id") != "" {
			return KindTerminate
		}
		return KindOther
	default:
		return KindOther
	}
}

// acceptsEventStream reports whether the request's Accept header opts
// into a Server-Sent Events stream (the MCP listen channel).
func acceptsEventStream(req *match.Request) bool {
	return strings.Contains(strings.ToLower(header(req, "Accept")), "text/event-stream")
}

func header(req *match.Request, name string) string {
	if req == nil || req.Headers == nil {
		return ""
	}
	return req.Headers.Get(name)
}
