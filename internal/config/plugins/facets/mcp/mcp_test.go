package mcp_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	mcpfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/mcp"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// prep builds an mcp-family request from method/path/headers/body and
// runs the facet's PrepareRequest, exactly as the gateway does before
// matching. set truncated to simulate a body capped at the inspection
// buffer.
func prep(method, path string, headers map[string]string, body string, truncated bool) *match.Request {
	u, _ := url.Parse("https://mcp.example.com" + path)
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	req := &match.Request{
		Family:    "mcp",
		Method:    method,
		URL:       u,
		Headers:   h,
		Body:      []byte(body),
		Truncated: truncated,
	}
	facet.Lookup("mcp").PrepareRequest(req)
	return req
}

func meta(t *testing.T, req *match.Request) *mcpfacet.Meta {
	t.Helper()
	m, ok := req.Meta.(*mcpfacet.Meta)
	if !ok {
		t.Fatalf("req.Meta = %T, want *mcp.Meta", req.Meta)
	}
	return m
}

func matchResult(t *testing.T, condition string, req *match.Request) match.Result {
	t.Helper()
	m, err := facet.NewMatcher("mcp", condition)
	if err != nil {
		t.Fatalf("NewMatcher(%q): %v", condition, err)
	}
	return m.Match(req).Result
}

const jsonHeaders = "application/json"

// TestMCPFacetExtractsToolCall: a tools/call JSON-RPC POST exposes
// mcp.method and mcp.tool_name to rules.
func TestMCPFacetExtractsToolCall(t *testing.T) {
	req := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_customer"}}`, false)

	m := meta(t, req)
	if m.Kind != mcpfacet.KindRPC || m.Method != "tools/call" || m.ToolName != "lookup_customer" {
		t.Fatalf("meta = %+v, want kind=rpc method=tools/call tool_name=lookup_customer", m)
	}
	if m.ID != "1" || m.IsNotification {
		t.Errorf("id = %q is_notification = %v, want id=1 not a notification", m.ID, m.IsNotification)
	}
	if got := matchResult(t, `mcp.method == "tools/call" && mcp.tool_name == "lookup_customer"`, req); got != match.Matched {
		t.Errorf("tool-call rule = %v, want Matched", got)
	}
	if got := matchResult(t, `mcp.tool_name == "delete_page"`, req); got != match.NoMatch {
		t.Errorf("wrong-tool rule = %v, want NoMatch", got)
	}
}

// TestMCPFacetExtractsResourceRead: a resources/read POST exposes
// mcp.resource_uri.
// TestMCPFacetExplicitNullIDIsNotNotification: the spec defines an MCP
// notification by an absent id; an explicit JSON null id is still present
// and must not be collapsed into the absent-id case.
func TestMCPFacetExplicitNullIDIsNotNotification(t *testing.T) {
	req := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders},
		`{"jsonrpc":"2.0","id":null,"method":"tools/list"}`, false)

	m := meta(t, req)
	if m.IsNotification {
		t.Fatal("explicit id:null was treated as a notification; only absent id should be notification")
	}
	if m.ID != "null" {
		t.Errorf("id = %q, want null", m.ID)
	}
}

func TestMCPFacetExtractsResourceRead(t *testing.T) {
	req := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders},
		`{"jsonrpc":"2.0","id":"abc","method":"resources/read","params":{"uri":"file:///etc/passwd"}}`, false)

	m := meta(t, req)
	if m.Method != "resources/read" || m.ResourceURI != "file:///etc/passwd" {
		t.Fatalf("meta = %+v, want method=resources/read resource_uri=file:///etc/passwd", m)
	}
	if m.ID != "abc" {
		t.Errorf("id = %q, want abc (string id preserved)", m.ID)
	}
	if got := matchResult(t, `mcp.method == "resources/read" && mcp.resource_uri == "file:///etc/passwd"`, req); got != match.Matched {
		t.Errorf("resource-read rule = %v, want Matched", got)
	}
}

// TestMCPFacetExtractsPromptGet: prompts/get exposes params.name as
// mcp.prompt_name so policy can gate prompt template reads separately
// from tools/resources.
func TestMCPFacetExtractsPromptGet(t *testing.T) {
	req := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders},
		`{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"incident-summary"}}`, false)

	m := meta(t, req)
	if m.Method != "prompts/get" || m.PromptName != "incident-summary" {
		t.Fatalf("meta = %+v, want method=prompts/get prompt_name=incident-summary", m)
	}
	if got := matchResult(t, `mcp.method == "prompts/get" && mcp.prompt_name == "incident-summary"`, req); got != match.Matched {
		t.Errorf("prompt-get rule = %v, want Matched", got)
	}
}

// TestMCPFacetClassifiesKind: kind is derived from the request line and
// headers, independent of the body.
func TestMCPFacetClassifiesKind(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		body    string
		want    string
	}{
		{"post json is rpc", "POST", map[string]string{"Content-Type": jsonHeaders}, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, mcpfacet.KindRPC},
		{"get sse is listen", "GET", map[string]string{"Accept": "text/event-stream"}, "", mcpfacet.KindListen},
		{"delete with session is terminate", "DELETE", map[string]string{"Mcp-Session-Id": "s1"}, "", mcpfacet.KindTerminate},
		{"get without sse is other", "GET", nil, "", mcpfacet.KindOther},
		{"delete without session is other", "DELETE", nil, "", mcpfacet.KindOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := prep(tc.method, "/mcp", tc.headers, tc.body, false)
			if got := meta(t, req).Kind; got != tc.want {
				t.Errorf("kind = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMCPFacetListenStreamFieldsEvaluableAndEmpty: a GET listen stream
// has no JSON-RPC body, so body-derived fields evaluate to zero values
// and are evaluable (NOT unknown). This is what lets an allowlist admit
// the Streamable HTTP control channel.
func TestMCPFacetListenStreamFieldsEvaluableAndEmpty(t *testing.T) {
	req := prep("GET", "/mcp", map[string]string{"Accept": "text/event-stream"}, "", false)

	if got := matchResult(t, `mcp.kind != "rpc"`, req); got != match.Matched {
		t.Errorf(`mcp.kind != "rpc" = %v, want Matched`, got)
	}
	// The body-derived field is empty AND evaluable — not Unevaluable.
	if got := matchResult(t, `mcp.method == ""`, req); got != match.Matched {
		t.Errorf(`mcp.method == "" = %v, want Matched (evaluable empty, not unknown)`, got)
	}
	if req.ProtocolInvalid {
		t.Error("listen stream must not be flagged protocol-invalid")
	}
}

// TestMCPFacetReadsSessionAndProtocolHeaders: header-derived fields are
// always available.
func TestMCPFacetReadsSessionAndProtocolHeaders(t *testing.T) {
	req := prep("POST", "/mcp", map[string]string{
		"Content-Type":         jsonHeaders,
		"MCP-Protocol-Version": "2025-06-18",
		"Mcp-Session-Id":       "sess-xyz",
	}, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, false)

	if got := matchResult(t, `mcp.protocol_version == "2025-06-18" && mcp.session_id == "sess-xyz"`, req); got != match.Matched {
		t.Errorf("header rule = %v, want Matched", got)
	}
}

// TestMCPFacetBodyDerivedFieldsFailClosedOnTruncation: a truncated body
// makes body-derived rules Unevaluable (the dispatcher fails closed),
// while header-derived rules still evaluate.
func TestMCPFacetBodyDerivedFieldsFailClosedOnTruncation(t *testing.T) {
	req := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders},
		`{"jsonrpc":"2.0","id":1,"method":"tools/ca`, true)

	if got := matchResult(t, `mcp.method == "tools/call"`, req); got != match.Unevaluable {
		t.Errorf("body-derived rule on truncated body = %v, want Unevaluable", got)
	}
	if got := matchResult(t, `mcp.kind == "rpc"`, req); got != match.Matched {
		t.Errorf("header-derived rule on truncated body = %v, want Matched", got)
	}
	if !req.ProtocolInvalid {
		t.Error("truncated rpc POST must be flagged protocol-invalid")
	}
}

// TestMCPFacetBodyDerivedFieldsFailClosedOnMalformedJSON: invalid JSON
// makes body-derived rules Unevaluable.
func TestMCPFacetBodyDerivedFieldsFailClosedOnMalformedJSON(t *testing.T) {
	req := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, `{not valid json`, false)

	if got := matchResult(t, `mcp.method == "tools/call"`, req); got != match.Unevaluable {
		t.Errorf("body-derived rule on malformed JSON = %v, want Unevaluable", got)
	}
	if !req.ProtocolInvalid {
		t.Error("malformed rpc POST must be flagged protocol-invalid")
	}
}

// TestMCPFacetBodyDerivedFieldsFailClosedOnBatchArray: a JSON-RPC batch
// must not let a tools/call slip past a tool-name rule by leaving
// mcp.tool_name empty. The body-derived field is Unevaluable, not an
// empty string that NoMatches.
func TestMCPFacetBodyDerivedFieldsFailClosedOnTrailingGarbage(t *testing.T) {
	cases := map[string]string{
		"trailing garbage":    `{"jsonrpc":"2.0","id":1,"method":"tools/list"} garbage`,
		"concatenated object": `{"jsonrpc":"2.0","id":1,"method":"tools/list"}{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_page"}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, body, false)
			if got := matchResult(t, `mcp.method == "tools/list"`, req); got != match.Unevaluable {
				t.Errorf("body-derived rule on %s = %v, want Unevaluable", name, got)
			}
			if !req.ProtocolInvalid {
				t.Fatalf("%s rpc POST must be flagged protocol-invalid", name)
			}
			if deny := runtime.ProtocolInvalidDeny(req); deny == nil || deny.Outcome.Verdict != "deny" {
				t.Fatalf("ProtocolInvalidDeny(%s) = %v, want deny", name, deny)
			}
		})
	}
}

func TestMCPFacetBodyDerivedFieldsFailClosedOnBatchArray(t *testing.T) {
	req := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders},
		`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_page"}}]`, false)

	// The rev-1 bypass: a deny rule on the tool name must not silently
	// miss because the batch left the field empty.
	if got := matchResult(t, `mcp.tool_name == "delete_page"`, req); got != match.Unevaluable {
		t.Errorf(`mcp.tool_name == "delete_page" on batch = %v, want Unevaluable`, got)
	}
	if got := matchResult(t, `mcp.tool_name == ""`, req); got != match.Unevaluable {
		t.Errorf(`mcp.tool_name == "" on batch = %v, want Unevaluable (no empty-but-evaluable state)`, got)
	}
	if !req.ProtocolInvalid {
		t.Error("batch rpc POST must be flagged protocol-invalid")
	}
}

// invalidBodies enumerates the three protocol-invalid rpc POST shapes
// the gate must catch.
func invalidRequests() map[string]*match.Request {
	return map[string]*match.Request{
		"malformed":       prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, `{not json`, false),
		"empty body":      prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, ``, false),
		"batch":           prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, `[{"method":"tools/call"}]`, false),
		"trailing junk":   prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, `{"method":"tools/list"} trailing`, false),
		"missing jsonrpc": prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, `{"method":"tools/list"}`, false),
		"missing method":  prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, `{"jsonrpc":"2.0","id":1}`, false),
		"wrong jsonrpc":   prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, `{"jsonrpc":"1.0","method":"tools/list"}`, false),
		"truncated":       prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders}, `{"method":"too`, true),
	}
}

func assertGateDeniesDespiteAllow(t *testing.T, ep *config.CompiledEndpoint) {
	t.Helper()
	for name, req := range invalidRequests() {
		t.Run(name, func(t *testing.T) {
			// The matcher alone would allow this request — that is the
			// whole point: the gate, not the rule set, is what denies.
			if cr := runtime.MatchRequest(ep, req); cr == nil || cr.Outcome.Verdict != "allow" {
				t.Fatalf("precondition: MatchRequest = %v, want the allow rule (so the gate is the only thing denying)", cr)
			}
			deny := runtime.ProtocolInvalidDeny(req)
			if deny == nil {
				t.Fatal("ProtocolInvalidDeny = nil, want a synthesized deny")
			}
			if deny.Outcome.Verdict != "deny" {
				t.Errorf("verdict = %q, want deny", deny.Outcome.Verdict)
			}
			if !strings.HasPrefix(deny.Outcome.Reason, "mcp_protocol_invalid") {
				t.Errorf("reason = %q, want mcp_protocol_invalid prefix", deny.Outcome.Reason)
			}
		})
	}
}

func allowRule(t *testing.T, name, condition string) *config.CompiledRule {
	t.Helper()
	var m match.Matcher
	if condition != "" {
		var err error
		if m, err = facet.NewMatcher("mcp", condition); err != nil {
			t.Fatalf("NewMatcher(%q): %v", condition, err)
		}
	}
	return &config.CompiledRule{Name: name, Matcher: m, Outcome: config.Outcome{Verdict: "allow"}}
}

// TestMCPFacetProtocolInvalidDeniesCatchAllAllow: an unconditional allow
// rule (nil matcher) does not let a malformed/batch/truncated MCP POST
// through.
func TestMCPFacetProtocolInvalidDeniesCatchAllAllow(t *testing.T) {
	ep := &config.CompiledEndpoint{Family: "mcp", Name: "m", Rules: []*config.CompiledRule{
		allowRule(t, "catch-all", ""),
	}}
	assertGateDeniesDespiteAllow(t, ep)
}

// TestMCPFacetProtocolInvalidDeniesHTTPPostAllow: an http.method allow
// rule does not let a malformed/batch/truncated MCP POST through.
func TestMCPFacetProtocolInvalidDeniesHTTPPostAllow(t *testing.T) {
	ep := &config.CompiledEndpoint{Family: "mcp", Name: "m", Rules: []*config.CompiledRule{
		allowRule(t, "http-post", `http.method == "POST"`),
	}}
	assertGateDeniesDespiteAllow(t, ep)
}

// TestMCPFacetProtocolInvalidDeniesKindRPCAllow: an mcp.kind allow rule
// does not let a malformed/batch/truncated MCP POST through.
func TestMCPFacetProtocolInvalidDeniesKindRPCAllow(t *testing.T) {
	ep := &config.CompiledEndpoint{Family: "mcp", Name: "m", Rules: []*config.CompiledRule{
		allowRule(t, "kind-rpc", `mcp.kind == "rpc"`),
	}}
	assertGateDeniesDespiteAllow(t, ep)

	// Specificity: a well-formed rpc POST is allowed by the same rule
	// and the gate does not fire.
	valid := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, false)
	if runtime.ProtocolInvalidDeny(valid) != nil {
		t.Error("gate fired on a valid rpc POST")
	}
	if cr := runtime.MatchRequest(ep, valid); cr == nil || cr.Outcome.Verdict != "allow" {
		t.Errorf("valid rpc POST = %v, want allow", cr)
	}
}

// TestMCPFacetAllowsHTTPFields: the mcp family composes the http facet,
// so an mcp rule can read http.* alongside mcp.*.
func TestMCPFacetAllowsHTTPFields(t *testing.T) {
	req := prep("POST", "/mcp", map[string]string{"Content-Type": jsonHeaders},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, false)
	if got := matchResult(t, `mcp.kind == "rpc" && http.path == "/mcp"`, req); got != match.Matched {
		t.Errorf("compound mcp+http rule = %v, want Matched", got)
	}
}

// TestHTTPFamilyCannotReadMCPFields: the http family does not compose
// the mcp facet, so referencing mcp.* in an http rule is a compile
// error.
func TestHTTPFamilyCannotReadMCPFields(t *testing.T) {
	if _, err := facet.NewMatcher("http", `mcp.kind == "rpc"`); err == nil {
		t.Error("expected http-family rule referencing mcp.* to fail compilation")
	}
}

// TestMCPFacetReportFields: the per-family report carries the
// dashboard-facing fields for representative RPC and control requests.
func TestMCPFacetReportFields(t *testing.T) {
	fac := facet.Lookup("mcp")

	rpc := prep("POST", "/mcp", map[string]string{
		"Content-Type":   jsonHeaders,
		"Mcp-Session-Id": "sess-1",
	}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_customer"}}`, false)
	got := fac.Report(rpc)
	want := map[string]any{
		"kind": "rpc", "method": "tools/call", "tool_name": "lookup_customer",
		"resource_uri": "", "session_id": "sess-1",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("rpc report[%q] = %v, want %v", k, got[k], v)
		}
	}

	term := prep("DELETE", "/mcp", map[string]string{"Mcp-Session-Id": "sess-2"}, "", false)
	tr := fac.Report(term)
	if tr["kind"] != "terminate" || tr["session_id"] != "sess-2" || tr["method"] != "" {
		t.Errorf("terminate report = %v, want kind=terminate session_id=sess-2 method=''", tr)
	}
}
