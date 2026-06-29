package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"

	"github.com/denoland/clawpatrol/internal/config/match"
)

// parseRPCBody parses a single JSON-RPC request object out of an rpc
// POST body and fills the body-derived fields of m. It enforces the
// fail-closed contract from the design (§6.3): an rpc POST is either
// parsed from one well-formed JSON-RPC object, or the whole MCP action
// is marked protocol-invalid so the dispatcher denies it before any
// allow rule can match.
//
//   - Truncated body: the gateway already set req.Truncated; mark the
//     action protocol-invalid (body-derived MCP fields are unknown).
//   - Unparseable body (not valid JSON, or valid JSON that is not a
//     single JSON-RPC object): set req.Unparseable and mark the action
//     protocol-invalid.
//   - JSON-RPC batch array: same protocol-invalid outcome as malformed
//     JSON — batches were removed from the MCP spec in revision
//     2025-06-18, and a batched tools/call must not bypass a tool-name
//     deny rule by leaving mcp.tool_name empty.
//
// Body-derived fields are listed in the facet's TruncatablePaths /
// UnparseablePaths, so marking req.Truncated / req.Unparseable also
// poisons any rule that reads them — but the security boundary is the
// ProtocolInvalid signal, which catches catch-all, http.method, and
// mcp.kind allow rules too.
func parseRPCBody(req *match.Request, m *Meta) {
	if req.Truncated {
		markInvalid(m, "request body truncated at the inspection buffer")
		return
	}
	body := bytes.TrimSpace(req.Body)
	if len(body) == 0 {
		// A POST with no body is not a valid JSON-RPC request.
		markInvalid(m, "body is not a single JSON-RPC request")
		req.Unparseable = true
		return
	}
	// A JSON-RPC batch is a top-level array. Reject it outright rather
	// than parsing the first element.
	if body[0] == '[' {
		markInvalid(m, "JSON-RPC batch arrays are not supported")
		req.Unparseable = true
		return
	}
	var obj rpcRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&obj); err != nil {
		markInvalid(m, "body is not a single JSON-RPC request")
		req.Unparseable = true
		return
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		markInvalid(m, "body is not a single JSON-RPC request")
		req.Unparseable = true
		return
	}
	if obj.JSONRPC != "2.0" || obj.Method == "" {
		// Valid JSON, but not a JSON-RPC 2.0 request.
		markInvalid(m, "body is not a single JSON-RPC request")
		req.Unparseable = true
		return
	}
	m.Method = obj.Method
	m.IsNotification = len(obj.ID) == 0
	if !m.IsNotification {
		m.ID = stringifyID(obj.ID)
	}
	switch obj.Method {
	case "tools/call":
		m.ToolName = obj.Params.Name
	case "prompts/get":
		m.PromptName = obj.Params.Name
	case "resources/read", "resources/subscribe", "resources/unsubscribe":
		m.ResourceURI = obj.Params.URI
	}
}

// markInvalid flags m protocol-invalid with an agent-safe reason
// prefixed by the stable "mcp_protocol_invalid" tag the deny event
// surfaces. The cause names only the category of malformedness (the
// agent already knows it sent that body), so it leaks nothing about
// which facets a rule inspects.
func markInvalid(m *Meta, cause string) {
	m.ProtocolInvalid = true
	m.ProtocolInvalidReason = "mcp_protocol_invalid: " + cause
}

// rpcRequest is the minimal JSON-RPC request shape the facet needs.
// ID is kept raw so a numeric or string id round-trips without forcing
// a type, and so an absent id (notification) is distinguishable from a
// null id.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  rpcParams       `json:"params"`
}

// rpcParams carries the params fields the facet extracts. tools/call
// and prompts/get key on params.name; resources/* key on params.uri.
type rpcParams struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

// stringifyID renders a JSON-RPC id (number or string) as a string for
// the mcp.id CEL field. A JSON string id keeps its value without the
// surrounding quotes; any other shape is rendered as its raw JSON.
func stringifyID(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	// Numeric ids: normalize through strconv when possible so 1.0 and 1
	// render consistently; otherwise fall back to the raw token.
	if f, err := strconv.ParseFloat(string(raw), 64); err == nil {
		if f == float64(int64(f)) {
			return strconv.FormatInt(int64(f), 10)
		}
	}
	return string(raw)
}
