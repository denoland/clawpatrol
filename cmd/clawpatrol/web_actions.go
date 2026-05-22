package main

// Action-detail handler + fixture exporter. /api/actions/<id> backs
// the dashboard's request detail page and the "Download action"
// button that produces a JSON fixture for `clawpatrol test`. The
// match*FromEvent + export* helpers here translate a recorded Event
// (sourced from the actions table) into the typed Fixture / Match /
// HTTPAction / K8sAction / SQLAction surface defined in action_file.go.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (w *webMux) apiActionByID(
	rw http.ResponseWriter, r *http.Request,
) {
	// Path: /api/actions/<uuid>
	actionID := strings.TrimPrefix(r.URL.Path, "/api/actions/")
	if actionID == "" {
		http.Error(rw, "missing id", 400)
		return
	}
	var (
		e            Event
		tsNs         int64
		mode         sql.NullString
		family       sql.NullString
		agentIP      sql.NullString
		method       sql.NullString
		path         sql.NullString
		status       sql.NullInt64
		in, ot       sql.NullInt64
		ms           sql.NullInt64
		action       sql.NullString
		reason       sql.NullString
		reqSha       sql.NullString
		respSha      sql.NullString
		reqBody      sql.NullString
		respBody     sql.NullString
		reqHeaders   sql.NullString
		respHeaders  sql.NullString
		extra        sql.NullString
		endpoint     sql.NullString
		rule         sql.NullString
		approver     sql.NullString
		approverType sql.NullString
		approverBy   sql.NullString
	)
	err := w.g.db.QueryRow(`
		SELECT ts_ns, mode, family, agent_ip, host, method, path,
		       status, bytes_in, bytes_out, ms, action,
		       reason, req_sha, resp_sha,
		       req_body, resp_body,
		       req_headers, resp_headers, extra,
		       endpoint, rule,
		       approver, approver_type, approver_by
		FROM actions WHERE action_id = ?`, actionID,
	).Scan(
		&tsNs, &mode, &family, &agentIP, &e.Host,
		&method, &path, &status, &in, &ot, &ms,
		&action, &reason, &reqSha, &respSha,
		&reqBody, &respBody,
		&reqHeaders, &respHeaders, &extra,
		&endpoint, &rule,
		&approver, &approverType, &approverBy,
	)
	if err == sql.ErrNoRows {
		http.Error(rw, "not found", 404)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	e.ID = actionID
	e.Ts = time.Unix(0, tsNs).UTC()
	e.Mode = mode.String
	e.Family = family.String
	e.AgentIP = agentIP.String
	e.Method = method.String
	e.Path = path.String
	e.Status = int(status.Int64)
	e.In = in.Int64
	e.Out = ot.Int64
	e.Ms = ms.Int64
	e.Action = action.String
	e.Reason = reason.String
	e.ReqSha = reqSha.String
	e.RespSha = respSha.String
	e.ReqBody = reqBody.String
	e.RespBody = respBody.String
	unmarshalHeaders(reqHeaders.String, &e.ReqHeaders)
	unmarshalHeaders(respHeaders.String, &e.RespHeaders)
	if extra.String != "" {
		_ = json.Unmarshal([]byte(extra.String), &e.Facets)
	}
	e.Endpoint = endpoint.String
	e.Rule = rule.String
	e.Approver = approver.String
	e.ApproverType = approverType.String
	e.ApproverBy = approverBy.String
	if r.URL.Query().Get("fmt") == "fixture" {
		w.writeActionFixture(rw, &e)
		return
	}
	writeJSON(rw, e)
}

// writeActionFixture emits the Action JSON for `clawpatrol test`
// (site/doc/clawpatrol-test.md). 400s on events that pre-date
// endpoint tracking or can't be mapped to a terminal verdict.
func (w *webMux) writeActionFixture(rw http.ResponseWriter, ev *Event) {
	policy := w.g.Policy()
	if policy == nil {
		http.Error(rw, "policy not loaded", http.StatusServiceUnavailable)
		return
	}
	if ev.Endpoint == "" {
		http.Error(rw, "action predates endpoint tracking; cannot export as fixture", 400)
		return
	}
	ep := policy.Endpoints[ev.Endpoint]
	if ep == nil {
		http.Error(rw, fmt.Sprintf("endpoint %q no longer in policy", ev.Endpoint), 400)
		return
	}
	m, ok := matchFromEvent(ev)
	if !ok {
		http.Error(rw, fmt.Sprintf("event action %q is not exportable as a fixture", ev.Action), 400)
		return
	}
	// Stamp the typed reference (endpoint-type.endpoint-name) so the
	// runner can route the fixture without ambiguity. ev.Endpoint is
	// the bare DB-recorded name; the policy supplies the type.
	m.Endpoint = endpointRef(ep)

	fx := &Fixture{Match: m, Action: Action{PeerIP: ev.AgentIP}}
	switch ep.Family {
	case "http":
		fx.Action.Host = ev.Host
		fx.Action.HTTP = exportHTTP(ev)
	case "k8s":
		fx.Action.Host = ev.Host
		fx.Action.K8s = exportK8s(ev)
	case "sql":
		sql := exportSQL(ev)
		if sql == nil {
			http.Error(rw, "sql action has no statement recorded; cannot export", 400)
			return
		}
		// Host for SQL comes from the endpoint's HCL declaration —
		// the recorded Event.Host is the dst IP / tunnel listener,
		// not what the resolver scans against. For multi-host
		// endpoints pick the first; the runner short-circuits on
		// match.endpoint anyway, so host is informational here.
		if len(ep.Hosts) > 0 {
			fx.Action.Host = ep.Hosts[0]
		}
		fx.Action.SQL = sql
	default:
		http.Error(rw, fmt.Sprintf("endpoint family %q is not yet exportable", ep.Family), http.StatusNotImplemented)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, ev.ID))
	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")
	_ = enc.Encode(fx)
}

// matchFromEvent maps post-chain Event.Action onto the fixture's
// terminal verdict vocabulary. hitl_* collapses to "approve".
// Empty Event.Action maps to "allow" — that's the legacy default
// for rows written before per-action verdicts were tracked.
func matchFromEvent(ev *Event) (Match, bool) {
	m := Match{Rule: ev.Rule, Endpoint: ev.Endpoint, Reason: ev.Reason}
	switch ev.Action {
	case "deny":
		m.Verdict = "deny"
	case "approved", "denied", "hitl_allow", "hitl_deny":
		// `approved` / `denied` is the post-rename label for an
		// approve-chain verdict; `hitl_*` are kept for pre-migration
		// fixtures so the test corpus still loads.
		m.Verdict = "approve"
	case "allow", "":
		m.Verdict = "allow"
	case "passthrough":
		m.Verdict = "passthrough"
	default:
		return Match{}, false
	}
	return m, true
}

// exportHTTP populates the http.* CEL view from a recorded Event.
// Host lives on Action (not in the http block) since `http.host`
// isn't a CEL variable. Path comes straight from the recorded URL.
func exportHTTP(ev *Event) *HTTPAction {
	body, b64 := encodeBody([]byte(ev.ReqBody))
	path, query := splitPathQuery(ev.Path)
	return &HTTPAction{
		Method:  ev.Method,
		Path:    path,
		Query:   query,
		Headers: headersToMultiValue(ev.ReqHeaders),
		Body:    body,
		BodyB64: b64,
	}
}

// splitPathQuery separates a recorded Event.Path (which may carry
// `?query=...` already encoded) into path + parsed-query.
func splitPathQuery(raw string) (string, map[string][]string) {
	q := strings.IndexByte(raw, '?')
	if q < 0 {
		return raw, nil
	}
	vals, err := url.ParseQuery(raw[q+1:])
	if err != nil || len(vals) == 0 {
		return raw[:q], nil
	}
	return raw[:q], vals
}

// exportK8s recovers the parsed k8s tuple from Event.Facets, set
// by the k8s facet's Report at live-dispatch time. Only CEL-visible
// fields land in the k8s block.
func exportK8s(ev *Event) *K8sAction {
	a := &K8sAction{}
	if v, ok := ev.Facets["verb"].(string); ok {
		a.Verb = v
	}
	if v, ok := ev.Facets["resource"].(string); ok {
		a.Resource = v
	}
	if v, ok := ev.Facets["namespace"].(string); ok {
		a.Namespace = v
	}
	if v, ok := ev.Facets["name"].(string); ok {
		a.Name = v
	}
	if p, ok := ev.Facets["params"].(map[string]any); ok {
		a.Params = map[string]string{}
		for k, val := range p {
			if s, ok := val.(string); ok {
				a.Params[k] = s
			}
		}
	}
	return a
}

// exportSQL pulls the SQL facet fields out of Event.Facets (set by
// sqlfacet.Report). Statement is required; verb / tables / functions
// / database are emitted when the recorded facets supply them so the
// downloaded fixture mirrors what the dashboard renders and stays
// self-contained for `clawpatrol test` (the loader still tolerates
// missing facets — the SQLParser re-derives them at replay).
func exportSQL(ev *Event) *SQLAction {
	stmt, _ := ev.Facets["statement"].(string)
	if stmt == "" {
		return nil
	}
	a := &SQLAction{Statement: stmt}
	if v, ok := ev.Facets["verb"].(string); ok {
		a.Verb = v
	}
	a.Tables = stringSliceFromFacet(ev.Facets["tables"])
	a.Functions = stringSliceFromFacet(ev.Facets["functions"])
	if v, ok := ev.Facets["database"].(string); ok {
		a.Database = v
	}
	return a
}

// stringSliceFromFacet narrows a JSON-unmarshalled facet list into
// []string. Event.Facets is decoded as map[string]any, so list-typed
// facets land as []any.
func stringSliceFromFacet(v any) []string {
	raw, ok := v.([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		s, ok := x.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// headersToMultiValue widens the Sink's single-value header map to
// http.Header's multi-value shape.
func headersToMultiValue(h map[string]string) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		out[k] = []string{v}
	}
	return out
}
