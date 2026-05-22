package main

// Analytics + facet-schema endpoints feeding the dashboard's
// analytics tab and per-family column renderer. apiAnalytics samples
// the actions table for the chart layer and computes real top-N
// breakdowns by device and host; apiFacets surfaces every registered
// facet's report-field schema so the frontend can build columns from
// the JSON payload of each event without hardcoding a switch on
// family strings.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config/facet"
)

// apiAnalytics returns a randomly-sampled set of events for the
// analytics charts. Query params:
//
//	range  — duration string (1m, 5m, 15m, 30m, 1h, 6h, 24h)
//	agent  — optional agent IP filter
//	limit  — max rows (default 5000)
func (w *webMux) apiAnalytics(
	rw http.ResponseWriter, r *http.Request,
) {
	q := r.URL.Query()
	rangeStr := q.Get("range")
	if rangeStr == "" {
		rangeStr = "1h"
	}
	dur, err := time.ParseDuration(
		strings.TrimSuffix(rangeStr, "m") + "m0s",
	)
	// Parse shorthand: 1m, 5m, 30m, 1h, 6h, 24h
	switch rangeStr {
	case "1m":
		dur = time.Minute
	case "5m":
		dur = 5 * time.Minute
	case "15m":
		dur = 15 * time.Minute
	case "30m":
		dur = 30 * time.Minute
	case "1h":
		dur = time.Hour
	case "6h":
		dur = 6 * time.Hour
	case "24h":
		dur = 24 * time.Hour
	default:
		if err != nil {
			dur = time.Hour
		}
	}
	cutoff := time.Now().Add(-dur).UnixNano()
	limit := 5000
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 10000 {
				n = 10000
			}
			limit = n
		}
	}
	agent := q.Get("agent")

	where := "ts_ns >= ?"
	whereArgs := []any{cutoff}
	if agent != "" {
		where += " AND agent_ip = ?"
		whereArgs = append(whereArgs, agent)
	}

	// Sort by the random suffix of action_id (UUIDv7, so the last
	// chars are uniform random) instead of RANDOM(). Same range +
	// agent → same sample, so a polling dashboard doesn't reshuffle
	// the scatter every 10 s.
	query := `
		SELECT action_id, ts_ns, mode, family, agent_ip, host,
		       method, path, status, bytes_in, bytes_out,
		       ms, action, reason, extra
		FROM actions
		WHERE ` + where + `
		ORDER BY COALESCE(substr(action_id, -8), CAST(ts_ns AS TEXT))
		LIMIT ?`
	args := append(append([]any{}, whereArgs...), limit)
	rows, err := w.g.db.Query(query, args...)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]Event, 0, 256)
	for rows.Next() {
		var (
			e        Event
			actionID sql.NullString
			tsNs     int64
			mode     sql.NullString
			family   sql.NullString
			agentIP  sql.NullString
			method   sql.NullString
			path     sql.NullString
			status   sql.NullInt64
			in, ot   sql.NullInt64
			ms       sql.NullInt64
			action   sql.NullString
			reason   sql.NullString
			extra    sql.NullString
		)
		if err := rows.Scan(
			&actionID, &tsNs, &mode, &family, &agentIP, &e.Host,
			&method, &path, &status, &in, &ot, &ms,
			&action, &reason, &extra,
		); err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		e.ID = actionID.String
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
		if extra.String != "" {
			_ = json.Unmarshal([]byte(extra.String), &e.Facets)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}

	// Real (non-sampled) totals so the top stats reflect the actual
	// request volume, not the chart's 5000-row sample. Filtered by
	// the same range + agent as the events query above.
	var totalCount int64
	var errorCount sql.NullInt64
	_ = w.g.db.QueryRow(
		`SELECT COUNT(*),
		        SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END)
		 FROM actions WHERE `+where, whereArgs...,
	).Scan(&totalCount, &errorCount)

	// Real per-device / per-host counts so the bar lists aren't
	// capped at the sample size either. Same filter; bar charts only
	// render the top ~10 so 50 is a generous cap.
	byDevice := groupCount(w.g.db,
		`SELECT agent_ip, COUNT(*) FROM actions
		 WHERE `+where+` AND agent_ip IS NOT NULL AND agent_ip != ''
		 GROUP BY agent_ip ORDER BY 2 DESC LIMIT 50`,
		whereArgs)
	byHost := groupCount(w.g.db,
		`SELECT host, COUNT(*) FROM actions
		 WHERE `+where+` AND host IS NOT NULL AND host != ''
		 GROUP BY host ORDER BY 2 DESC LIMIT 50`,
		whereArgs)

	writeJSON(rw, map[string]any{
		"events":      out,
		"total":       len(out),
		"total_count": totalCount,
		"error_count": errorCount.Int64,
		"by_device":   byDevice,
		"by_host":     byHost,
	})
}

// apiFacets returns every registered facet's reporting schema.
// The dashboard fetches this once at boot and uses it to render
// per-family columns (HTTPS: method/path/status, SQL:
// verb/tables/..., k8s: verb/resource/...) directly from the JSON
// `facets` payload on each event, instead of carrying a hardcoded
// switch on family strings.
func (w *webMux) apiFacets(rw http.ResponseWriter, r *http.Request) {
	_ = r
	type reportFieldJSON struct {
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Label string `json:"label,omitempty"`
	}
	type facetJSON struct {
		Name             string            `json:"name"`
		EndpointFamilies []string          `json:"endpoint_families"`
		Transport        string            `json:"transport,omitempty"`
		HITLQueryLabel   string            `json:"hitl_query_label,omitempty"`
		HostIsResource   bool              `json:"host_is_resource"`
		ReportFields     []reportFieldJSON `json:"report_fields"`
	}
	all := facet.All()
	out := make([]facetJSON, 0, len(all))
	for _, f := range all {
		fks := f.ReportFields()
		entry := facetJSON{
			Name:             f.Name(),
			EndpointFamilies: f.EndpointFamilies(),
			Transport:        f.Transport(),
			HITLQueryLabel:   f.HITLQueryLabel(),
			HostIsResource:   f.HostIsResource(),
			ReportFields:     make([]reportFieldJSON, len(fks)),
		}
		for i, fk := range fks {
			entry.ReportFields[i] = reportFieldJSON{
				Name: fk.Name, Kind: reportKindName(fk.Kind), Label: fk.Label,
			}
		}
		out = append(out, entry)
	}
	writeJSON(rw, map[string]any{"facets": out})
}

func reportKindName(k facet.ReportValueKind) string {
	switch k {
	case facet.ReportString:
		return "string"
	case facet.ReportStringList:
		return "string_list"
	case facet.ReportStringMap:
		return "string_map"
	case facet.ReportInt:
		return "int"
	}
	return ""
}

func groupCount(db *sql.DB, q string, args []any) []map[string]any {
	out := []map[string]any{}
	rows, err := db.Query(q, args...)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k sql.NullString
		var c int64
		if err := rows.Scan(&k, &c); err != nil || !k.Valid {
			continue
		}
		out = append(out, map[string]any{
			"key": k.String, "count": c,
		})
	}
	if err := rows.Err(); err != nil {
		return []map[string]any{}
	}
	return out
}
