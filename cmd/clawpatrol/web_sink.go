package main

// Event sink — the per-action audit record + the in-memory ring + SSE
// fan-out the dashboard subscribes to. mitm.go and dispatch.go construct
// Event values and feed them through (g *Gateway).emit / sink.Emit; the
// drain goroutine persists terminal rows to the actions table and ships
// the marshaled JSON to every live /api/events subscriber.

import (
	"database/sql"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Ts      time.Time `json:"ts"`
	ID      string    `json:"id,omitempty"`    // UUIDv7; correlates start/end/frame + DB key
	Phase   string    `json:"phase,omitempty"` // "" (legacy/end), "start", "end", "frame"
	Mode    string    `json:"mode"`
	Agent   string    `json:"agent,omitempty"`
	AgentIP string    `json:"agent_ip,omitempty"`
	Host    string    `json:"host"`
	Method  string    `json:"method,omitempty"`
	Path    string    `json:"path,omitempty"`
	Status  int       `json:"status,omitempty"`
	In      int64     `json:"in,omitempty"`
	Out     int64     `json:"out,omitempty"`
	Ms      int64     `json:"ms"`
	Action  string    `json:"action,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	// Approver* are populated when Action is "approved" / "denied":
	// the approver entity's HCL block name, plugin type (human_approver
	// / llm_approver / dashboard), and the approver-specific "By"
	// string (Slack handle, llm:<model>, ...). All empty for rule-
	// driven verdicts.
	Approver     string            `json:"approver,omitempty"`
	ApproverType string            `json:"approver_type,omitempty"`
	ApproverBy   string            `json:"approver_by,omitempty"`
	ReqSha       string            `json:"req_sha,omitempty"`
	ReqBody      string            `json:"req_body,omitempty"`
	RespSha      string            `json:"resp_sha,omitempty"`
	RespBody     string            `json:"resp_body,omitempty"`
	ReqHeaders   map[string]string `json:"req_headers,omitempty"`
	RespHeaders  map[string]string `json:"resp_headers,omitempty"`
	// Frame is set for Phase="frame" only — a single WS frame's text
	// payload (truncated at sampleCap). Direction is "c→s" or "s→c"
	// to disambiguate masked client frames from unmasked server frames.
	Frame     string `json:"frame,omitempty"`
	Direction string `json:"direction,omitempty"`

	// Family identifies which protocol-family facet emitted this
	// event ("http", "sql", "k8s", or a future plugin's name).
	// Persisted as a dedicated column on actions so analytics can
	// filter by family; drives dashboard column selection via
	// /api/facets. Empty for splice events and pre-migration rows.
	Family string `json:"family,omitempty"`

	// Facets carries the per-family report payload — the result of
	// the family's facet.Runtime.Report hook against the matched
	// request. Keys correspond to the family's ReportFields().
	// Serialised as JSON into the actions table's `extra` column.
	Facets map[string]any `json:"facets,omitempty"`

	// Endpoint is the dispatching CompiledEndpoint.Name; Rule is the
	// matched CompiledRule.Name (empty when no rule fired). Populated
	// at the existing dispatch sites so the action-fixture exporter
	// can pin a downloaded action to a specific endpoint and assert
	// the rule that produced its verdict (site/doc/clawpatrol-test.md).
	Endpoint string `json:"endpoint,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

// eventPacket carries an event plus its marshaled JSON bytes. drain()
// marshals once and ships the same bytes to every subscriber so a
// busy gateway doesn't pay N × json.Marshal per event when N
// dashboards are connected.
type eventPacket struct {
	ev  Event
	raw []byte
}

type Sink struct {
	ch    chan Event
	db    *sql.DB
	drops atomic.Uint64
	mu    sync.Mutex
	subs  []chan eventPacket
	// Recent ring backlog. recent is sized once at construction; we
	// write at recentNext (modulo cap) and rotate. Old behavior used
	// `append + slice` which reallocated on every overflow, churning
	// GC at ~10 alloc/sec on a busy gateway. Lazy fill: until we wrap,
	// recentLen tracks valid entries.
	recent     []Event
	recentNext int
	recentLen  int
	recentCap  int
}

func NewSink(db *sql.DB, buf int) (*Sink, error) {
	s := &Sink{ch: make(chan Event, buf), db: db, recentCap: 500}
	s.recent = make([]Event, s.recentCap)
	if db != nil {
		if seed, err := readTailEvents(db, s.recentCap); err == nil && len(seed) > 0 {
			// Seed fills oldest→newest; place at indices 0..len(seed)-1
			// and set recentNext to the next slot, recentLen to length.
			n := len(seed)
			if n > s.recentCap {
				seed = seed[n-s.recentCap:]
				n = s.recentCap
			}
			copy(s.recent, seed)
			s.recentLen = n
			s.recentNext = n % s.recentCap
		}
	}
	go s.drain()
	return s, nil
}

func readTailEvents(db *sql.DB, n int) ([]Event, error) {
	rows, err := db.Query(`
		SELECT action_id, ts_ns, mode, family, agent_ip, host,
		       method, path, status, bytes_in, bytes_out,
		       ms, action, reason, req_sha, resp_sha, extra,
		       endpoint, rule,
		       approver, approver_type, approver_by
		FROM actions ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]Event, 0, n)
	for rows.Next() {
		var (
			e            Event
			actionID     sql.NullString
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
			extra        sql.NullString
			endpoint     sql.NullString
			rule         sql.NullString
			approver     sql.NullString
			approverType sql.NullString
			approverBy   sql.NullString
		)
		if err := rows.Scan(
			&actionID, &tsNs, &mode, &family, &agentIP, &e.Host,
			&method, &path, &status, &in, &ot, &ms,
			&action, &reason, &reqSha, &respSha, &extra,
			&endpoint, &rule,
			&approver, &approverType, &approverBy,
		); err != nil {
			return nil, err
		}
		e.ID = actionID.String
		e.Ts = time.Unix(0, tsNs).UTC()
		e.Mode = mode.String
		e.Family = family.String
		e.Endpoint = endpoint.String
		e.Rule = rule.String
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
		if extra.String != "" {
			_ = json.Unmarshal([]byte(extra.String), &e.Facets)
		}
		e.Approver = approver.String
		e.ApproverType = approverType.String
		e.ApproverBy = approverBy.String
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// rows are newest-first; flip to oldest-first so SSE backlog
	// arrives in the order subscribers expect.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (s *Sink) Emit(e Event) {
	if s == nil {
		return
	}
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	select {
	case s.ch <- e:
	default:
		s.drops.Add(1)
	}
}

func (s *Sink) Drops() uint64 { return s.drops.Load() }

func (s *Sink) drain() {
	for e := range s.ch {
		// Persist only terminal events. start/frame are transient
		// signals for live SSE — duplicating them in `actions` would
		// double-count requests in the request-history view and bloat
		// the table for long-poll / WS sessions.
		persist := e.Phase == "" || e.Phase == "end"
		if persist && e.ID == "" {
			// Some connection-oriented endpoint runtimes emit a single terminal
			// event instead of the HTTP start/end pair. Give those events a
			// stable action_id before DB insert + SSE fan-out so every persisted
			// live-request row can navigate to /api/actions/<id>.
			e.ID = newReqID()
		}
		if s.db != nil && persist {
			var rqhJSON, rshJSON []byte
			if len(e.ReqHeaders) > 0 {
				rqhJSON, _ = json.Marshal(e.ReqHeaders)
			}
			if len(e.RespHeaders) > 0 {
				rshJSON, _ = json.Marshal(e.RespHeaders)
			}
			var extraJSON []byte
			if len(e.Facets) > 0 {
				extraJSON, _ = json.Marshal(e.Facets)
			}
			_, _ = s.db.Exec(`
				INSERT INTO actions
				 (action_id, ts_ns, mode, family, agent_ip, host,
				  method, path, status, bytes_in, bytes_out,
				  ms, action, reason, req_sha, resp_sha,
				  req_body, resp_body,
				  req_headers, resp_headers, extra,
				  endpoint, rule,
				  approver, approver_type, approver_by)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			`, e.ID, e.Ts.UnixNano(), e.Mode, e.Family, e.AgentIP,
				e.Host, e.Method, e.Path, e.Status,
				e.In, e.Out, e.Ms, e.Action, e.Reason,
				e.ReqSha, e.RespSha,
				e.ReqBody, e.RespBody,
				string(rqhJSON), string(rshJSON),
				string(extraJSON),
				e.Endpoint, e.Rule,
				e.Approver, e.ApproverType, e.ApproverBy)
		}

		// Marshal once per event regardless of subscriber count. Old
		// path marshaled inside each subscriber's SSE handler — N
		// dashboards = N json.Marshal calls per event. Now it's 1.
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		pkt := eventPacket{ev: e, raw: raw}

		s.mu.Lock()
		// Recent ring updated under lock since RecentAndSubscribe
		// snapshots it. Circular write: O(1) regardless of cap.
		// Strip bodies from the backlog copy — SSE consumers only
		// need metadata; the detail page fetches full data via
		// /api/actions/<id>.
		if persist {
			lite := e
			lite.ReqBody = ""
			lite.RespBody = ""
			lite.ReqHeaders = nil
			lite.RespHeaders = nil
			s.recent[s.recentNext] = lite
			s.recentNext = (s.recentNext + 1) % s.recentCap
			if s.recentLen < s.recentCap {
				s.recentLen++
			}
		}
		// Copy subs out of the lock, fan-out without holding mu so
		// a slow channel doesn't serialize the gateway. Cheap copy
		// (slice of channel pointers, len ~= dashboards open).
		subs := append([]chan eventPacket(nil), s.subs...)
		s.mu.Unlock()

		for _, sub := range subs {
			select {
			case sub <- pkt:
			default:
				// slow consumer; drop
				s.drops.Add(1)
			}
		}
	}
}

// recentSnapshot copies the ring into a flat oldest→newest slice.
// Caller must hold s.mu (or call from RecentAndSubscribe which does).
func (s *Sink) recentSnapshot() []Event {
	if s.recentLen == 0 {
		return nil
	}
	out := make([]Event, s.recentLen)
	if s.recentLen < s.recentCap {
		copy(out, s.recent[:s.recentLen])
		return out
	}
	// Wrapped: oldest entry sits at recentNext, walk forward modulo cap.
	for i := 0; i < s.recentCap; i++ {
		out[i] = s.recent[(s.recentNext+i)%s.recentCap]
	}
	return out
}

// RecentAndSubscribe atomically snapshots the backlog and registers a
// subscriber under the same lock so no event is missed or duplicated
// between the two. Channel ships eventPackets — drain marshaled the
// JSON once and shares those bytes across every subscriber.
func (s *Sink) RecentAndSubscribe() ([]Event, <-chan eventPacket, func()) {
	if s == nil {
		ch := make(chan eventPacket)
		close(ch)
		return nil, ch, func() {}
	}
	ch := make(chan eventPacket, 64)
	s.mu.Lock()
	snap := s.recentSnapshot()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		for i, c := range s.subs {
			if c == ch {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}
	return snap, ch, cancel
}

func (s *Sink) Subscribe() (<-chan eventPacket, func()) {
	_, ch, cancel := s.RecentAndSubscribe()
	return ch, cancel
}
