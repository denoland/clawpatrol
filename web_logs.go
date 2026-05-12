package main

// Plugin-diagnostic log sink. Plugins write structured events via the
// runtime.Logger interface; the gateway buffers the last N entries
// (LogSink.cap, default 1000) in memory and serves them to the
// dashboard's /logs tab via:
//
//   - GET /api/logs           filtered snapshot (plugin / severity / range)
//   - GET /api/logs/stream    SSE live tail
//
// Mirrors the existing Sink (events) shape — ring buffer + subscriber
// fan-out, marshaled once per entry. Distinct from Sink because
// diagnostic logs are not persisted to SQLite (operators want a fast
// rolling tail, not a forever-history; the request actions table
// already carries request-correlated metadata).

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/denoland/clawpatrol/config/runtime"
)

// defaultLogBufferSize is the cap on LogSink's in-memory ring buffer
// when the gateway doesn't override it. Matches the issue spec's
// "default 1000" so an operator running the stock binary sees a
// reasonable scrollback without tuning anything.
const defaultLogBufferSize = 1000

// LogSink buffers plugin diagnostic events in a fixed-size ring and
// fans them out to dashboard SSE subscribers. Drop policy: if a
// subscriber falls behind by more than its channel buffer, packets
// are dropped for that subscriber (counted in `drops`) — the gateway
// stays responsive and the dashboard reconnects on its own.
type LogSink struct {
	ch    chan runtime.LogEntry
	drops atomic.Uint64

	mu   sync.Mutex
	subs []chan logPacket

	// ring storage; recentNext / recentLen track lazy fill before
	// the buffer wraps.
	recent     []runtime.LogEntry
	recentNext int
	recentLen  int
	recentCap  int
}

type logPacket struct {
	entry runtime.LogEntry
	raw   []byte
}

// NewLogSink starts a goroutine that drains the input channel and
// fans entries out to subscribers. cap is the ring-buffer size; 0
// falls back to defaultLogBufferSize.
func NewLogSink(cap int) *LogSink {
	if cap <= 0 {
		cap = defaultLogBufferSize
	}
	s := &LogSink{
		ch:        make(chan runtime.LogEntry, 256),
		recent:    make([]runtime.LogEntry, cap),
		recentCap: cap,
	}
	go s.drain()
	return s
}

// Emit pushes an entry into the sink's drain channel. Drops on full
// channel to keep the gateway snappy — drops are counted but not
// surfaced (operators see a gap; the next entry still arrives).
//
// Sets Ts to now if the caller left it zero so plugin code paths
// don't have to fill it in.
func (s *LogSink) Emit(e runtime.LogEntry) {
	if s == nil {
		return
	}
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	if e.Level == "" {
		e.Level = runtime.LogInfo
	}
	select {
	case s.ch <- e:
	default:
		s.drops.Add(1)
	}
}

// Drops returns the cumulative count of entries dropped because the
// drain channel or a subscriber channel was full. Surfaced via
// /api/logs?meta=1 so operators can spot a runaway plugin.
func (s *LogSink) Drops() uint64 {
	if s == nil {
		return 0
	}
	return s.drops.Load()
}

func (s *LogSink) drain() {
	for e := range s.ch {
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		pkt := logPacket{entry: e, raw: raw}

		s.mu.Lock()
		s.recent[s.recentNext] = e
		s.recentNext = (s.recentNext + 1) % s.recentCap
		if s.recentLen < s.recentCap {
			s.recentLen++
		}
		subs := append([]chan logPacket(nil), s.subs...)
		s.mu.Unlock()

		for _, sub := range subs {
			select {
			case sub <- pkt:
			default:
				s.drops.Add(1)
			}
		}
	}
}

// Snapshot returns a copy of the ring buffer in oldest→newest order.
// Caller may filter / re-order without holding the sink's lock.
func (s *LogSink) Snapshot() []runtime.LogEntry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recentLen == 0 {
		return nil
	}
	out := make([]runtime.LogEntry, s.recentLen)
	if s.recentLen < s.recentCap {
		copy(out, s.recent[:s.recentLen])
		return out
	}
	for i := 0; i < s.recentCap; i++ {
		out[i] = s.recent[(s.recentNext+i)%s.recentCap]
	}
	return out
}

// SnapshotAndSubscribe atomically snapshots the buffer and registers
// a subscriber under the same lock so no event is missed or
// duplicated between the two. Same pattern as
// Sink.RecentAndSubscribe.
func (s *LogSink) SnapshotAndSubscribe() ([]runtime.LogEntry, <-chan logPacket, func()) {
	if s == nil {
		ch := make(chan logPacket)
		close(ch)
		return nil, ch, func() {}
	}
	ch := make(chan logPacket, 64)
	s.mu.Lock()
	snap := s.snapshotLocked()
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

func (s *LogSink) snapshotLocked() []runtime.LogEntry {
	if s.recentLen == 0 {
		return nil
	}
	out := make([]runtime.LogEntry, s.recentLen)
	if s.recentLen < s.recentCap {
		copy(out, s.recent[:s.recentLen])
		return out
	}
	for i := 0; i < s.recentCap; i++ {
		out[i] = s.recent[(s.recentNext+i)%s.recentCap]
	}
	return out
}

// pluginLogger is the gateway's runtime.Logger implementation. Each
// per-request / per-session logger captures the binding (plugin name,
// request id, agent ip) up front so plugin call sites stay terse:
// they invoke .Log on whatever Logger they were handed without
// needing to plumb identification.
type pluginLogger struct {
	sink    *LogSink
	plugin  string
	reqID   string
	agentIP string
	// mirror, when set, writes a line to the host's traditional log
	// (log.Default) for warn / error entries. Keeps backwards compat
	// with operators who watch journalctl / stderr; debug / info stay
	// dashboard-only to avoid stderr spam.
	mirror func(level runtime.LogLevel, plugin, msg string, fields map[string]any)
}

func (l *pluginLogger) Log(level runtime.LogLevel, msg string, fields map[string]any) {
	if l == nil {
		return
	}
	// Redact once, before either consumer sees the payload: the
	// stderr mirror is just as likely to leak credentials as the
	// dashboard buffer.
	redacted := redactFields(fields)
	if l.sink != nil {
		l.sink.Emit(runtime.LogEntry{
			Plugin:  l.plugin,
			Level:   level,
			Msg:     msg,
			ReqID:   l.reqID,
			AgentIP: l.agentIP,
			Fields:  redacted,
		})
	}
	if l.mirror != nil {
		l.mirror(level, l.plugin, msg, redacted)
	}
}

// LoggerFor returns a pluginLogger scoped to (plugin, reqID, agentIP).
// Empty strings are fine — they're omitted from the rendered entry.
// The returned Logger is safe for concurrent use (writes are
// serialized through the sink's drain channel) so endpoint runtimes
// can hand the same instance to reader + writer pumps.
func (g *Gateway) LoggerFor(plugin, reqID, agentIP string) runtime.Logger {
	if g == nil {
		return runtime.NopLogger()
	}
	return &pluginLogger{
		sink:    g.logs,
		plugin:  plugin,
		reqID:   reqID,
		agentIP: agentIP,
		mirror:  mirrorPluginLog,
	}
}

// pluginID builds the "kind/type" identifier surfaced on log entries.
// kind is the lowercase plugin kind ("credential" / "endpoint" /
// "approver" / "tunnel"); typ is the plugin's registered Type
// ("bearer_token", "postgres", etc.). When typ is empty (legacy /
// schema-only plugins), the bare kind keeps the format readable.
func pluginID(kind, typ string) string {
	if typ == "" {
		return kind
	}
	return kind + "/" + typ
}

// mirrorPluginLog writes warn/error plugin diagnostics to the host's
// traditional log so operators still see them in journalctl. Debug /
// info entries stay dashboard-only — the new tab is the system of
// record for the chatty stuff.
func mirrorPluginLog(level runtime.LogLevel, plugin, msg string, fields map[string]any) {
	if level != runtime.LogWarn && level != runtime.LogError {
		return
	}
	if len(fields) == 0 {
		// One-line log with no kv tail; stdlib log adds its own
		// timestamp, so we only carry plugin + msg.
		log.Printf("plugin %s %s: %s", level, plugin, msg)
		return
	}
	log.Printf("plugin %s %s: %s %s", level, plugin, msg, joinFields(fields))
}

// joinFields renders structured fields as `key=value` pairs for the
// stdlib-log mirror. Stable ordering would be nice but isn't worth
// the sort allocation on every warn line — plugin logs are tail-only.
func joinFields(fields map[string]any) string {
	if len(fields) == 0 {
		return ""
	}
	var b strings.Builder
	first := true
	for k, v := range fields {
		if !first {
			b.WriteByte(' ')
		}
		first = false
		b.WriteString(k)
		b.WriteByte('=')
		fmt.Fprintf(&b, "%v", v)
	}
	return b.String()
}

// redactFields ensures we never accidentally surface raw secret
// bytes in the log buffer. Defense in depth — plugin authors are
// expected to log credential names/refs only, but if someone passes
// a `[]byte` or a value flagged with a sensitive-looking key, we
// replace it with "***" before the entry enters the buffer.
//
// Keys flagged: anything matching the existing sensitiveHeader
// regex (auth/token/secret/key/password/cookie). `[]byte` values
// are redacted unconditionally — the plugin should not be passing
// raw bytes through structured logs.
func redactFields(in map[string]any) map[string]any {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if isSensitiveLogKey(k) {
			out[k] = "***"
			continue
		}
		switch v.(type) {
		case []byte:
			out[k] = "***"
		default:
			out[k] = v
		}
	}
	return out
}

func isSensitiveLogKey(k string) bool {
	return sensitiveHeader.MatchString(k)
}

// apiLogs returns the filtered snapshot of the log buffer.
// Query params:
//
//	plugin  — exact plugin identifier; repeatable as comma list
//	min     — min severity (debug|info|warn|error); default info
//	since   — RFC3339 / unix-seconds lower bound on Ts
//	until   — RFC3339 / unix-seconds upper bound on Ts
//	agent   — agent IP filter
//	limit   — cap on returned entries (newest-first up to limit; default 500)
//	meta    — when "1", include {drops,buffer_size,buffer_cap}
func (w *webMux) apiLogs(rw http.ResponseWriter, r *http.Request) {
	if w.g.logs == nil {
		writeJSON(rw, map[string]any{"entries": []runtime.LogEntry{}, "buffer_cap": 0})
		return
	}
	q := r.URL.Query()
	min := runtime.LogLevel(strings.ToLower(q.Get("min")))
	if min == "" {
		min = runtime.LogInfo
	}
	plugins := splitCSV(q.Get("plugin"))
	agent := q.Get("agent")
	since := parseTimeParam(q.Get("since"))
	until := parseTimeParam(q.Get("until"))
	limit := 500
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 5000 {
				n = 5000
			}
			limit = n
		}
	}

	snap := w.g.logs.Snapshot()
	out := make([]runtime.LogEntry, 0, len(snap))
	for _, e := range snap {
		if !runtime.LevelAtLeast(e.Level, min) {
			continue
		}
		if !since.IsZero() && e.Ts.Before(since) {
			continue
		}
		if !until.IsZero() && e.Ts.After(until) {
			continue
		}
		if agent != "" && e.AgentIP != agent {
			continue
		}
		if len(plugins) > 0 && !containsString(plugins, e.Plugin) {
			continue
		}
		out = append(out, e)
	}
	// Truncate newest-first when oversized. The snapshot is already
	// oldest→newest; we want the most recent N entries.
	if len(out) > limit {
		out = out[len(out)-limit:]
	}

	body := map[string]any{
		"entries":    out,
		"buffer_cap": w.g.logs.recentCap,
	}
	if q.Get("meta") == "1" {
		body["drops"] = w.g.logs.Drops()
		body["buffer_size"] = w.g.logs.recentLen
		body["plugins"] = pluginsInBuffer(snap)
	}
	writeJSON(rw, body)
}

// apiLogsSSE streams live log entries to the dashboard. Same shape
// as apiEventsSSE: connected header, snapshot backlog as one
// `event: backlog` payload, then one `data:` line per live entry.
func (w *webMux) apiLogsSSE(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	rw.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "streaming unsupported", 500)
		return
	}
	if w.g.logs == nil {
		_, _ = fmt.Fprintf(rw, ": no log sink\n\n")
		flusher.Flush()
		return
	}

	q := r.URL.Query()
	min := runtime.LogLevel(strings.ToLower(q.Get("min")))
	if min == "" {
		min = runtime.LogDebug
	}
	plugins := splitCSV(q.Get("plugin"))
	agent := q.Get("agent")
	keep := func(e runtime.LogEntry) bool {
		if !runtime.LevelAtLeast(e.Level, min) {
			return false
		}
		if agent != "" && e.AgentIP != agent {
			return false
		}
		if len(plugins) > 0 && !containsString(plugins, e.Plugin) {
			return false
		}
		return true
	}

	backlog, ch, cancel := w.g.logs.SnapshotAndSubscribe()
	defer cancel()

	_, _ = fmt.Fprint(rw, ": connected\n\n")
	if len(backlog) > 0 {
		filtered := backlog[:0]
		for _, e := range backlog {
			if keep(e) {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) > 0 {
			b, err := json.Marshal(filtered)
			if err == nil {
				_, _ = fmt.Fprintf(rw, "event: backlog\ndata: %s\n\n", b)
			}
		}
	}
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			_, _ = fmt.Fprint(rw, ": ka\n\n")
			flusher.Flush()
		case pkt, ok := <-ch:
			if !ok {
				return
			}
			if !keep(pkt.entry) {
				continue
			}
			_, _ = fmt.Fprintf(rw, "data: %s\n\n", pkt.raw)
			flusher.Flush()
		}
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// parseTimeParam accepts an RFC3339 timestamp or a unix-seconds
// integer; returns zero Time when the input is unparseable.
func parseTimeParam(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
}

func pluginsInBuffer(entries []runtime.LogEntry) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, e := range entries {
		if e.Plugin == "" {
			continue
		}
		if _, ok := seen[e.Plugin]; ok {
			continue
		}
		seen[e.Plugin] = struct{}{}
		out = append(out, e.Plugin)
	}
	return out
}
