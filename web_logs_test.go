package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config/runtime"
)

func TestLogSinkRingBuffer(t *testing.T) {
	s := NewLogSink(3)
	for i := 0; i < 5; i++ {
		s.Emit(runtime.LogEntry{
			Plugin: "test",
			Level:  runtime.LogInfo,
			Msg:    "m" + string(rune('0'+i)),
		})
	}
	waitForBufferFill(t, s, 3)

	snap := s.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("ring buffer len: want 3, got %d", len(snap))
	}
	got := make([]string, 0, len(snap))
	for _, e := range snap {
		got = append(got, e.Msg)
	}
	want := []string{"m2", "m3", "m4"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: want %q got %q", i, want[i], got[i])
		}
	}
}

func TestLogSinkDefaultTsAndLevel(t *testing.T) {
	s := NewLogSink(8)
	s.Emit(runtime.LogEntry{Plugin: "x", Msg: "hi"}) // no Ts, no Level
	waitForBufferFill(t, s, 1)

	snap := s.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("len: want 1 got %d", len(snap))
	}
	if snap[0].Level != runtime.LogInfo {
		t.Fatalf("default level: want info, got %q", snap[0].Level)
	}
	if snap[0].Ts.IsZero() {
		t.Fatalf("Ts not auto-populated")
	}
	if time.Since(snap[0].Ts) > time.Minute {
		t.Fatalf("Ts looks stale: %v", snap[0].Ts)
	}
}

func TestPluginLoggerRedactsSensitiveKeys(t *testing.T) {
	g := &Gateway{logs: NewLogSink(8)}
	lg := g.LoggerFor("credential/test", "", "")
	runtime.Warn(lg, "leaked", map[string]any{
		"credential":   "github-oauth", // ref by name: keep
		"token":        "ghp_xxx",      // sensitive key: redact
		"password":     "swordfish",    // sensitive key: redact
		"raw_bytes":    []byte("abc"),  // []byte value: redact
		"plain_string": "ok",
	})
	waitForBufferFill(t, g.logs, 1)

	got := g.logs.Snapshot()[0].Fields
	if got["credential"] != "github-oauth" {
		t.Errorf("credential ref must pass through: got %v", got["credential"])
	}
	if got["token"] != "***" {
		t.Errorf("token: want redacted, got %v", got["token"])
	}
	if got["password"] != "***" {
		t.Errorf("password: want redacted, got %v", got["password"])
	}
	if got["raw_bytes"] != "***" {
		t.Errorf("raw_bytes: want redacted, got %v", got["raw_bytes"])
	}
	if got["plain_string"] != "ok" {
		t.Errorf("plain string: want passthrough, got %v", got["plain_string"])
	}
}

func TestLogSinkSubscriberFanout(t *testing.T) {
	s := NewLogSink(8)
	_, ch, cancel := s.SnapshotAndSubscribe()
	defer cancel()

	s.Emit(runtime.LogEntry{Plugin: "p", Level: runtime.LogInfo, Msg: "live"})

	select {
	case pkt := <-ch:
		if pkt.entry.Msg != "live" {
			t.Fatalf("got %q", pkt.entry.Msg)
		}
	case <-time.After(time.Second):
		t.Fatal("no entry on subscriber channel")
	}
}

func TestLogSinkSnapshotAndSubscribeOrdering(t *testing.T) {
	s := NewLogSink(8)
	s.Emit(runtime.LogEntry{Plugin: "p", Level: runtime.LogInfo, Msg: "before"})
	waitForBufferFill(t, s, 1)

	backlog, ch, cancel := s.SnapshotAndSubscribe()
	defer cancel()
	if len(backlog) != 1 || backlog[0].Msg != "before" {
		t.Fatalf("backlog snapshot lost the pre-subscribe entry: %+v", backlog)
	}

	s.Emit(runtime.LogEntry{Plugin: "p", Level: runtime.LogInfo, Msg: "after"})
	select {
	case pkt := <-ch:
		if pkt.entry.Msg != "after" {
			t.Fatalf("want 'after', got %q", pkt.entry.Msg)
		}
	case <-time.After(time.Second):
		t.Fatal("post-subscribe entry never arrived")
	}
}

func TestLevelAtLeast(t *testing.T) {
	cases := []struct {
		level, min runtime.LogLevel
		want       bool
	}{
		{runtime.LogDebug, runtime.LogInfo, false},
		{runtime.LogInfo, runtime.LogInfo, true},
		{runtime.LogWarn, runtime.LogInfo, true},
		{runtime.LogError, runtime.LogWarn, true},
		{runtime.LogDebug, runtime.LogDebug, true},
	}
	for _, c := range cases {
		if got := runtime.LevelAtLeast(c.level, c.min); got != c.want {
			t.Errorf("LevelAtLeast(%q, min=%q): got %v want %v", c.level, c.min, got, c.want)
		}
	}
}

func TestApiLogsFilters(t *testing.T) {
	g := &Gateway{logs: NewLogSink(16)}
	w := &webMux{g: g}

	now := time.Now().UTC()
	emit := func(plugin string, level runtime.LogLevel, ts time.Time) {
		g.logs.Emit(runtime.LogEntry{
			Plugin: plugin, Level: level, Msg: "m",
			Ts: ts, AgentIP: "10.0.0.1",
		})
	}
	emit("credential/bearer_token", runtime.LogDebug, now.Add(-2*time.Minute))
	emit("credential/bearer_token", runtime.LogInfo, now.Add(-90*time.Second))
	emit("endpoint/postgres", runtime.LogWarn, now.Add(-60*time.Second))
	emit("endpoint/postgres", runtime.LogError, now.Add(-30*time.Second))
	waitForBufferFill(t, g.logs, 4)

	// min=warn → only warn+error
	r := httptest.NewRequest("GET", "/api/logs?min=warn", nil)
	rw := httptest.NewRecorder()
	w.apiLogs(rw, r)
	got := decodeLogsResp(t, rw)
	if len(got.Entries) != 2 {
		t.Fatalf("min=warn: want 2 entries got %d (%+v)", len(got.Entries), got.Entries)
	}
	for _, e := range got.Entries {
		if !runtime.LevelAtLeast(e.Level, runtime.LogWarn) {
			t.Errorf("min=warn filter let through %q", e.Level)
		}
	}

	// plugin filter
	r = httptest.NewRequest("GET", "/api/logs?min=debug&plugin=endpoint/postgres", nil)
	rw = httptest.NewRecorder()
	w.apiLogs(rw, r)
	got = decodeLogsResp(t, rw)
	if len(got.Entries) != 2 {
		t.Fatalf("plugin=endpoint/postgres: want 2 entries got %d", len(got.Entries))
	}
	for _, e := range got.Entries {
		if e.Plugin != "endpoint/postgres" {
			t.Errorf("plugin filter let through %q", e.Plugin)
		}
	}

	// since= filter — 45s ago should keep only the last two
	since := now.Add(-45 * time.Second).Format(time.RFC3339)
	r = httptest.NewRequest("GET", "/api/logs?min=debug&since="+url.QueryEscape(since), nil)
	rw = httptest.NewRecorder()
	w.apiLogs(rw, r)
	got = decodeLogsResp(t, rw)
	if len(got.Entries) != 1 {
		t.Fatalf("since= filter: want 1 entry got %d", len(got.Entries))
	}
}

func TestApiLogsMetaShape(t *testing.T) {
	g := &Gateway{logs: NewLogSink(8)}
	w := &webMux{g: g}
	g.logs.Emit(runtime.LogEntry{Plugin: "p1", Level: runtime.LogInfo, Msg: "m"})
	g.logs.Emit(runtime.LogEntry{Plugin: "p2", Level: runtime.LogInfo, Msg: "m"})
	waitForBufferFill(t, g.logs, 2)

	r := httptest.NewRequest("GET", "/api/logs?meta=1", nil)
	rw := httptest.NewRecorder()
	w.apiLogs(rw, r)

	var body map[string]any
	if err := json.NewDecoder(rw.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["drops"]; !ok {
		t.Fatalf("meta=1: missing drops field; body=%+v", body)
	}
	plugins, _ := body["plugins"].([]any)
	if len(plugins) != 2 {
		t.Fatalf("plugins list: want 2 got %v", plugins)
	}
}

func TestGatewayLoggerForRoutesToSink(t *testing.T) {
	g := &Gateway{logs: NewLogSink(8)}
	lg := g.LoggerFor("credential/bearer_token", "req-123", "10.0.0.5")
	runtime.Info(lg, "test message", map[string]any{"k": "v"})
	waitForBufferFill(t, g.logs, 1)

	got := g.logs.Snapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 entry got %d", len(got))
	}
	e := got[0]
	if e.Plugin != "credential/bearer_token" {
		t.Errorf("Plugin: got %q", e.Plugin)
	}
	if e.ReqID != "req-123" {
		t.Errorf("ReqID: got %q", e.ReqID)
	}
	if e.AgentIP != "10.0.0.5" {
		t.Errorf("AgentIP: got %q", e.AgentIP)
	}
	if e.Level != runtime.LogInfo {
		t.Errorf("Level: got %q", e.Level)
	}
	if e.Fields["k"] != "v" {
		t.Errorf("Fields: got %v", e.Fields)
	}
}

func TestNilGatewayLoggerFor(t *testing.T) {
	var g *Gateway
	lg := g.LoggerFor("p", "", "")
	// must not panic
	runtime.Info(lg, "msg", nil)
}

func TestRuntimeWithLoggerRoundTrip(t *testing.T) {
	s := NewLogSink(4)
	g := &Gateway{logs: s}
	lg := g.LoggerFor("endpoint/http", "rid", "1.2.3.4")
	ctx := runtime.WithLogger(t.Context(), lg)
	back := runtime.LoggerFrom(ctx)
	runtime.Warn(back, "warn from ctx", nil)
	waitForBufferFill(t, s, 1)

	got := s.Snapshot()
	if len(got) != 1 || got[0].Level != runtime.LogWarn || got[0].ReqID != "rid" {
		t.Fatalf("ctx-bound logger lost identity: %+v", got)
	}
}

func TestApiLogsSSEBacklogAndLive(t *testing.T) {
	g := &Gateway{logs: NewLogSink(8)}
	w := &webMux{g: g}
	g.logs.Emit(runtime.LogEntry{Plugin: "p", Level: runtime.LogInfo, Msg: "backlog-entry"})
	waitForBufferFill(t, g.logs, 1)

	r := httptest.NewRequest("GET", "/api/logs/stream", nil)
	rw := &flushableRecorder{ResponseRecorder: httptest.NewRecorder()}

	// Run SSE handler in a goroutine; cancel the request ctx after
	// we've grabbed the backlog so the handler returns.
	ctx, cancel := context.WithCancel(context.Background())
	r = r.WithContext(ctx)
	done := make(chan struct{})
	go func() {
		w.apiLogsSSE(rw, r)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for {
		if strings.Contains(rw.Snapshot(), "backlog-entry") {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatalf("SSE never delivered backlog; got body=%q", rw.Snapshot())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !strings.Contains(rw.Snapshot(), "event: backlog") {
		t.Errorf("missing `event: backlog` framing in SSE output: %q", rw.Snapshot())
	}

	// Live entry after backlog.
	g.logs.Emit(runtime.LogEntry{Plugin: "p", Level: runtime.LogInfo, Msg: "live-entry"})
	deadline = time.After(2 * time.Second)
	for {
		if strings.Contains(rw.Snapshot(), "live-entry") {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatalf("SSE never delivered live entry; got body=%q", rw.Snapshot())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	<-done
}

// --- helpers ---

type flushableRecorder struct {
	*httptest.ResponseRecorder
	mu  sync.Mutex
	buf strings.Builder
}

func (r *flushableRecorder) Flush() {}

func (r *flushableRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(b)
	r.mu.Unlock()
	return r.ResponseRecorder.Write(b)
}

func (r *flushableRecorder) Snapshot() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

type logsRespFixture struct {
	Entries   []runtime.LogEntry `json:"entries"`
	BufferCap int                `json:"buffer_cap"`
}

func decodeLogsResp(t *testing.T, rw *httptest.ResponseRecorder) logsRespFixture {
	t.Helper()
	var got logsRespFixture
	if err := json.NewDecoder(rw.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// waitForBufferFill blocks until the sink's drain goroutine has
// pushed at least n entries into the ring buffer, or 1 s elapses.
// The sink's emit channel is buffered, so an Emit returns before the
// entry is observable — tests need a barrier rather than a sleep.
func waitForBufferFill(t *testing.T, s *LogSink, n int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := s.recentLen
		s.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("buffer never reached %d entries", n)
}

