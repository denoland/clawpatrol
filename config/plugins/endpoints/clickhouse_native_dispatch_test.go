package endpoints

// Tests for the ClickHouse native query-pattern matchers and dispatch
// glue. The wire-level pump tests live in clickhouse_native_test.go;
// this file pins the SQL-extractor + matcher behaviour the dispatch
// layer relies on for the protocol shapes called out in the dispatch
// ADR (site/doc/adr-clickhouse-native-dispatch.md): INSERT … VALUES,
// SELECT … FORMAT, and SYSTEM commands.

import (
	"bytes"
	"context"
	"testing"

	chgoproto "github.com/ClickHouse/ch-go/proto"
	chproto "github.com/ClickHouse/clickhouse-go/v2/lib/proto"
)

// TestParseChSQLInsertValues covers the INSERT-VALUES shapes a ClickHouse
// client emits when streaming row literals. The parser must surface
// verb=insert and the destination table; trailing FORMAT / SETTINGS the
// real server tolerates after VALUES are stripped before the AST walk
// so an over-strict parser doesn't drop the whole statement on the floor.
func TestParseChSQLInsertValues(t *testing.T) {
	cases := []struct {
		name      string
		sql       string
		wantVerb  string
		wantTable string
	}{
		{
			name:      "plain values single row",
			sql:       "INSERT INTO events VALUES (1, 'hello')",
			wantVerb:  "insert",
			wantTable: "events",
		},
		{
			name:      "values multi row",
			sql:       "INSERT INTO events VALUES (1, 'a'), (2, 'b'), (3, 'c')",
			wantVerb:  "insert",
			wantTable: "events",
		},
		{
			name:      "named columns",
			sql:       "INSERT INTO events (ts, body) VALUES (now(), 'x')",
			wantVerb:  "insert",
			wantTable: "events",
		},
		{
			name:      "qualified database",
			sql:       "INSERT INTO analytics.events VALUES (1, 'x')",
			wantVerb:  "insert",
			wantTable: "analytics.events",
		},
		{
			name:      "values with settings trailer",
			sql:       "INSERT INTO events VALUES (1, 'x') SETTINGS async_insert = 1",
			wantVerb:  "insert",
			wantTable: "events",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := parseChSQL(tc.sql)
			if info.Verb != tc.wantVerb {
				t.Errorf("verb = %q, want %q", info.Verb, tc.wantVerb)
			}
			if len(info.Tables) != 1 || info.Tables[0] != tc.wantTable {
				t.Errorf("tables = %v, want [%q]", info.Tables, tc.wantTable)
			}
			if info.Statement != tc.sql {
				t.Errorf("Statement dropped: got %q, want %q", info.Statement, tc.sql)
			}
		})
	}
}

// TestParseChSQLSelectFormat covers SELECT-FORMAT — clients use this to
// request a specific result encoding (JSON, JSONEachRow, TSV, CSV,
// Pretty, Native, RowBinary, …). The trailing `FORMAT <name>` is one
// of the inputs the AfterShip parser rejects in some positions, so
// chSQLTrailerRE strips it before the AST walk.
func TestParseChSQLSelectFormat(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"format json", "SELECT id, name FROM users FORMAT JSON"},
		{"format jsoneachrow", "SELECT * FROM events FORMAT JSONEachRow"},
		{"format tsv", "SELECT count() FROM events FORMAT TSV"},
		{"format csv with newline", "SELECT id\nFROM users\nFORMAT CSV"},
		{"format pretty trailing space", "SELECT 1 FROM events FORMAT Pretty "},
		{"format native", "SELECT * FROM events FORMAT Native"},
		{"format rowbinary", "SELECT * FROM analytics.events FORMAT RowBinary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := parseChSQL(tc.sql)
			if info.Verb != "select" {
				t.Errorf("verb = %q, want select", info.Verb)
			}
			// All forms reference exactly one table; the AST walker
			// must surface it despite the FORMAT trailer.
			if len(info.Tables) != 1 {
				t.Errorf("tables = %v, want exactly one entry", info.Tables)
			}
			if info.Statement != tc.sql {
				t.Errorf("Statement = %q, want untouched %q", info.Statement, tc.sql)
			}
		})
	}
}

// TestParseChSQLSystemQueries covers operator-side commands that ship as
// SYSTEM <verb> [<target>]. Some — STOP MERGES, RELOAD DICTIONARIES —
// the AfterShip parser knows; others — DROP MARK CACHE — it doesn't,
// in which case the verb-sniffer fallback still surfaces "system" so
// rule conditions like `sql.verb == 'system'` keep firing.
//
// The matcher's contract is loose by design: operators write rules
// against `sql.verb` and `sql.statement_regex`, not against an exact
// SYSTEM sub-command enum, so a fallback-derived verb is enough.
func TestParseChSQLSystemQueries(t *testing.T) {
	cases := []string{
		"SYSTEM RELOAD CONFIG",
		"SYSTEM RELOAD DICTIONARIES",
		"SYSTEM RELOAD DICTIONARY my_dict",
		"SYSTEM STOP MERGES",
		"SYSTEM START MERGES",
		"SYSTEM STOP DISTRIBUTED SENDS",
		"SYSTEM FLUSH LOGS",
		"SYSTEM DROP MARK CACHE",
		"SYSTEM DROP UNCOMPRESSED CACHE",
		"SYSTEM SYNC REPLICA replicas.events",
	}
	for _, sql := range cases {
		t.Run(sql, func(t *testing.T) {
			info := parseChSQL(sql)
			if info.Verb != "system" {
				t.Errorf("verb = %q, want system (input: %q)", info.Verb, sql)
			}
			if info.Statement != sql {
				t.Errorf("Statement dropped: got %q, want %q", info.Statement, sql)
			}
		})
	}
}

// TestParseChSQLShowDescribe verifies the system-shape introspection
// statements (SHOW / DESCRIBE / EXPLAIN) get their dedicated verbs.
// Important because operator-side rules often gate these: "agents may
// SELECT but may not EXPLAIN" is a real anti-leakage stance.
func TestParseChSQLShowDescribe(t *testing.T) {
	cases := []struct {
		sql      string
		wantVerb string
	}{
		{"SHOW DATABASES", "show"},
		{"SHOW TABLES", "show"},
		{"SHOW TABLES FROM analytics", "show"},
		{"DESCRIBE TABLE events", "describe"},
		{"EXPLAIN SELECT * FROM events", "explain"},
		{"EXPLAIN PIPELINE SELECT * FROM events", "explain"},
		{"EXPLAIN AST SELECT * FROM events", "explain"},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			info := parseChSQL(tc.sql)
			if info.Verb != tc.wantVerb {
				t.Errorf("verb = %q, want %q", info.Verb, tc.wantVerb)
			}
			if info.Statement != tc.sql {
				t.Errorf("Statement dropped: got %q, want %q", info.Statement, tc.sql)
			}
		})
	}
}

// TestChEvaluateSQLDeniesSystemQueries ties the system-verb extractor
// to the rule matcher end-to-end. A rule with condition `sql.verb ==
// 'system'` must fire for every SYSTEM-shaped statement, regardless of
// whether the underlying AST parser accepted the body or fell through
// to the verb sniffer.
func TestChEvaluateSQLDeniesSystemQueries(t *testing.T) {
	denySystem := chRuleSQL(t, "deny-system",
		"sql.verb == 'system'", "deny", "system ops blocked", 100)
	ep := chBuildEndpoint(t, denySystem)

	mock, _ := chNewMockHandle(t, ep)

	for _, sql := range []string{
		"SYSTEM RELOAD CONFIG",
		"SYSTEM STOP MERGES",
		"SYSTEM FLUSH LOGS",
	} {
		verdict, reason := chEvaluateSQL(context.Background(), mock.ConnHandle, sql, "ch-cred")
		if verdict != "deny" {
			t.Errorf("%q verdict = %q, want deny", sql, verdict)
		}
		if reason != "system ops blocked" {
			t.Errorf("%q reason = %q, want %q", sql, reason, "system ops blocked")
		}
	}
}

// TestChEvaluateSQLAllowsSelectWithFormat is the inverse of the system-
// deny test: a `sql.verb == 'select'` allow rule must fire for SELECT-
// FORMAT shapes too, since the FORMAT clause is purely an encoding
// directive on the server's reply — not a structural change to the
// statement that policy should care about.
func TestChEvaluateSQLAllowsSelectWithFormat(t *testing.T) {
	allowSelect := chRuleSQL(t, "allow-select",
		"sql.verb == 'select'", "allow", "", 100)
	ep := chBuildEndpoint(t, allowSelect)

	mock, _ := chNewMockHandle(t, ep)

	for _, sql := range []string{
		"SELECT * FROM users FORMAT JSON",
		"SELECT count() FROM events FORMAT JSONEachRow",
		"SELECT id FROM events FORMAT RowBinary",
	} {
		verdict, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, sql, "ch-cred")
		if verdict != "" {
			t.Errorf("%q verdict = %q, want allow (empty)", sql, verdict)
		}
	}
}

// TestChEvaluateSQLTableFacetMatchesQualified covers the
// `sql.tables contains "..."` matcher shape over qualified table names.
// ClickHouse rule writers commonly gate access to specific tables
// (e.g. `sql.tables contains "analytics.secrets"`); the extractor must
// surface the qualifier so the rule fires on `INSERT INTO
// analytics.secrets VALUES (…)` while letting `INSERT INTO
// analytics.events VALUES (…)` through.
func TestChEvaluateSQLTableFacetMatchesQualified(t *testing.T) {
	rule := chRuleSQL(t, "deny-secrets",
		`sql.tables.exists(t, t == "analytics.secrets")`,
		"deny", "secrets table protected", 100)
	ep := chBuildEndpoint(t, rule)

	mock, _ := chNewMockHandle(t, ep)

	verdict, reason := chEvaluateSQL(context.Background(), mock.ConnHandle,
		"INSERT INTO analytics.secrets VALUES (1)", "ch-cred")
	if verdict != "deny" {
		t.Fatalf("secrets-INSERT verdict = %q, want deny", verdict)
	}
	if reason != "secrets table protected" {
		t.Errorf("reason = %q, want %q", reason, "secrets table protected")
	}

	verdict, _ = chEvaluateSQL(context.Background(), mock.ConnHandle,
		"INSERT INTO analytics.events VALUES (1)", "ch-cred")
	if verdict != "" {
		t.Errorf("events-INSERT verdict = %q, want allow (empty)", verdict)
	}
}

// TestChAgentToServerInsertValuesForwarded round-trips an INSERT
// Query + one Data block through the agent → server pump. The data
// block that follows the Query packet is what real clients stream
// row literals on; this nails down that the Query body lands upstream
// verbatim and the ClientData header (TableName=events) is preserved.
func TestChAgentToServerInsertValuesForwarded(t *testing.T) {
	const revision = 54448
	const sql = "INSERT INTO events VALUES"

	mock, _ := chNewMockHandle(t, chBuildEndpoint(t))
	defer func() { _ = mock.Conn.Close() }()

	q := chgoproto.Query{
		ID:    "qid-1",
		Body:  sql,
		Stage: chgoproto.StageComplete,
		Info: chgoproto.ClientInfo{
			ProtocolVersion: revision, Major: 24, Minor: 8,
			Interface:   chgoproto.InterfaceTCP,
			Query:       chgoproto.ClientQueryInitial,
			InitialUser: "alice",
		},
	}
	var agentBuf chgoproto.Buffer
	q.EncodeAware(&agentBuf, revision)

	// One Data packet carrying a single-column block — mirrors what
	// clickhouse-client streams immediately after the Query for an
	// INSERT … VALUES statement.
	agentBuf.PutByte(byte(chgoproto.ClientCodeData))
	chgoproto.ClientData{TableName: "events"}.EncodeAware(&agentBuf, revision)
	dataBlock := chBuildSampleBlock(t)
	if err := dataBlock.Encode(&agentBuf, uint64(revision)); err != nil {
		t.Fatalf("encode data block: %v", err)
	}

	reader := chgoproto.NewReader(bytes.NewReader(agentBuf.Buf))
	var upstream bytes.Buffer
	chAgentToServer(context.Background(), mock.ConnHandle, reader, &upstream, revision, "ch-cred")

	// Walk the forwarded bytes: Query, then Data(events).
	r := chgoproto.NewReader(bytes.NewReader(upstream.Bytes()))
	code, err := r.UInt8()
	if err != nil {
		t.Fatalf("read first packet code: %v", err)
	}
	if chgoproto.ClientCode(code) != chgoproto.ClientCodeQuery {
		t.Fatalf("first packet = %d, want ClientCodeQuery", code)
	}
	var gotQ chgoproto.Query
	if err := gotQ.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode forwarded Query: %v", err)
	}
	if gotQ.Body != sql {
		t.Errorf("forwarded Query body = %q, want %q", gotQ.Body, sql)
	}

	code, err = r.UInt8()
	if err != nil {
		t.Fatalf("read second packet code: %v", err)
	}
	if chgoproto.ClientCode(code) != chgoproto.ClientCodeData {
		t.Fatalf("second packet = %d, want ClientCodeData", code)
	}
	var gotHdr chgoproto.ClientData
	if err := gotHdr.DecodeAware(r, revision); err != nil {
		t.Fatalf("decode forwarded ClientData: %v", err)
	}
	if gotHdr.TableName != "events" {
		t.Errorf("forwarded TableName = %q, want events", gotHdr.TableName)
	}
	gotBlock := chproto.NewBlock()
	if err := gotBlock.Decode(r, uint64(revision)); err != nil {
		t.Fatalf("decode forwarded block: %v", err)
	}
	if gotBlock.Rows() != dataBlock.Rows() {
		t.Errorf("forwarded block rows=%d, want %d", gotBlock.Rows(), dataBlock.Rows())
	}
}
