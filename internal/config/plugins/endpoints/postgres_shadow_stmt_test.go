package endpoints

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestAnalyseShadowStatements pins which wrappers surface their inner
// statement as a shadow sub-statement. The outer verb names the
// wrapper (`explain` / `prepare` / `declare`), so a rule keyed on the
// verb of the statement that actually runs only fires if the inner
// statement reaches the matcher on its own.
//
// EXPLAIN is the split that matters: with ANALYZE it runs the
// statement it wraps, without it it only plans, and the option nodes
// are what say which — the same DefElem whatever spelling the client
// used.
func TestAnalyseShadowStatements(t *testing.T) {
	cases := []struct {
		name       string
		sql        string
		wantVerb   string
		wantInner  []string
		wantTables []string
	}{
		{
			name:     "plain EXPLAIN plans only",
			sql:      "EXPLAIN SELECT * FROM users",
			wantVerb: "explain", wantInner: nil,
			wantTables: []string{"users"},
		},
		{
			name:     "EXPLAIN with non-executing options plans only",
			sql:      "EXPLAIN (COSTS, VERBOSE) DELETE FROM users",
			wantVerb: "explain", wantInner: nil,
			wantTables: []string{"users"},
		},
		{
			name:     "EXPLAIN ANALYZE runs its statement",
			sql:      "EXPLAIN ANALYZE DELETE FROM users WHERE id = 1",
			wantVerb: "explain", wantInner: []string{"delete"},
			wantTables: []string{"users"},
		},
		{
			name:     "EXPLAIN ANALYZE VERBOSE runs its statement",
			sql:      "EXPLAIN ANALYZE VERBOSE UPDATE users SET admin = true",
			wantVerb: "explain", wantInner: []string{"update"},
			wantTables: []string{"users"},
		},
		{
			name:     "parenthesized ANALYZE runs its statement",
			sql:      "EXPLAIN (ANALYZE) DELETE FROM users",
			wantVerb: "explain", wantInner: []string{"delete"},
			wantTables: []string{"users"},
		},
		{
			name:     "ANALYZE true runs its statement",
			sql:      "EXPLAIN (ANALYZE true) INSERT INTO admins (uid) VALUES (1)",
			wantVerb: "explain", wantInner: []string{"insert"},
			wantTables: []string{"admins"},
		},
		{
			name:     "ANALYZE alongside another option runs its statement",
			sql:      "EXPLAIN (ANALYZE, WAL) DELETE FROM users",
			wantVerb: "explain", wantInner: []string{"delete"},
			wantTables: []string{"users"},
		},
		{
			name:     "ANALYZE on runs its statement",
			sql:      "EXPLAIN (analyze ON, format text) DELETE FROM users",
			wantVerb: "explain", wantInner: []string{"delete"},
			wantTables: []string{"users"},
		},
		{
			name:     "ANALYZE 1 runs its statement",
			sql:      "EXPLAIN (ANALYZE 1) DELETE FROM users",
			wantVerb: "explain", wantInner: []string{"delete"},
			wantTables: []string{"users"},
		},
		{
			name:     "ANALYZE false plans only",
			sql:      "EXPLAIN (ANALYZE false) DELETE FROM users",
			wantVerb: "explain", wantInner: nil,
			wantTables: []string{"users"},
		},
		{
			name:     "ANALYZE off plans only",
			sql:      "EXPLAIN (ANALYZE off) DELETE FROM users",
			wantVerb: "explain", wantInner: nil,
			wantTables: []string{"users"},
		},
		{
			name:     "ANALYZE 0 plans only",
			sql:      "EXPLAIN (ANALYZE 0) DELETE FROM users",
			wantVerb: "explain", wantInner: nil,
			wantTables: []string{"users"},
		},
		{
			name:     "the last ANALYZE option wins",
			sql:      "EXPLAIN (ANALYZE true, ANALYZE false) DELETE FROM users",
			wantVerb: "explain", wantInner: nil,
			wantTables: []string{"users"},
		},
		{
			name:     "PREPARE stores a statement that runs later",
			sql:      "PREPARE p AS DELETE FROM users WHERE id = $1",
			wantVerb: "prepare", wantInner: []string{"delete"},
			wantTables: []string{"users"},
		},
		{
			name:     "DECLARE runs its query as the portal is read",
			sql:      "DECLARE c CURSOR FOR SELECT * FROM users",
			wantVerb: "declare", wantInner: []string{"select"},
			wantTables: []string{"users"},
		},
		{
			name:     "COPY of a table carries no inner statement",
			sql:      "COPY users FROM stdin",
			wantVerb: "copy", wantInner: nil,
			wantTables: []string{"users"},
		},
		{
			name:     "COPY of a query runs that query",
			sql:      "COPY (DELETE FROM users RETURNING *) TO stdout",
			wantVerb: "copy", wantInner: []string{"delete"},
			wantTables: []string{"users"},
		},
		{
			name: "EXPLAIN ANALYZE surfaces its own inner and the CTE's",
			sql: "EXPLAIN ANALYZE WITH x AS (DELETE FROM users RETURNING *) " +
				"SELECT * FROM x",
			wantVerb: "explain", wantInner: []string{"select", "delete"},
			wantTables: []string{"users", "x"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyseAll(tc.sql)
			if len(got) != 1 {
				t.Fatalf("analyseAll(%q) returned %d statements, want 1", tc.sql, len(got))
			}
			if got[0].Outer.Verb != tc.wantVerb {
				t.Errorf("outer verb = %q, want %q", got[0].Outer.Verb, tc.wantVerb)
			}
			var innerVerbs []string
			for _, in := range got[0].Inner {
				innerVerbs = append(innerVerbs, in.Verb)
			}
			if diff := cmp.Diff(tc.wantInner, innerVerbs); diff != "" {
				t.Errorf("inner verbs mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantTables, got[0].Outer.Tables); diff != "" {
				t.Errorf("outer tables mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestAnalyseShadowStatementFacets pins what a shadow carries: the
// inner statement's verb and tables, and the wrapper's statement text
// so a rule keyed on sql.statement sees the same bytes it sees on the
// outer statement.
func TestAnalyseShadowStatementFacets(t *testing.T) {
	const sql = "EXPLAIN ANALYZE DELETE FROM public.users WHERE id = 1"
	got := analyseAll(sql)
	if len(got) != 1 || len(got[0].Inner) != 1 {
		t.Fatalf("analyseAll(%q) = %d statements / %d inner, want 1 / 1",
			sql, len(got), len(got[0].Inner))
	}
	inner := got[0].Inner[0]
	if inner.Verb != "delete" {
		t.Errorf("inner verb = %q, want delete", inner.Verb)
	}
	if inner.Statement != sql {
		t.Errorf("inner statement = %q, want %q", inner.Statement, sql)
	}
	if diff := cmp.Diff([]string{"public.users", "users"}, inner.Tables); diff != "" {
		t.Errorf("inner tables mismatch (-want +got):\n%s", diff)
	}
}

// TestPgEvaluateShadowStatements runs the wrappers through a config
// with the shape operators write — a reads allow-list plus a
// lowest-priority catch-all deny. Rules are first-match-wins with no
// deny precedence, so a statement the allow-list matches on the
// wrapper's verb is allowed outright and the catch-all never sees it;
// the mutation is only caught because the inner statement reaches the
// matcher under its own verb.
func TestPgEvaluateShadowStatements(t *testing.T) {
	ep := pgEndpointFromHCL(t, `
endpoint "postgres" "db" {
  host = "db.example.com:5432"
}
credential "postgres_credential" "db-cred" { endpoint = postgres.db }
profile "default" { credentials = [postgres_credential.db-cred] }

rule "reads" {
  endpoint  = postgres.db
  condition = "sql.verb in ['select', 'show', 'explain', 'prepare', 'declare', 'fetch', 'close', 'copy']"
  verdict   = "allow"
}

rule "default-deny" {
  endpoint = postgres.db
  priority = -100
  verdict  = "deny"
  reason   = "not on the read allow-list"
}
`)
	cases := []struct {
		name     string
		sql      string
		wantDeny bool
	}{
		{"plain EXPLAIN of a read", "EXPLAIN SELECT * FROM users", false},
		{"EXPLAIN ANALYZE of a read", "EXPLAIN ANALYZE SELECT * FROM users", false},
		{"EXPLAIN of a write plans only", "EXPLAIN DELETE FROM users", false},
		{"EXPLAIN ANALYZE of a delete", "EXPLAIN ANALYZE DELETE FROM users", true},
		{"parenthesized ANALYZE of a delete", "EXPLAIN (ANALYZE) DELETE FROM users", true},
		{"ANALYZE true of an update", "EXPLAIN (ANALYZE true) UPDATE users SET admin = true", true},
		{"ANALYZE with another option, insert", "EXPLAIN (ANALYZE, WAL) INSERT INTO admins (uid) VALUES (1)", true},
		{"ANALYZE of a CTE-hidden delete", "EXPLAIN ANALYZE WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x", true},
		{"PREPARE of a read", "PREPARE p AS SELECT * FROM users WHERE id = $1", false},
		{"PREPARE of a delete", "PREPARE p AS DELETE FROM users WHERE id = $1", true},
		{"DECLARE of a read", "DECLARE c CURSOR FOR SELECT * FROM users", false},
		{"COPY of a read query", "COPY (SELECT * FROM users) TO stdout", false},
		{"COPY of a delete query", "COPY (DELETE FROM users RETURNING *) TO stdout", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := &runtime.ConnHandle{Endpoint: ep, Emit: func(runtime.ConnEvent) {}}
			v, reason := pgEvaluate(ch, tc.sql, "", "")
			if got := v == "deny"; got != tc.wantDeny {
				t.Errorf("pgEvaluate(%q) = %q (%s), want deny=%v",
					tc.sql, v, reason, tc.wantDeny)
			}
		})
	}
}
