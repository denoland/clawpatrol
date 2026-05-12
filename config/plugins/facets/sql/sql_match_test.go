package sql_test

import (
	"testing"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	sqlfacet "github.com/denoland/clawpatrol/config/plugins/facets/sql"
)

func TestSQLMatcherVerbAndTables(t *testing.T) {
	m, err := facet.NewMatcher("sql", "sql.verb == 'select' && sets.intersects(sql.tables, ['github_identities', 'tokens'])")
	if err != nil {
		t.Fatal(err)
	}
	meta := &sqlfacet.Meta{
		Verb:   "select",
		Tables: []string{"users", "github_identities"},
	}
	req := &match.Request{Family: "sql", Meta: meta}
	if !m.Match(req) {
		t.Errorf("expected select on github_identities to match")
	}
	meta.Verb = "insert"
	if m.Match(req) {
		t.Errorf("expected verb mismatch to fail")
	}
}

// TestSQLMatcherVerbCaseInsensitive locks in that a rule written as
// `sql.verb == "SELECT"` matches a select statement even though the
// activation normalizes the got value to lowercase. CompileCondition
// lowercases the want-side string literals at rule-load time.
func TestSQLMatcherVerbCaseInsensitive(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		want      bool
	}{
		{"uppercase want", "sql.verb == 'SELECT'", true},
		{"mixed-case want", "sql.verb == 'Select'", true},
		{"lowercase want (already)", "sql.verb == 'select'", true},
		{"upper-case list", "sql.verb in ['SELECT', 'INSERT']", true},
		{"miss after normalization", "sql.verb == 'UPDATE'", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("sql", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			req := &match.Request{Family: "sql", Meta: &sqlfacet.Meta{Verb: "select"}}
			if got := m.Match(req); got != tc.want {
				t.Errorf("Match=%v want %v (condition=%q)", got, tc.want, tc.condition)
			}
		})
	}
}

// TestSQLMatcherVerbsList confirms `sql.verbs` is exposed to CEL and
// that `"drop" in sql.verbs` fires on a multi-statement query whose
// FIRST verb is the harmless SELECT — the canonical pre-#143 bypass
// shape.
func TestSQLMatcherVerbsList(t *testing.T) {
	m, err := facet.NewMatcher("sql", `"drop" in sql.verbs`)
	if err != nil {
		t.Fatal(err)
	}
	meta := &sqlfacet.Meta{Verb: "select", Verbs: []string{"select", "drop"}}
	req := &match.Request{Family: "sql", Meta: meta}
	if !m.Match(req) {
		t.Errorf("expected `drop in sql.verbs` to match a select;drop batch")
	}
	meta.Verbs = []string{"select"}
	if m.Match(req) {
		t.Errorf("expected no match when sql.verbs has only select")
	}
}

// TestSQLMatcherVerbsUppercaseTolerated guards the activation-side
// case guarantee: meta.Verbs come from the extractor lower-cased, but
// if a future endpoint ever populates them with mixed case the
// activation path should still feed CEL lowercase values.
func TestSQLMatcherVerbsUppercaseTolerated(t *testing.T) {
	m, err := facet.NewMatcher("sql", `"insert" in sql.verbs`)
	if err != nil {
		t.Fatal(err)
	}
	meta := &sqlfacet.Meta{Verb: "select", Verbs: []string{"SELECT", "INSERT"}}
	req := &match.Request{Family: "sql", Meta: meta}
	if !m.Match(req) {
		t.Errorf("expected case-folded `insert in sql.verbs` match")
	}
}

func TestSQLMatcherStatementRegex(t *testing.T) {
	m, err := facet.NewMatcher("sql", `sql.verb == 'select' && sql.statement.matches('(?i)\\b(secret|password|token)\\b')`)
	if err != nil {
		t.Fatal(err)
	}
	meta := &sqlfacet.Meta{Verb: "select", Statement: "SELECT secret FROM vault"}
	req := &match.Request{Family: "sql", Meta: meta}
	if !m.Match(req) {
		t.Errorf("expected regex hit on bare 'secret'")
	}
	// `_` is a word character, so \btoken\b should NOT match inside
	// "api_token" — confirms the regex isn't accidentally
	// substring-matching.
	meta.Statement = "SELECT api_token FROM keys"
	if m.Match(req) {
		t.Errorf("expected no regex hit on api_token (word boundary)")
	}
}
