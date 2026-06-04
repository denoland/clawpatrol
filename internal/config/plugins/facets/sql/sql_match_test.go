package sql_test

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	sqlfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/sql"
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
	if m.Match(req).Result != match.Matched {
		t.Errorf("expected select on github_identities to match")
	}
	meta.Verb = "insert"
	if got := m.Match(req).Result; got != match.NoMatch {
		t.Errorf("expected verb mismatch to fail, got %v", got)
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
			if got := m.Match(req).Result; got != match.ResultOf(tc.want) {
				t.Errorf("Match=%v want %v (condition=%q)", got, match.ResultOf(tc.want), tc.condition)
			}
		})
	}
}

// TestSQLMatcherDatabaseCaseSensitive pins the database facet's
// case-sensitivity: postgres treats database names as identifiers, so
// `sql.database == "Prod"` MUST distinguish "Prod" from "prod". The
// existing `sql.verb` path normalizes both sides to lowercase; the
// `sql.database` path deliberately does not.
func TestSQLMatcherDatabaseCaseSensitive(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		meta      sqlfacet.Meta
		want      bool
	}{
		{"exact match", `sql.database == 'prod'`, sqlfacet.Meta{Database: "prod"}, true},
		{"different case must miss", `sql.database == 'Prod'`, sqlfacet.Meta{Database: "prod"}, false},
		{"mixed-case got matches mixed-case want", `sql.database == 'Prod'`, sqlfacet.Meta{Database: "Prod"}, true},
		{"missing database does not match", `sql.database == 'prod'`, sqlfacet.Meta{}, false},
		{"composed with verb", `sql.database == 'prod' && sql.verb == 'delete'`, sqlfacet.Meta{Database: "prod", Verb: "delete"}, true},
		{"composed: wrong db", `sql.database == 'prod' && sql.verb == 'delete'`, sqlfacet.Meta{Database: "dev", Verb: "delete"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("sql", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			meta := tc.meta
			req := &match.Request{Family: "sql", Meta: &meta}
			if got := m.Match(req).Result; got != match.ResultOf(tc.want) {
				t.Errorf("Match=%v want %v (condition=%q meta=%+v)", got, match.ResultOf(tc.want), tc.condition, tc.meta)
			}
		})
	}
}

// TestSQLMatcherDatabaseSources exercises both sources of
// sql.database — the req-level field (set by the protocol runtime
// alongside Meta) and the meta.Database fallback. Either path must
// satisfy a rule reading sql.database; req wins when both are set.
func TestSQLMatcherDatabaseSources(t *testing.T) {
	m, err := facet.NewMatcher("sql", "sql.database == 'prod'")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		req  *match.Request
		want bool
	}{
		{"req.Database matches", &match.Request{Family: "sql", Database: "prod", Meta: &sqlfacet.Meta{}}, true},
		{"meta.Database matches when req empty", &match.Request{Family: "sql", Meta: &sqlfacet.Meta{Database: "prod"}}, true},
		{"req beats meta", &match.Request{Family: "sql", Database: "prod", Meta: &sqlfacet.Meta{Database: "dev"}}, true},
		{"req mismatch loses", &match.Request{Family: "sql", Database: "dev", Meta: &sqlfacet.Meta{}}, false},
		{"both empty loses", &match.Request{Family: "sql", Meta: &sqlfacet.Meta{}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.Match(tc.req).Result; got != match.ResultOf(tc.want) {
				t.Errorf("Match=%v want %v", got, match.ResultOf(tc.want))
			}
		})
	}
}

// TestSQLMatcherDatabaseSurvivesTruncation confirms that a rule
// reading only sql.database is NOT auto-denied by the truncation
// fail-close path, because database resolves off-wire and is
// unaffected by the inspection-buffer cap.
func TestSQLMatcherDatabaseSurvivesTruncation(t *testing.T) {
	m, err := facet.NewMatcher("sql", "sql.database == 'prod'")
	if err != nil {
		t.Fatal(err)
	}
	if m.InspectsTruncatableFacet() {
		t.Errorf("a rule reading only sql.database must not be flagged truncatable")
	}
	req := &match.Request{Family: "sql", Database: "prod", Truncated: true, Meta: &sqlfacet.Meta{}}
	if m.Match(req).Result != match.Matched {
		t.Errorf("truncated request with database=prod should still match")
	}
}

func TestSQLMatcherStatementRegex(t *testing.T) {
	m, err := facet.NewMatcher("sql", `sql.verb == 'select' && sql.statement.matches('(?i)\\b(secret|password|token)\\b')`)
	if err != nil {
		t.Fatal(err)
	}
	meta := &sqlfacet.Meta{Verb: "select", Statement: "SELECT secret FROM vault"}
	req := &match.Request{Family: "sql", Meta: meta}
	if m.Match(req).Result != match.Matched {
		t.Errorf("expected regex hit on bare 'secret'")
	}
	// `_` is a word character, so \btoken\b should NOT match inside
	// "api_token" — confirms the regex isn't accidentally
	// substring-matching.
	meta.Statement = "SELECT api_token FROM keys"
	if got := m.Match(req).Result; got != match.NoMatch {
		t.Errorf("expected no regex hit on api_token (word boundary), got %v", got)
	}
}

// TestSQLMatcherUnparseableViralUnknown pins that the parser-facet
// unknown propagates to Unevaluable through every operator shape on
// an Unparseable request — equality, negation, `in` over the unknown
// list, and a comprehension macro — while the raw statement text
// (populated regardless of parse success) keeps evaluating honestly.
func TestSQLMatcherUnparseableViralUnknown(t *testing.T) {
	unevaluable := []string{
		"sql.verb == 'select'",
		"!(sql.verb == 'select')",
		"'users' in sql.tables",
		"sql.tables.exists(t, t == 'users')",
	}
	for _, cond := range unevaluable {
		t.Run(cond, func(t *testing.T) {
			m, err := facet.NewMatcher("sql", cond)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			req := &match.Request{
				Family:      "sql",
				Unparseable: true,
				Meta:        &sqlfacet.Meta{Statement: "DROP;"},
			}
			if got := m.Match(req).Result; got != match.Unevaluable {
				t.Errorf("Match=%v, want Unevaluable (condition=%q)", got, cond)
			}
		})
	}

	m, err := facet.NewMatcher("sql", "sql.statement.contains('DROP')")
	if err != nil {
		t.Fatal(err)
	}
	req := &match.Request{
		Family:      "sql",
		Unparseable: true,
		Meta:        &sqlfacet.Meta{Statement: "DROP;"},
	}
	if got := m.Match(req).Result; got != match.Matched {
		t.Errorf("statement rule on unparseable request: Match=%v, want Matched", got)
	}
}
