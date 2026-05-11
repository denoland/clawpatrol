package sql_test

import (
	"testing"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	sqlfacet "github.com/denoland/clawpatrol/config/plugins/facets/sql"
)

func TestSQLMatcherVerbAndTables(t *testing.T) {
	m, err := facet.NewMatcher("sql", map[string]any{
		"verb":   "select",
		"tables": []any{"github_identities", "tokens"},
	})
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

func TestSQLMatcherStatementRegex(t *testing.T) {
	m, err := facet.NewMatcher("sql", map[string]any{
		"verb":            "select",
		"statement_regex": `(?i)\b(secret|password|token)\b`,
	})
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
