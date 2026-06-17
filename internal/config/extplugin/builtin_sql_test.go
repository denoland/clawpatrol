package extplugin

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	sqlfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/sql"
)

// TestBuiltinRequestForSQL covers M3: an external endpoint that binds
// family="sql" sends the coarse sql action fields, and builtinRequestFor
// maps them onto the typed *sql.Meta the built-in sql matcher reads — so
// the endpoint reuses the operator's existing sql.* rules verbatim.
func TestBuiltinRequestForSQL(t *testing.T) {
	action := map[string]any{
		"verb":      "delete",
		"tables":    []any{"tokens", "sessions"},
		"functions": []any{"now"},
		"database":  "prod",
		"statement": "DELETE FROM tokens WHERE id = 1",
	}
	req := builtinRequestFor("sql", "1.2.3.4", "summary", action, nil)

	meta, ok := req.Meta.(*sqlfacet.Meta)
	if !ok {
		t.Fatalf("req.Meta is %T, want *sql.Meta", req.Meta)
	}
	if meta.Verb != "delete" || meta.Database != "prod" ||
		len(meta.Tables) != 2 || meta.Tables[0] != "tokens" || meta.Tables[1] != "sessions" ||
		len(meta.Functions) != 1 || meta.Functions[0] != "now" ||
		meta.Statement != "DELETE FROM tokens WHERE id = 1" {
		t.Fatalf("mapped meta = %+v", meta)
	}

	// End to end: real sql.* rules evaluate against the mapped request.
	cases := []struct {
		cond string
		want match.Result
	}{
		{"sql.verb == 'delete'", match.Matched},
		{"sql.verb == 'select'", match.NoMatch},
		{"sets.intersects(sql.tables, ['tokens'])", match.Matched},
		{"sets.intersects(sql.tables, ['unrelated'])", match.NoMatch},
		{"sql.database == 'prod' && sql.verb == 'delete'", match.Matched},
		{"sql.statement.contains('DELETE')", match.Matched},
	}
	for _, c := range cases {
		m, err := facet.NewMatcher("sql", c.cond)
		if err != nil {
			t.Fatalf("NewMatcher(%q): %v", c.cond, err)
		}
		if got := m.Match(req).Result; got != c.want {
			t.Errorf("%q: result = %v, want %v", c.cond, got, c.want)
		}
	}
}

// TestBuiltinRequestForSQLStatementStream confirms a large statement
// delivered as a stream field (not inline JSON) reaches the matcher.
func TestBuiltinRequestForSQLStatementStream(t *testing.T) {
	req := builtinRequestFor("sql", "1.2.3.4", "summary",
		map[string]any{"verb": "select"},
		map[string][]byte{"statement": []byte("SELECT secret FROM vault")})
	meta, ok := req.Meta.(*sqlfacet.Meta)
	if !ok {
		t.Fatalf("req.Meta is %T, want *sql.Meta", req.Meta)
	}
	if meta.Statement != "SELECT secret FROM vault" {
		t.Errorf("statement = %q, want from stream", meta.Statement)
	}
}
