package sql_test

import (
	"testing"

	"github.com/denoland/clawpatrol/config/facet"
)

// TestSQLMatcherInspectsTruncatableFacet pins which CEL conditions
// the dispatcher will fail-close on a truncated SQL request, and
// which still get their normal Match call.
//
// Every sql.* field rides on the same parsed statement bytes (the
// best-effort lexer in postgres / clickhouse runtimes), so they're
// either all trustworthy or none of them are. Touching any one of
// them in a CEL condition must register as truncatable; touching
// none of them must NOT — predicates that only key off credential
// or family-shape still evaluate honestly when the wire frontend
// hits its inspection cap.
func TestSQLMatcherInspectsTruncatableFacet(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		want      bool
	}{
		{"verb only", "sql.verb == 'select'", true},
		{"tables", "'users' in sql.tables", true},
		{"function list", "'pg_terminate_backend' in sql.function", true},
		{"statement contains", "sql.statement.contains('drop')", true},
		{"statement regex", "sql.statement.matches('(?i)secret')", true},
		{"compound with sql field", "sql.verb == 'select' && true", true},
		{"true literal — reads nothing", "true", false},
		{"false literal — reads nothing", "false", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("sql", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher %q: %v", tc.condition, err)
			}
			if got := m.InspectsTruncatableFacet(); got != tc.want {
				t.Errorf("InspectsTruncatableFacet(%q) = %v, want %v", tc.condition, got, tc.want)
			}
		})
	}
}

// TestSQLPassThroughInspectsTruncatableFacet pins the catch-all
// behavior: an empty condition produces match.PassThrough, which
// reads no facet bytes and so must report false. The dispatcher
// fires it on any request regardless of Truncated.
func TestSQLPassThroughInspectsTruncatableFacet(t *testing.T) {
	m, err := facet.NewMatcher("sql", "")
	if err != nil {
		t.Fatalf("NewMatcher(\"\"): %v", err)
	}
	if m.InspectsTruncatableFacet() {
		t.Errorf("PassThrough.InspectsTruncatableFacet() = true, want false")
	}
}
