package https_test

import (
	"testing"

	"github.com/denoland/clawpatrol/config/facet"
)

// TestHTTPSMatcherInspectsTruncatableFacet pins which CEL
// conditions the dispatcher will fail-close on a request whose
// body overflowed the inspection cap (maxHTTPMatchBody in main.go).
// Only http.body and http.body_json are read out of the buffered
// prefix; method / path / query / headers come straight off the
// request line / header block and are unaffected by truncation.
func TestHTTPSMatcherInspectsTruncatableFacet(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		want      bool
	}{
		{"body contains", "http.body.contains('secret')", true},
		{"body matches", "http.body.matches('(?i)token')", true},
		{"body_json field", "http.body_json.archived == true", true},
		{"body_json nested", "http.body_json.x.y == 'z'", true},
		{"method only", "http.method == 'POST'", false},
		{"path only", "http.path == '/v1/messages'", false},
		{"headers only", "'application/json' in http.headers['Content-Type']", false},
		{"compound method+body", "http.method == 'POST' && http.body.contains('secret')", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("http", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher %q: %v", tc.condition, err)
			}
			if got := m.InspectsTruncatableFacet(); got != tc.want {
				t.Errorf("InspectsTruncatableFacet(%q) = %v, want %v", tc.condition, got, tc.want)
			}
		})
	}
}
