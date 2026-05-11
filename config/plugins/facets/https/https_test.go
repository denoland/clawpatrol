package https_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"

	_ "github.com/denoland/clawpatrol/config/plugins/facets/https"
)

// httpReq builds a minimal Request for the HTTP matcher tests.
// Header / body / credential default to empty unless the test sets
// them via the Request returned (callers mutate before calling Match).
func httpReq(method, path string) *match.Request {
	u, _ := url.Parse("https://example.com" + path)
	return &match.Request{
		Family:  "https",
		Method:  method,
		URL:     u,
		Headers: http.Header{},
	}
}

func TestHTTPMatcherMethodAndPath(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		req       *match.Request
		want      bool
	}{
		{
			"empty condition → match-all",
			"",
			httpReq("GET", "/anything"),
			true,
		},
		{
			"method list, GET hit",
			"method in ['GET', 'HEAD']",
			httpReq("GET", "/x"),
			true,
		},
		{
			"method list, POST miss",
			"method in ['GET', 'HEAD']",
			httpReq("POST", "/x"),
			false,
		},
		{
			"method scalar",
			"method == 'DELETE'",
			httpReq("DELETE", "/x"),
			true,
		},
		{
			"path exact",
			"path == '/v1/refunds'",
			httpReq("POST", "/v1/refunds"),
			true,
		},
		{
			"path startsWith + endsWith for glob",
			"path.startsWith('/v1/charges/') && path.endsWith('/refund')",
			httpReq("POST", "/v1/charges/abc/refund"),
			true,
		},
		{
			"path list any-of",
			"path in ['/a', '/b']",
			httpReq("POST", "/b"),
			true,
		},
		{
			"path list miss",
			"path in ['/a', '/b']",
			httpReq("POST", "/c"),
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("https", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			if got := m.Match(tc.req); got != tc.want {
				t.Errorf("Match=%v want %v (condition=%q)", got, tc.want, tc.condition)
			}
		})
	}
}

func TestHTTPMatcherBodyJSON(t *testing.T) {
	m, err := facet.NewMatcher("https", "method == 'PATCH' && body_json.archived == true")
	if err != nil {
		t.Fatal(err)
	}
	req := httpReq("PATCH", "/v1/pages/abc")
	req.Body = []byte(`{"archived":true,"title":"x"}`)
	if !m.Match(req) {
		t.Errorf("expected body_json subset match")
	}
	req.Body = []byte(`{"archived":false,"title":"x"}`)
	if m.Match(req) {
		t.Errorf("expected body_json mismatch")
	}
}
