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
		name string
		raw  map[string]any
		req  *match.Request
		want bool
	}{
		{
			"empty match → match-all",
			map[string]any{},
			httpReq("GET", "/anything"),
			true,
		},
		{
			"method list, GET hit",
			map[string]any{"method": []any{"GET", "HEAD"}},
			httpReq("GET", "/x"),
			true,
		},
		{
			"method list, POST miss",
			map[string]any{"method": []any{"GET", "HEAD"}},
			httpReq("POST", "/x"),
			false,
		},
		{
			"method scalar, case-insensitive",
			map[string]any{"method": "delete"},
			httpReq("DELETE", "/x"),
			true,
		},
		{
			"path glob",
			map[string]any{"path": "/v1/refunds"},
			httpReq("POST", "/v1/refunds"),
			true,
		},
		{
			"path glob with wildcard",
			map[string]any{"path": "/v1/charges/*/refund"},
			httpReq("POST", "/v1/charges/abc/refund"),
			true,
		},
		{
			"path list any-of",
			map[string]any{"path": []any{"/a", "/b"}},
			httpReq("POST", "/b"),
			true,
		},
		{
			"path list miss",
			map[string]any{"path": []any{"/a", "/b"}},
			httpReq("POST", "/c"),
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("https", tc.raw)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			if got := m.Match(tc.req); got != tc.want {
				t.Errorf("Match=%v want %v (raw=%v req=%v)", got, tc.want, tc.raw, tc.req)
			}
		})
	}
}

func TestHTTPMatcherCredential(t *testing.T) {
	m, err := facet.NewMatcher("https", map[string]any{
		"credential": "orb-prod-key",
		"method":     "POST",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httpReq("POST", "/v1/x")
	req.Credential = "orb-test-key"
	if m.Match(req) {
		t.Errorf("expected credential mismatch to fail; got match")
	}
	req.Credential = "orb-prod-key"
	if !m.Match(req) {
		t.Errorf("expected credential match; got no match")
	}
}

func TestHTTPMatcherBodyJSON(t *testing.T) {
	m, err := facet.NewMatcher("https", map[string]any{
		"method":    "PATCH",
		"body_json": map[string]any{"archived": true},
	})
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
