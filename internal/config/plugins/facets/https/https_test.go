package https_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"

	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/https"
)

// httpReq builds a minimal Request for the HTTP matcher tests.
// Header / body / credential default to empty unless the test sets
// them via the Request returned (callers mutate before calling Match).
func httpReq(method, path string) *match.Request {
	u, _ := url.Parse("https://example.com" + path)
	return &match.Request{
		Family:  "http",
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
			"http.method in ['GET', 'HEAD']",
			httpReq("GET", "/x"),
			true,
		},
		{
			"method list, POST miss",
			"http.method in ['GET', 'HEAD']",
			httpReq("POST", "/x"),
			false,
		},
		{
			"method scalar",
			"http.method == 'DELETE'",
			httpReq("DELETE", "/x"),
			true,
		},
		{
			"path exact",
			"http.path == '/v1/refunds'",
			httpReq("POST", "/v1/refunds"),
			true,
		},
		{
			"path startsWith + endsWith for glob",
			"http.path.startsWith('/v1/charges/') && http.path.endsWith('/refund')",
			httpReq("POST", "/v1/charges/abc/refund"),
			true,
		},
		{
			"path list any-of",
			"http.path in ['/a', '/b']",
			httpReq("POST", "/b"),
			true,
		},
		{
			"path list miss",
			"http.path in ['/a', '/b']",
			httpReq("POST", "/c"),
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("http", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			if got := m.Match(tc.req).Result; got != match.ResultOf(tc.want) {
				t.Errorf("Match=%v want %v (condition=%q)", got, match.ResultOf(tc.want), tc.condition)
			}
		})
	}
}

// TestHTTPMatcherMethodCaseInsensitive locks in that the matcher
// normalizes the want-side string literal of a method comparison to
// lowercase at rule-load time. Without that normalization a rule
// written as `http.method == "POST"` would silently never match,
// because the activation always reports `method = "post"`.
func TestHTTPMatcherMethodCaseInsensitive(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		method    string
		want      bool
	}{
		{"uppercase want, uppercase got", `http.method == 'POST'`, "POST", true},
		{"uppercase want, lowercase got", `http.method == 'POST'`, "post", true},
		{"lowercase want, uppercase got", `http.method == 'post'`, "POST", true},
		{"mixed-case want, uppercase got", `http.method == 'Post'`, "POST", true},
		{"!= uppercase, GET got",
			`http.method != 'POST'`, "GET", true},
		{"!= uppercase, POST got",
			`http.method != 'POST'`, "POST", false},
		{"in uppercase list, lowercase got",
			`http.method in ['GET', 'POST']`, "post", true},
		{"in uppercase list, miss",
			`http.method in ['GET', 'POST']`, "PUT", false},
		{"in mixed-case list",
			`http.method in ['Get', 'Post', 'put']`, "POST", true},
		{"startsWith uppercase",
			`http.method.startsWith('PO')`, "POST", true},
		{"endsWith uppercase",
			`http.method.endsWith('ST')`, "POST", true},
		{"reversed equality (literal LHS)",
			`'POST' == http.method`, "POST", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("http", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			if got := m.Match(httpReq(tc.method, "/x")).Result; got != match.ResultOf(tc.want) {
				t.Errorf("Match=%v want %v (condition=%q method=%q)", got, match.ResultOf(tc.want), tc.condition, tc.method)
			}
		})
	}
}

func TestHTTPMatcherBodyJSON(t *testing.T) {
	m, err := facet.NewMatcher("http", "http.method == 'PATCH' && http.body_json.archived == true")
	if err != nil {
		t.Fatal(err)
	}
	req := httpReq("PATCH", "/v1/pages/abc")
	req.Body = []byte(`{"archived":true,"title":"x"}`)
	if m.Match(req).Result != match.Matched {
		t.Errorf("expected body_json subset match")
	}
	req.Body = []byte(`{"archived":false,"title":"x"}`)
	if got := m.Match(req).Result; got != match.NoMatch {
		t.Errorf("expected body_json mismatch, got %v", got)
	}
}

// TestHTTPMatcherBodyJSONMissingFieldUnevaluable pins strict-mode
// fail-closed evaluation: selecting a body_json field the payload
// doesn't carry is a CEL eval error, which surfaces as Unevaluable
// (the dispatcher synthesizes a deny) instead of silently
// no-matching — silent no-match would let a deny rule fail open.
// Rules with optional fields must guard with has().
func TestHTTPMatcherBodyJSONMissingFieldUnevaluable(t *testing.T) {
	m, err := facet.NewMatcher("http", "http.body_json.archived == true")
	if err != nil {
		t.Fatal(err)
	}
	req := httpReq("PATCH", "/v1/pages/abc")
	req.Body = []byte(`{"title":"x"}`)
	if got := m.Match(req).Result; got != match.Unevaluable {
		t.Errorf("missing field: Match=%v, want Unevaluable", got)
	}
	// Empty / non-JSON bodies parse to an empty object — same deal.
	req.Body = nil
	if got := m.Match(req).Result; got != match.Unevaluable {
		t.Errorf("empty body: Match=%v, want Unevaluable", got)
	}
}

// TestHTTPMatcherBodyJSONHasGuard pins the has() escape hatch on a
// fully captured body: presence-testing a missing key is false, not
// an error, so the guarded condition cleanly no-matches and the
// rule keeps working for payloads where the field is optional.
func TestHTTPMatcherBodyJSONHasGuard(t *testing.T) {
	m, err := facet.NewMatcher("http", "has(http.body_json.archived) && http.body_json.archived == true")
	if err != nil {
		t.Fatal(err)
	}
	req := httpReq("PATCH", "/v1/pages/abc")
	req.Body = []byte(`{"title":"x"}`)
	if got := m.Match(req).Result; got != match.NoMatch {
		t.Errorf("guarded missing field: Match=%v, want NoMatch", got)
	}
	req.Body = []byte(`{"archived":true}`)
	if got := m.Match(req).Result; got != match.Matched {
		t.Errorf("guarded present field: Match=%v, want Matched", got)
	}
}

// TestHTTPMatcherTruncatedBodyUnknown pins the viral-unknown
// contract on a Truncated request: http.body / http.body_json are
// marked CEL-unknown, so a condition whose outcome depends on the
// capped bytes is Unevaluable — and has() cannot rescue it, because
// the presence test itself is unknown (whatever was cut off might
// have carried the key). Conditions that resolve through &&/||
// absorption still evaluate honestly.
func TestHTTPMatcherTruncatedBodyUnknown(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		method    string
		want      match.Result
	}{
		{"body contains", "http.body.contains('drop')", "POST", match.Unevaluable},
		{"body_json field", "http.body_json.archived == true", "POST", match.Unevaluable},
		{"has() is unknown too", "has(http.body_json.archived) && http.body_json.archived == true", "POST", match.Unevaluable},
		{"absorbed by false &&", "http.method == 'post' && http.body.contains('drop')", "GET", match.NoMatch},
		{"absorbed by true ||", "http.method == 'get' || http.body.contains('drop')", "GET", match.Matched},
		{"method only — unaffected", "http.method == 'get'", "GET", match.Matched},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("http", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			req := httpReq(tc.method, "/x")
			req.Body = []byte(`{"archived":true}`) // whatever fit before the cap
			req.Truncated = true
			if got := m.Match(req).Result; got != tc.want {
				t.Errorf("Match=%v want %v (condition=%q)", got, tc.want, tc.condition)
			}
		})
	}
}
