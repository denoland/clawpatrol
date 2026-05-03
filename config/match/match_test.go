package match_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/denoland/clawpatrol-go/config/match"
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
			m, err := match.New("https", tc.raw)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := m.Match(tc.req); got != tc.want {
				t.Errorf("Match=%v want %v (raw=%v req=%v)", got, tc.want, tc.raw, tc.req)
			}
		})
	}
}

func TestHTTPMatcherCredential(t *testing.T) {
	m, err := match.New("https", map[string]any{
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

func TestK8sMatcherNegationAndGlobs(t *testing.T) {
	m, err := match.New("k8s", map[string]any{
		"verb":     []any{"create", "update", "patch", "delete"},
		"name":     "!debug-*",
		"resource": []any{"!*/exec", "!*/attach", "!*/portforward"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		k8s  *match.K8sMeta
		want bool
	}{
		{"create non-debug pod", &match.K8sMeta{Verb: "create", Name: "prod-x", Resource: "pods"}, true},
		{"create debug pod", &match.K8sMeta{Verb: "create", Name: "debug-shell", Resource: "pods"}, false},
		{"create pods/exec", &match.K8sMeta{Verb: "create", Name: "prod-x", Resource: "pods/exec"}, false},
		{"get (verb mismatch)", &match.K8sMeta{Verb: "get", Name: "x", Resource: "pods"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &match.Request{Family: "k8s", K8s: tc.k8s}
			if got := m.Match(req); got != tc.want {
				t.Errorf("Match=%v want %v", got, tc.want)
			}
		})
	}
}

func TestK8sMatcherParams(t *testing.T) {
	m, err := match.New("k8s", map[string]any{
		"resource": []any{"pods/exec", "pods/attach"},
		"params":   map[string]any{"stdin": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &match.Request{
		Family: "k8s",
		K8s: &match.K8sMeta{
			Verb: "create", Resource: "pods/exec", Name: "x",
			Params: map[string]string{"stdin": "true"},
		},
	}
	if !m.Match(req) {
		t.Errorf("expected interactive exec to match")
	}
	req.K8s.Params = map[string]string{"stdin": "false"}
	if m.Match(req) {
		t.Errorf("expected non-interactive exec to NOT match")
	}
}

func TestSQLMatcherVerbAndTables(t *testing.T) {
	m, err := match.New("sql", map[string]any{
		"verb":   "select",
		"tables": []any{"github_identities", "tokens"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &match.Request{
		Family: "sql",
		SQL: &match.SQLMeta{
			Verb:   "select",
			Tables: []string{"users", "github_identities"},
		},
	}
	if !m.Match(req) {
		t.Errorf("expected select on github_identities to match")
	}
	req.SQL.Verb = "insert"
	if m.Match(req) {
		t.Errorf("expected verb mismatch to fail")
	}
}

func TestSQLMatcherStatementRegex(t *testing.T) {
	m, err := match.New("sql", map[string]any{
		"verb":            "select",
		"statement_regex": `(?i)\b(secret|password|token)\b`,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &match.Request{
		Family: "sql",
		SQL:    &match.SQLMeta{Verb: "select", Statement: "SELECT secret FROM vault"},
	}
	if !m.Match(req) {
		t.Errorf("expected regex hit on bare 'secret'")
	}
	// `_` is a word character, so \btoken\b should NOT match inside
	// "api_token" — confirms the regex isn't accidentally
	// substring-matching.
	req.SQL.Statement = "SELECT api_token FROM keys"
	if m.Match(req) {
		t.Errorf("expected no regex hit on api_token (word boundary)")
	}
}

func TestHTTPMatcherBodyJSON(t *testing.T) {
	m, err := match.New("https", map[string]any{
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
