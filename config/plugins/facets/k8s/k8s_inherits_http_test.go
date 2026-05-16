package k8s_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	k8sfacet "github.com/denoland/clawpatrol/config/plugins/facets/k8s"
)

// TestK8sMatcherInheritsHTTPFacets locks in family-containment: a
// k8s_rule can reference http.* fields (method, path, headers) in
// addition to its native k8s.* fields, because a k8s action is an
// HTTPS request underneath and carries both sets of bindings.
func TestK8sMatcherInheritsHTTPFacets(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		want      bool
	}{
		{
			name:      "http.method on k8s rule",
			condition: "http.method == 'POST'",
			want:      true,
		},
		{
			name:      "http.path on k8s rule",
			condition: "http.path == '/api/v1/namespaces/default/pods'",
			want:      true,
		},
		{
			name:      "mixed http and k8s predicate",
			condition: "k8s.verb == 'create' && http.method == 'POST'",
			want:      true,
		},
		{
			name:      "http header on k8s rule",
			condition: "'application/json' in http.headers['Content-Type']",
			want:      true,
		},
		{
			name:      "mismatch on http facet",
			condition: "http.method == 'DELETE'",
			want:      false,
		},
	}
	u, _ := url.Parse("/api/v1/namespaces/default/pods")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("k8s", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			req := &match.Request{
				Family:  "k8s",
				Method:  "POST",
				URL:     u,
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Meta:    &k8sfacet.Meta{Verb: "create", Resource: "pods", Namespace: "default"},
			}
			if got := m.Match(req); got != tc.want {
				t.Errorf("Match=%v want %v (condition=%q)", got, tc.want, tc.condition)
			}
		})
	}
}

// TestK8sMatcherRejectsSqlFacets locks in one-way containment: a
// k8s_rule referencing sql.* fields fails to compile, because sql is
// not in k8s's ancestor chain.
func TestK8sMatcherRejectsSqlFacets(t *testing.T) {
	_, err := facet.NewMatcher("k8s", "sql.verb == 'select'")
	if err == nil {
		t.Fatalf("expected compile error for k8s rule reading sql.verb")
	}
}

// TestHTTPMatcherRejectsK8sFacets locks in that containment is
// one-way: an http_rule referencing k8s.* fails to compile, because
// http sits at the root of the containment registry and inherits
// from nothing.
func TestHTTPMatcherRejectsK8sFacets(t *testing.T) {
	_, err := facet.NewMatcher("http", "k8s.verb == 'create'")
	if err == nil {
		t.Fatalf("expected compile error for http rule reading k8s.verb")
	}
}

// TestK8sMatcherBodyTruncationFailsClosed locks in that http.body /
// http.body_json inherit the truncatable-fail-closed contract for
// k8s rules too: a k8s rule whose CEL condition reads either should
// report InspectsTruncatableFacet() == true, so the dispatcher can
// synthesize a deny on a truncated request.
func TestK8sMatcherBodyTruncationFailsClosed(t *testing.T) {
	m, err := facet.NewMatcher("k8s", "http.body.contains('secret')")
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if !m.InspectsTruncatableFacet() {
		t.Fatalf("k8s rule reading http.body should report InspectsTruncatableFacet() == true")
	}
	// A k8s rule that only reads native k8s facets must NOT fail-close
	// on truncation — its predicate is body-independent.
	plain, err := facet.NewMatcher("k8s", "k8s.verb == 'create'")
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if plain.InspectsTruncatableFacet() {
		t.Fatalf("k8s rule reading only k8s.verb must not be marked truncatable")
	}
}
