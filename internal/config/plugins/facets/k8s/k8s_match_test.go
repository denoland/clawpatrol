package k8s_test

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	k8sfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/k8s"
)

// TestK8sMatcherVerbCaseInsensitive locks in that a rule written as
// `k8s.verb == "GET"` matches a list/get request even though the
// activation normalizes the got value to lowercase. CompileCondition
// lowercases the want-side string literals at rule-load time.
func TestK8sMatcherVerbCaseInsensitive(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		verb      string
		want      bool
	}{
		{"uppercase want, get got", "k8s.verb == 'GET'", "get", true},
		{"mixed-case want, get got", "k8s.verb == 'Get'", "get", true},
		{"uppercase list, watch got",
			"k8s.verb in ['WATCH', 'LIST']", "watch", true},
		{"uppercase list, create got",
			"k8s.verb in ['WATCH', 'LIST']", "create", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("k8s", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			req := &match.Request{Family: "k8s", Meta: &k8sfacet.Meta{Verb: tc.verb}}
			if got := m.Match(req).Result; got != match.ResultOf(tc.want) {
				t.Errorf("Match=%v want %v (condition=%q)", got, match.ResultOf(tc.want), tc.condition)
			}
		})
	}
}

func TestK8sMatcherNegationAndGlobs(t *testing.T) {
	m, err := facet.NewMatcher("k8s",
		"k8s.verb in ['create', 'update', 'patch', 'delete'] && !k8s.name.startsWith('debug-') "+
			"&& !k8s.resource.endsWith('/exec') && !k8s.resource.endsWith('/attach') && !k8s.resource.endsWith('/portforward')")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		meta *k8sfacet.Meta
		want bool
	}{
		{"create non-debug pod", &k8sfacet.Meta{Verb: "create", Name: "prod-x", Resource: "pods"}, true},
		{"create debug pod", &k8sfacet.Meta{Verb: "create", Name: "debug-shell", Resource: "pods"}, false},
		{"create pods/exec", &k8sfacet.Meta{Verb: "create", Name: "prod-x", Resource: "pods/exec"}, false},
		{"get (verb mismatch)", &k8sfacet.Meta{Verb: "get", Name: "x", Resource: "pods"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &match.Request{Family: "k8s", Meta: tc.meta}
			if got := m.Match(req).Result; got != match.ResultOf(tc.want) {
				t.Errorf("Match=%v want %v", got, match.ResultOf(tc.want))
			}
		})
	}
}

func TestK8sMatcherParams(t *testing.T) {
	m, err := facet.NewMatcher("k8s", "k8s.resource in ['pods/exec', 'pods/attach'] && k8s.params.stdin == 'true'")
	if err != nil {
		t.Fatal(err)
	}
	meta := &k8sfacet.Meta{
		Verb: "create", Resource: "pods/exec", Name: "x",
		Params: map[string]string{"stdin": "true"},
	}
	req := &match.Request{Family: "k8s", Meta: meta}
	if m.Match(req).Result != match.Matched {
		t.Errorf("expected interactive exec to match")
	}
	meta.Params = map[string]string{"stdin": "false"}
	if got := m.Match(req).Result; got != match.NoMatch {
		t.Errorf("expected non-interactive exec to NOT match, got %v", got)
	}
}

func TestK8sMatcherWatchVerbAndParams(t *testing.T) {
	m, err := facet.NewMatcher("k8s", "k8s.verb == 'watch' && k8s.resource == 'pods' && k8s.params.watch == 'true'")
	if err != nil {
		t.Fatal(err)
	}

	meta := &k8sfacet.Meta{
		Verb: "watch", Resource: "pods", Params: map[string]string{"watch": "true"},
	}
	req := &match.Request{Family: "k8s", Meta: meta}
	if m.Match(req).Result != match.Matched {
		t.Errorf("expected watch pod list to match")
	}
	meta.Verb = "list"
	if got := m.Match(req).Result; got != match.NoMatch {
		t.Errorf("expected plain list to miss watch rule, got %v", got)
	}
}
