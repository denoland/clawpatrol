package k8s_test

import (
	"testing"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	k8sfacet "github.com/denoland/clawpatrol/config/plugins/facets/k8s"
)

func TestK8sMatcherNegationAndGlobs(t *testing.T) {
	m, err := facet.NewMatcher("k8s", map[string]any{
		"verb":     []any{"create", "update", "patch", "delete"},
		"name":     "!debug-*",
		"resource": []any{"!*/exec", "!*/attach", "!*/portforward"},
	})
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
			if got := m.Match(req); got != tc.want {
				t.Errorf("Match=%v want %v", got, tc.want)
			}
		})
	}
}

func TestK8sMatcherParams(t *testing.T) {
	m, err := facet.NewMatcher("k8s", map[string]any{
		"resource": []any{"pods/exec", "pods/attach"},
		"params":   map[string]any{"stdin": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	meta := &k8sfacet.Meta{
		Verb: "create", Resource: "pods/exec", Name: "x",
		Params: map[string]string{"stdin": "true"},
	}
	req := &match.Request{Family: "k8s", Meta: meta}
	if !m.Match(req) {
		t.Errorf("expected interactive exec to match")
	}
	meta.Params = map[string]string{"stdin": "false"}
	if m.Match(req) {
		t.Errorf("expected non-interactive exec to NOT match")
	}
}

func TestK8sMatcherWatchVerbAndParams(t *testing.T) {
	m, err := facet.NewMatcher("k8s", map[string]any{
		"verb":     "watch",
		"resource": "pods",
		"params":   map[string]any{"watch": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}

	meta := &k8sfacet.Meta{
		Verb: "watch", Resource: "pods", Params: map[string]string{"watch": "true"},
	}
	req := &match.Request{Family: "k8s", Meta: meta}
	if !m.Match(req) {
		t.Errorf("expected watch pod list to match")
	}
	meta.Verb = "list"
	if m.Match(req) {
		t.Errorf("expected plain list to miss watch rule")
	}
}
