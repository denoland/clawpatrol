package facet_test

import (
	"reflect"
	"testing"

	"github.com/denoland/clawpatrol/config/facet"

	// Pull in the built-in facets so Lookup resolves the families
	// the containment registry references.
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

// TestParents documents the family-containment registry as it stands
// today. Updates to the registry should land here as well so the
// containment graph is reviewable in one place.
func TestParents(t *testing.T) {
	cases := []struct {
		family string
		want   []string
	}{
		{"http", nil},
		{"sql", nil},
		{"k8s", []string{"http"}},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			got := facet.Parents(tc.family)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Parents(%q)=%v, want %v", tc.family, got, tc.want)
			}
		})
	}
}

// TestAncestors locks in the transitive-parent order: with a single
// parent today the result is just `[http]`, but the contract is that
// ancestors precede the leaf and are dedupe'd. Multi-parent shapes
// will land here when they materialize.
func TestAncestors(t *testing.T) {
	if got := facet.Ancestors("k8s"); !reflect.DeepEqual(got, []string{"http"}) {
		t.Errorf("Ancestors(k8s)=%v, want [http]", got)
	}
	if got := facet.Ancestors("http"); got != nil {
		t.Errorf("Ancestors(http)=%v, want nil", got)
	}
}
