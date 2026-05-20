package facet_test

import (
	"reflect"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/facet"

	// Pull in the built-in facets so Lookup resolves the families
	// the composition registry references.
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// TestFacets documents the family→facets composition registry as it
// stands today. Updates to the registry should land here as well so
// the composition is reviewable in one place.
func TestFacets(t *testing.T) {
	cases := []struct {
		family string
		want   []string
	}{
		{"http", []string{"http"}},
		{"sql", []string{"sql"}},
		{"k8s", []string{"http", "k8s"}},
		// Unregistered family falls back to [family] — adds at
		// least its own eponymous facet.
		{"unknown", []string{"unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			got := facet.Facets(tc.family)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Facets(%q)=%v, want %v", tc.family, got, tc.want)
			}
		})
	}
}
