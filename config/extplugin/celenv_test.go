package extplugin

import (
	"testing"

	"github.com/denoland/clawpatrol/config/match"
)

// TestPluginFacetMatcherUnparseableBinding pins the CEL `unparseable`
// binding plugin facet conditions get from newPluginFacetMatcher.
// A rule that reads `unparseable` reports InspectsUnparseableFacet()
// = true, so the dispatcher's fail-closed gate synth-denies on
// Unparseable=true requests; a rule that doesn't read it stays a
// no-op for the gate. Mirrors the built-in sql facet's
// unparseablePaths declaration.
func TestPluginFacetMatcherUnparseableBinding(t *testing.T) {
	t.Run("reads_unparseable_marks_facet", func(t *testing.T) {
		m, err := newPluginFacetMatcher("smtp", "smtp.verb == 'mail_from' || unparseable", nil)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if !m.InspectsUnparseableFacet() {
			t.Fatalf("InspectsUnparseableFacet = false, want true (condition reads `unparseable`)")
		}
	})

	t.Run("no_read_no_inspection", func(t *testing.T) {
		m, err := newPluginFacetMatcher("smtp", "smtp.verb == 'mail_from'", nil)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if m.InspectsUnparseableFacet() {
			t.Fatalf("InspectsUnparseableFacet = true, want false (condition reads no parser-derived facet)")
		}
	})

	t.Run("unparseable_binding_is_readable", func(t *testing.T) {
		// `unparseable` evaluates to the request's flag — a rule that
		// gates allow purely on the bool fires when the plugin set
		// EvaluateAction.unparseable=true.
		m, err := newPluginFacetMatcher("smtp", "unparseable", nil)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		// Unparseable=true → condition true.
		if !m.Match(&match.Request{Family: "smtp", Meta: map[string]any{}, Unparseable: true}) {
			t.Errorf("Match(Unparseable=true) = false, want true")
		}
		// Unparseable=false → condition false.
		if m.Match(&match.Request{Family: "smtp", Meta: map[string]any{}, Unparseable: false}) {
			t.Errorf("Match(Unparseable=false) = true, want false")
		}
	})
}
