package match_test

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config/match"
)

func TestActivationCacheRoundTrip(t *testing.T) {
	r := &match.Request{}
	if got := r.CachedActivation("http"); got != nil {
		t.Fatalf("fresh request should have empty cache, got %v", got)
	}
	type fakeFields struct{ k string }
	v := &fakeFields{k: "v"}
	r.SetCachedActivation("http", v)
	got := r.CachedActivation("http")
	if got == nil {
		t.Fatalf("cache should return stored value")
	}
	if got != any(v) {
		t.Fatalf("cache returned different pointer: %p vs %p", got, v)
	}
}

func TestActivationCacheResetClearsAllFacets(t *testing.T) {
	r := &match.Request{}
	r.SetCachedActivation("http", "h")
	r.SetCachedActivation("sql", "s")
	r.ResetActivationCache()
	if got := r.CachedActivation("http"); got != nil {
		t.Errorf("http cache should be cleared, got %v", got)
	}
	if got := r.CachedActivation("sql"); got != nil {
		t.Errorf("sql cache should be cleared, got %v", got)
	}
}

func TestActivationCacheTolerantOfNilReceiver(t *testing.T) {
	var r *match.Request
	// Must not panic on any of these — gateway code reaches the
	// match.Request through several layers and is tolerant of nil
	// requests in some early-validation paths.
	if got := r.CachedActivation("http"); got != nil {
		t.Errorf("nil request: CachedActivation should yield nil, got %v", got)
	}
	r.SetCachedActivation("http", "x") // must not panic
	r.ResetActivationCache()           // must not panic
}
