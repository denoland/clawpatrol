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
	if got := r.ActivationMap(); got != nil {
		t.Errorf("nil request: ActivationMap should yield nil, got %v", got)
	}
}

// TestActivationMapDoublesAsCache locks in the unified design where
// ActivationMap and the facet activation cache are the same map.
// facet.Compose's build closure passes the map into each AddActivation
// hook; a hook that wrote to it via act["http"]=fields must be
// observable to a subsequent CachedActivation("http") on the same
// Request, and vice versa. Regression test for the rework that
// merged the two storages — if they ever drift apart we'd silently
// reintroduce the per-Match map allocation the rework eliminated.
func TestActivationMapDoublesAsCache(t *testing.T) {
	r := &match.Request{}
	act := r.ActivationMap()
	if act == nil {
		t.Fatal("ActivationMap should lazy-init a non-nil map")
	}
	act["http"] = "via-act-map"
	if got := r.CachedActivation("http"); got != "via-act-map" {
		t.Errorf("CachedActivation should observe writes through ActivationMap; got %v", got)
	}
	r.SetCachedActivation("k8s", "via-setter")
	if got := act["k8s"]; got != "via-setter" {
		t.Errorf("SetCachedActivation should write into the shared ActivationMap; got %v", got)
	}
	r.ResetActivationCache()
	// After reset, r drops its reference to the previous map.
	// CachedActivation should see no entries, and ActivationMap
	// re-init must produce a fresh map (verified below).
	if got := r.CachedActivation("http"); got != nil {
		t.Errorf("ResetActivationCache should clear the map; got %v", got)
	}
	if r.ActivationMap() == nil {
		t.Error("ActivationMap should still re-init after reset")
	}
}
