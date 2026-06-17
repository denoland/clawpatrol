package extplugin

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

func TestNormalizeEgress(t *testing.T) {
	got := normalizeEgress([]string{
		"  API.Foo.com:443 ", "*.Bar.COM:443", "api.foo.com:443", "", "not a target",
	})
	want := []string{"*.bar.com:443", "api.foo.com:443", "not a target"}
	if !slices.Equal(got, want) {
		t.Fatalf("normalizeEgress = %v, want %v", got, want)
	}
}

func TestEgressEntryCovers(t *testing.T) {
	cases := []struct {
		pat, target string
		want        bool
	}{
		{"api.foo.com:443", "api.foo.com:443", true},    // exact == exact
		{"api.foo.com:443", "api.foo.com:80", false},    // port differs
		{"api.foo.com:443", "other.foo.com:443", false}, // exact != other exact
		{"*.foo.com:443", "api.foo.com:443", true},      // wildcard covers sub
		{"*.foo.com:443", "a.b.foo.com:443", true},      // multi-label sub
		{"*.foo.com:443", "foo.com:443", false},         // wildcard needs a label
		{"*.foo.com:443", "api.bar.com:443", false},     // different suffix
		{"*.com:443", "*.foo.com:443", true},            // broader wildcard covers narrower
		{"*.foo.com:443", "*.com:443", false},           // narrower does not cover broader
		{"*.foo.com:443", "*.foo.com:443", true},        // identical wildcard
		{"*.amazonaws.com:443", "s3.amazonaws.com:443", true},
	}
	for _, c := range cases {
		if got := egressEntryCovers(c.pat, c.target); got != c.want {
			t.Errorf("egressEntryCovers(%q, %q) = %v, want %v", c.pat, c.target, got, c.want)
		}
	}
}

func TestEgressBroadened(t *testing.T) {
	approved := []string{"*.foo.com:443", "api.bar.com:443"}
	// Declared entirely within approved: nothing broadened.
	if b := egressBroadened(approved, []string{"a.foo.com:443", "api.bar.com:443"}); len(b) != 0 {
		t.Fatalf("unexpected broadening %v", b)
	}
	// A new destination none of the approved entries cover.
	b := egressBroadened(approved, []string{"a.foo.com:443", "evil.com:443"})
	if !slices.Equal(b, []string{"evil.com:443"}) {
		t.Fatalf("broadened = %v, want [evil.com:443]", b)
	}
	// A broader port on an otherwise-covered host is broadening.
	if b := egressBroadened(approved, []string{"a.foo.com:8443"}); !slices.Equal(b, []string{"a.foo.com:8443"}) {
		t.Fatalf("port broadening = %v", b)
	}
}

func mfWithEgress(egress ...string) *pb.ManifestResponse {
	return &pb.ManifestResponse{
		Name:         "p",
		Capabilities: &pb.PluginCapabilities{Egress: egress},
	}
}

// newEgressTestManager wires a Manager with a configured lockfile for the
// resolveEgress trust-on-first-use / broadening tests.
func newEgressTestManager(t *testing.T) *Manager {
	t.Helper()
	m := New(nil)
	m.lock.configure(filepath.Join(t.TempDir(), LockfileName), false)
	if err := m.lock.load(); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestResolveEgressTOFUAndBroadening(t *testing.T) {
	m := newEgressTestManager(t)
	sp := config.PluginSource{Name: "p", Source: "github.com/o/p"}

	// resolveEgress reads the lockfile entry as it was at the start of the
	// pass (the snapshot Manager.Start captures before resolveNetwork's
	// addHash). Mirror that here.
	call := func(hash string, egress ...string) ([]string, string, error) {
		prior, priorRec := m.lock.get(sp.Name)
		return m.resolveEgress(sp, prior, priorRec, hash, egressFromManifest(mfWithEgress(egress...)))
	}

	// First load records the declared set (trust on first use).
	got, warn, err := call("sha256:v1", "*.foo.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"*.foo.com:443"}) || warn == "" {
		t.Fatalf("first load = %v warn=%q", got, warn)
	}
	if e, _ := m.lock.get("p"); !slices.Equal(e.Egress, []string{"*.foo.com:443"}) {
		t.Fatalf("recorded egress = %v", e.Egress)
	}

	// Same binary again: fast path returns the recorded set, no warn.
	if got, warn, err := call("sha256:v1", "*.foo.com:443"); err != nil ||
		warn != "" || !slices.Equal(got, []string{"*.foo.com:443"}) {
		t.Fatalf("fast path = %v warn=%q err=%v", got, warn, err)
	}

	// A new binary that broadens egress fails closed.
	_, _, err = call("sha256:v2", "*.foo.com:443", "evil.com:443")
	if err == nil || !strings.Contains(err.Error(), "broadens its network egress") {
		t.Fatalf("broadening err = %v, want fail-closed", err)
	}

	// A new binary within the approved set is allowed and (narrowing)
	// re-recorded.
	got, _, err = call("sha256:v3", "a.foo.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"a.foo.com:443"}) {
		t.Fatalf("narrowed load = %v", got)
	}
}

// TestResolveEgressRecordsAfterAddHash reproduces the load-time ordering in
// Manager.Start: resolveNetwork's addHash records the binary's hash before
// resolveEgress runs. On a first load resolveEgress must still record the
// declared egress — it keys off the pre-pass snapshot, not the live entry
// whose hash addHash just added. Regression: a fast path keyed on the live
// hash saw addHash's entry and silently dropped egress on every fresh
// lockfile, leaving the brokered-dial allow-list empty.
func TestResolveEgressRecordsAfterAddHash(t *testing.T) {
	m := newEgressTestManager(t)
	sp := config.PluginSource{Name: "p", Source: "github.com/o/p"}
	const hash = "sha256:v1"

	// Snapshot up front, exactly as Start does before resolveNetwork.
	prior, priorRec := m.lock.get(sp.Name)

	// resolveNetwork records the hash first.
	m.lock.addHash(sp.Name, hash, "none")

	got, warn, err := m.resolveEgress(sp, prior, priorRec, hash, egressFromManifest(mfWithEgress("*.amazonaws.com:443")))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"*.amazonaws.com:443"}) || warn == "" {
		t.Fatalf("first load after addHash = %v warn=%q, want egress recorded", got, warn)
	}
	if e, _ := m.lock.get("p"); !slices.Equal(e.Egress, []string{"*.amazonaws.com:443"}) {
		t.Fatalf("egress not persisted after addHash: %v", e.Egress)
	}
}

// TestResolveEgressRecordsDeferredFromInstall covers `plugins install` from a
// release without a signed static manifest: it records the binary hash but
// defers egress to the first real load. resolveEgress must record the
// manifest's declared egress on that load even though the hash is already
// approved, otherwise the brokered-dial allow-list stays empty.
func TestResolveEgressRecordsDeferredFromInstall(t *testing.T) {
	m := newEgressTestManager(t)
	sp := config.PluginSource{Name: "p", Source: "github.com/o/p"}
	const hash = "sha256:v1"

	// Simulate the lockfile install wrote: hash + network, no egress.
	m.lock.addHash(sp.Name, hash, "none")

	// First real load: the snapshot already has the hash but no egress.
	prior, priorRec := m.lock.get(sp.Name)
	got, warn, err := m.resolveEgress(sp, prior, priorRec, hash, egressFromManifest(mfWithEgress("*.amazonaws.com:443")))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"*.amazonaws.com:443"}) || warn == "" {
		t.Fatalf("deferred egress = %v warn=%q, want recorded", got, warn)
	}
	if e, _ := m.lock.get("p"); !slices.Equal(e.Egress, []string{"*.amazonaws.com:443"}) {
		t.Fatalf("deferred egress not persisted: %v", e.Egress)
	}
}

func TestResolveEgressNoLockfile(t *testing.T) {
	m := New(nil) // no lockfile configured
	sp := config.PluginSource{Name: "p", Source: "github.com/o/p"}
	prior, priorRec := m.lock.get(sp.Name)
	got, _, err := m.resolveEgress(sp, prior, priorRec, "sha256:x", egressFromManifest(mfWithEgress("*.foo.com:443")))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"*.foo.com:443"}) {
		t.Fatalf("no-lockfile egress = %v", got)
	}
}

func TestLockStoreEgressRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LockfileName)
	s := newLockStore()
	s.configure(path, false)
	if err := s.load(); err != nil {
		t.Fatal(err)
	}
	s.addHash("p", "sha256:abc", "none")
	s.setEgress("p", []string{"*.foo.com:443", "api.bar.com:443"})
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	raw := readString(t, path)
	if !strings.Contains(raw, `"*.foo.com:443"`) || !strings.Contains(raw, `"api.bar.com:443"`) {
		t.Fatalf("egress not recorded:\n%s", raw)
	}

	s2 := newLockStore()
	s2.configure(path, false)
	if err := s2.load(); err != nil {
		t.Fatal(err)
	}
	e, ok := s2.get("p")
	if !ok || !slices.Equal(e.Egress, []string{"*.foo.com:443", "api.bar.com:443"}) {
		t.Fatalf("reloaded egress = %+v ok=%v", e.Egress, ok)
	}

	// setEgress to the same set is a no-op (not dirty); to a new set marks
	// dirty.
	s2.dirty = false
	s2.setEgress("p", []string{"*.foo.com:443", "api.bar.com:443"})
	if s2.dirty {
		t.Fatal("identical setEgress marked dirty")
	}
	s2.setEgress("p", nil)
	if !s2.dirty {
		t.Fatal("clearing egress did not mark dirty")
	}
	if e, _ := s2.get("p"); e.Egress != nil {
		t.Fatalf("egress not cleared: %v", e.Egress)
	}
}
