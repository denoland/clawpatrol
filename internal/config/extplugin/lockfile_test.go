package extplugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLockStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LockfileName)

	s := newLockStore()
	s.configure(path, false)
	if err := s.load(); err != nil { // missing file = empty
		t.Fatal(err)
	}
	if _, ok := s.get("x"); ok {
		t.Fatal("empty store returned an entry")
	}

	s.addHash("bravo", "sha256:bbb", "none")
	s.addHash("alpha", "sha256:aaa", "outbound")
	// A second platform build of alpha — both hashes must coexist.
	s.addHash("alpha", "sha256:aaa2", "outbound")
	s.addHash("alpha", "sha256:aaa", "outbound") // duplicate is a no-op
	if err := s.save(); err != nil {
		t.Fatal(err)
	}

	raw := readString(t, path)
	// Entries are sorted by name for stable diffs.
	if i, j := strings.Index(raw, `"alpha"`), strings.Index(raw, `"bravo"`); i < 0 || j < 0 || i > j {
		t.Fatalf("entries not sorted by name:\n%s", raw)
	}
	if !strings.Contains(raw, `"sha256:aaa"`) || !strings.Contains(raw, `"sha256:aaa2"`) ||
		!strings.Contains(raw, `"outbound"`) {
		t.Fatalf("alpha hashes not recorded:\n%s", raw)
	}

	// Reload into a fresh store.
	s2 := newLockStore()
	s2.configure(path, false)
	if err := s2.load(); err != nil {
		t.Fatal(err)
	}
	e, ok := s2.get("alpha")
	if !ok || e.Network != "outbound" || len(e.Hashes) != 2 ||
		!e.hasHash("sha256:aaa") || !e.hasHash("sha256:aaa2") {
		t.Fatalf("reloaded alpha = %+v, ok=%v", e, ok)
	}
}

func TestLockStoreSourceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LockfileName)
	s := newLockStore()
	s.configure(path, false)
	if err := s.load(); err != nil {
		t.Fatal(err)
	}
	s.setSource("gh", "github.com/acme/p", "v1.2.3", "~> 1.2", "abcdef123456", true)
	s.addHash("gh", "sha256:abc", "outbound")
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	raw := readString(t, path)
	for _, want := range []string{`source      = "github.com/acme/p"`, `version     = "v1.2.3"`, `commit      = "abcdef123456"`, `attested    = true`, `constraints = "~> 1.2"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("lockfile missing %q:\n%s", want, raw)
		}
	}

	s2 := newLockStore()
	s2.configure(path, false)
	if err := s2.load(); err != nil {
		t.Fatal(err)
	}
	e, ok := s2.get("gh")
	if !ok || e.Source != "github.com/acme/p" || e.Version != "v1.2.3" ||
		e.Constraints != "~> 1.2" || e.Commit != "abcdef123456" || !e.Attested ||
		e.Network != "outbound" || !e.hasHash("sha256:abc") {
		t.Fatalf("reloaded entry = %+v ok=%v", e, ok)
	}

	// A local-path plugin records no source/version (omitempty).
	s2.addHash("local", "sha256:zzz", "none")
	if err := s2.save(); err != nil {
		t.Fatal(err)
	}
	raw2 := readString(t, path)
	if strings.Contains(raw2, `source      = ""`) {
		t.Errorf("local plugin wrote an empty source attr:\n%s", raw2)
	}
}

func TestLockStoreReadOnlyNeverWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LockfileName)
	s := newLockStore()
	s.configure(path, true) // read-only
	_ = s.load()
	s.addHash("x", "sha256:1", "outbound")
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("read-only store wrote the lockfile (err=%v)", err)
	}
}

func TestLockStoreNoPathIsNoOp(t *testing.T) {
	s := newLockStore() // zero path
	if s.active() {
		t.Fatal("store with no path reports active")
	}
	s.addHash("x", "h", "none")
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
}

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
