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

	s.put("bravo", "sha256:bbb", "none")
	s.put("alpha", "sha256:aaa", "outbound")
	if err := s.save(); err != nil {
		t.Fatal(err)
	}

	raw := readString(t, path)
	// Entries are sorted by name for stable diffs.
	if i, j := strings.Index(raw, `"alpha"`), strings.Index(raw, `"bravo"`); i < 0 || j < 0 || i > j {
		t.Fatalf("entries not sorted by name:\n%s", raw)
	}
	if !strings.Contains(raw, `"sha256:aaa"`) || !strings.Contains(raw, `"outbound"`) {
		t.Fatalf("alpha not recorded:\n%s", raw)
	}

	// Reload into a fresh store.
	s2 := newLockStore()
	s2.configure(path, false)
	if err := s2.load(); err != nil {
		t.Fatal(err)
	}
	e, ok := s2.get("alpha")
	if !ok || e.Hash != "sha256:aaa" || e.Network != "outbound" {
		t.Fatalf("reloaded alpha = %+v, ok=%v", e, ok)
	}
}

func TestLockStoreReadOnlyNeverWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LockfileName)
	s := newLockStore()
	s.configure(path, true) // read-only
	_ = s.load()
	s.put("x", "sha256:1", "outbound")
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
	s.put("x", "h", "none")
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
