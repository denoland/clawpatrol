package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestDocReferenceUpToDate fails when site/doc/15-config-reference.md
// drifts from what docgen produces against the current source. Run
// `go run ./tools/docgen -out site/doc/15-config-reference.md` to fix.
func TestDocReferenceUpToDate(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	idx, err := indexDocs(root)
	if err != nil {
		t.Fatalf("indexDocs: %v", err)
	}
	got, err := render(idx)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	want, err := os.ReadFile(filepath.Join(root, "site/doc/15-config-reference.md"))
	if err != nil {
		t.Fatalf("read committed reference: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf(`site/doc/15-config-reference.md is stale.

Run:
    go run ./tools/docgen -out site/doc/15-config-reference.md

then commit the result.`)
	}
}

// repoRoot walks up from the test's working directory until it finds
// a go.mod. tools/docgen lives at <root>/tools/docgen so the parent
// of cwd's parent is the root, but walking up is robust to refactors.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
