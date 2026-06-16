package extplugin

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// The permissions lockfile records, per plugin, the binary identity
// (sha256) and the approved low-risk capabilities (currently just
// network). It lives next to the gateway config (committed to VCS) so
// a permission change shows up as a reviewable diff. Capabilities a
// plugin declares in its manifest are recorded here on first load
// (trust-on-first-use); a later version that escalates beyond the
// recorded set fails closed until re-approved.

// LockfileName is the lockfile's basename, written alongside the
// gateway config.
const LockfileName = "clawpatrol.lock.hcl"

// lockEntry is one plugin's recorded approval. Hashes is a set of
// approved binary hashes — one per platform build of the approved
// version(s) — so a single committed lockfile covers a team's
// different OS/arch hosts (and a future distribution system can
// pre-populate every platform's hash for a release at once). A binary
// is approved iff its hash is in this set; they all share Network.
type lockEntry struct {
	Name    string   `hcl:"name,label"`
	Network string   `hcl:"network"`
	Hashes  []string `hcl:"hashes"`

	// Source/Version/Constraints are set for plugins fetched from a
	// GitHub release (empty for local-path plugins). Source is the
	// canonical "github.com/<owner>/<repo>"; Version is the resolved
	// release tag the gateway is pinned to; Constraints echoes the
	// operator's version constraint for review. The running gateway
	// loads exactly Version; `clawpatrol plugins update` rewrites it.
	Source      string `hcl:"source,optional"`
	Version     string `hcl:"version,optional"`
	Constraints string `hcl:"constraints,optional"`
}

// hasHash reports whether hash is in the entry's approved set.
func (e lockEntry) hasHash(hash string) bool {
	return slices.Contains(e.Hashes, hash)
}

type lockDoc struct {
	Plugins []lockEntry `hcl:"plugin,block"`
}

// lockStore is the in-memory view of the lockfile plus its path. A
// zero path (tests / config.LoadBytes with no file) means "no
// lockfile": lookups always miss and saves are no-ops, so plugins
// fall back to their manifest-declared capabilities without
// persistence or escalation checks.
type lockStore struct {
	mu       sync.Mutex
	path     string
	readOnly bool
	entries  map[string]lockEntry
	dirty    bool
}

func newLockStore() *lockStore {
	return &lockStore{entries: map[string]lockEntry{}}
}

// configure points the store at a lockfile path. readOnly stores
// resolve and report escalations but never write (used by
// `clawpatrol validate`).
func (s *lockStore) configure(path string, readOnly bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	s.readOnly = readOnly
}

// load (re)reads the lockfile from disk. A missing file is an empty
// store (first run). Called at the start of each load pass so manual
// edits and `plugins approve` are picked up.
func (s *lockStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = map[string]lockEntry{}
	s.dirty = false
	if s.path == "" {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", s.path, err)
	}
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCL(raw, s.path)
	if diags.HasErrors() {
		return fmt.Errorf("parse %s: %s", s.path, diags.Error())
	}
	var doc lockDoc
	if diags := gohcl.DecodeBody(f.Body, nil, &doc); diags.HasErrors() {
		return fmt.Errorf("decode %s: %s", s.path, diags.Error())
	}
	for _, e := range doc.Plugins {
		s.entries[e.Name] = e
	}
	return nil
}

func (s *lockStore) get(name string) (lockEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[name]
	return e, ok
}

// addHash records an approval: it adds hash to the plugin's approved
// set (preserving other platforms' hashes) and sets the approved
// network. The store is marked dirty only when something actually
// changes, so a steady-state load (operator override or fast-path
// re-approval of an already-recorded binary) doesn't rewrite the
// committed lockfile on every reload.
func (s *lockStore) addHash(name, hash, network string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[name]
	changed := e.Name != name || e.Network != network
	e.Name = name
	e.Network = network
	if !slices.Contains(e.Hashes, hash) {
		e.Hashes = append(e.Hashes, hash)
		sort.Strings(e.Hashes) // stable diffs
		changed = true
	}
	s.entries[name] = e
	if changed {
		s.dirty = true
	}
}

// setSource records the resolved GitHub source/version/constraints for a
// plugin (the binary hashes are recorded separately by addHash at load,
// or by an all-platform `plugins lock`). Marks dirty only on change.
func (s *lockStore) setSource(name, source, version, constraints string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[name]
	if e.Name == name && e.Source == source && e.Version == version && e.Constraints == constraints {
		return
	}
	// A version change re-pins the plugin: the recorded hashes belonged
	// to the old version's platform builds, so drop them — the new
	// version's hashes are recorded fresh by the caller (addHash / lock).
	if e.Version != version {
		e.Hashes = nil
	}
	e.Name = name
	e.Source = source
	e.Version = version
	e.Constraints = constraints
	s.entries[name] = e
	s.dirty = true
}

// active reports whether a lockfile is in use (a path is configured).
func (s *lockStore) active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path != ""
}

// save atomically writes the lockfile if it changed. No-op without a
// path, in read-only mode, or when nothing changed.
func (s *lockStore) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" || s.readOnly || !s.dirty {
		return nil
	}
	names := make([]string, 0, len(s.entries))
	for n := range s.entries {
		names = append(names, n)
	}
	sort.Strings(names)

	f := hclwrite.NewEmptyFile()
	body := f.Body()
	body.AppendUnstructuredTokens(commentTokens(
		"# clawpatrol plugin permission lockfile — generated; commit this file.",
		"# Each block records a plugin's approved permissions and the set of",
		"# approved binary hashes (one per platform build). An upgrade that",
		"# escalates beyond the recorded permissions fails closed until",
		"# re-approved (clawpatrol plugins approve <name>).",
	))
	body.AppendNewline()
	for _, n := range names {
		e := s.entries[n]
		blk := body.AppendNewBlock("plugin", []string{n})
		// Distribution provenance first (when set), then the permission
		// record, so a GitHub-sourced block reads source -> version ->
		// network -> hashes top to bottom.
		if e.Source != "" {
			blk.Body().SetAttributeValue("source", cty.StringVal(e.Source))
		}
		if e.Version != "" {
			blk.Body().SetAttributeValue("version", cty.StringVal(e.Version))
		}
		if e.Constraints != "" {
			blk.Body().SetAttributeValue("constraints", cty.StringVal(e.Constraints))
		}
		blk.Body().SetAttributeValue("network", cty.StringVal(e.Network))
		hashVals := make([]cty.Value, len(e.Hashes))
		for i, h := range e.Hashes {
			hashVals[i] = cty.StringVal(h)
		}
		if len(hashVals) > 0 {
			blk.Body().SetAttributeValue("hashes", cty.ListVal(hashVals))
		} else {
			blk.Body().SetAttributeValue("hashes", cty.ListValEmpty(cty.String))
		}
		body.AppendNewline()
	}

	// Write to a uniquely-named temp file in the same dir, then rename
	// over the target. A fixed ".tmp" name would let two concurrent
	// savers clobber each other's in-progress write before the rename;
	// CreateTemp gives each its own file so the rename is the only
	// shared step (and rename is atomic).
	dir := filepath.Dir(s.path)
	tmpf, err := os.CreateTemp(dir, LockfileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", s.path, err)
	}
	tmp := tmpf.Name()
	if _, err := tmpf.Write(f.Bytes()); err != nil {
		_ = tmpf.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := tmpf.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	// CreateTemp makes the file 0600; the lockfile is a committed,
	// non-secret artifact, so match the prior 0644.
	if err := os.Chmod(tmp, 0o644); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", s.path, err)
	}
	s.dirty = false
	return nil
}

// LockfilePathFor returns the lockfile path that sits beside the given
// gateway config file.
func LockfilePathFor(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), LockfileName)
}

func commentTokens(lines ...string) hclwrite.Tokens {
	var toks hclwrite.Tokens
	for _, l := range lines {
		toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenComment, Bytes: []byte(l + "\n")})
	}
	return toks
}
