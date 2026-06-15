package extplugin

import (
	"fmt"
	"os"
	"path/filepath"
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

// lockEntry is one plugin's recorded approval.
type lockEntry struct {
	Name    string `hcl:"name,label"`
	Hash    string `hcl:"hash"`
	Network string `hcl:"network"`
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

// put records an approval and marks the store dirty.
func (s *lockStore) put(name, hash, network string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[name] = lockEntry{Name: name, Hash: hash, Network: network}
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
		"# Each block records a plugin's binary hash and the approved",
		"# permissions. An upgrade that escalates beyond the recorded set",
		"# fails closed until re-approved (clawpatrol plugins approve <name>).",
	))
	body.AppendNewline()
	for _, n := range names {
		e := s.entries[n]
		blk := body.AppendNewBlock("plugin", []string{n})
		blk.Body().SetAttributeValue("hash", cty.StringVal(e.Hash))
		blk.Body().SetAttributeValue("network", cty.StringVal(e.Network))
		body.AppendNewline()
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, f.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
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
