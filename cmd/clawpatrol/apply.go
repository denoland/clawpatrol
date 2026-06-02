package main

// `clawpatrol apply` and `clawpatrol config history`.
//
// apply is the audited, validated path for changing a gateway's config.
// It loads + compiles the target file (the same pipeline the daemon runs
// at startup, so an invalid config is rejected before it can reach a
// running gateway), shows a semantic diff against the last applied
// version, and on confirmation rewrites the file atomically and records
// a version row. The running gateway's file watcher then reloads.
//
// "Semantic" diff: each config block is rendered through config's
// deterministic Emit hooks (see config.PolicyDigest) and compared by
// name, so reordering blocks or editing a comment shows as no change —
// only a real change to a block's content does.

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
)

// applyTimeFormat matches the repo-wide timestamp convention
// (yyyy-MM-dd HH:mm:ss.SSS, 24-hour, locale-independent).
const applyTimeFormat = "2006-01-02 15:04:05.000"

// runApply is the `clawpatrol apply <config.hcl>` entry point.
func runApply(args []string) {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	autoApprove := fs.Bool("y", false, "apply without the interactive confirmation prompt")
	by := fs.String("by", "", "who is applying (default: $SUDO_USER, then $USER)")
	note := fs.String("note", "", "optional note recorded with this version")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: clawpatrol apply [-y] [--by who] [--note text] <config.hcl>")
		os.Exit(2)
	}
	path := rest[0]

	// Same validation the daemon does at startup, plus external-plugin
	// schema verification — an invalid config never gets recorded or
	// activated.
	mgr := extplugin.New(nil)
	defer mgr.Stop()
	config.SetPluginLoader(mgr)
	gw, cp, err := loadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply: %s: %v\n", path, err)
		os.Exit(1)
	}
	if d := mgr.Verify(); d.HasErrors() {
		fmt.Fprintf(os.Stderr, "apply: %s: %s\n", path, d.Error())
		os.Exit(1)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply: read %s: %v\n", path, err)
		os.Exit(1)
	}
	revision := revisionForBytes(raw)

	stateDir := resolveStateDir(gw)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "apply: state dir: %v\n", err)
		os.Exit(1)
	}
	db, err := OpenDB(filepath.Join(stateDir, "clawpatrol.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply: open db: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	latest, hasLatest, err := latestConfigVersion(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply: read history: %v\n", err)
		os.Exit(1)
	}

	// Build the semantic diff against the last applied version.
	newDigest := config.PolicyDigest(gw)
	var oldDigest map[string]string
	if hasLatest {
		if oldGw, diags := config.LoadBytes(latest.Content, "applied.hcl"); !diags.HasErrors() {
			oldDigest = config.PolicyDigest(oldGw)
		}
	}
	d := diffDigests(oldDigest, newDigest)

	if hasLatest && latest.Revision == revision {
		fmt.Printf("no changes — config already at revision %s\n", shortRev(revision))
		return
	}

	fmt.Printf("config: %s\n", path)
	fmt.Printf("revision: %s  (%d endpoints, %d profiles)\n", shortRev(revision), len(cp.Endpoints), len(cp.Profiles))
	if hasLatest {
		fmt.Printf("last applied: %s by %s at %s\n",
			shortRev(latest.Revision), orUnknown(latest.AppliedBy), time.Unix(0, latest.AppliedNs).Format(applyTimeFormat))
	} else {
		fmt.Println("last applied: (none — this is the first recorded version)")
	}
	fmt.Println()
	d.render(os.Stdout)
	fmt.Println()

	if !*autoApprove {
		if !confirm(fmt.Sprintf("Apply this config to %s?", path)) {
			fmt.Println("aborted.")
			return
		}
	}

	// Rewrite atomically so the running gateway never reads a half-written
	// file, and so the mtime bump triggers its watcher to reload.
	if err := writeFileAtomic(path, raw); err != nil {
		fmt.Fprintf(os.Stderr, "apply: write %s: %v\n", path, err)
		os.Exit(1)
	}

	who := resolveApplier(*by)
	rev, inserted, err := recordConfigVersion(db, raw, gw.SchemaVersion, who, *note)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply: record version: %v\n", err)
		os.Exit(1)
	}
	if inserted {
		fmt.Printf("applied: revision %s recorded by %s\n", shortRev(rev), who)
	} else {
		fmt.Printf("applied: revision %s (already recorded)\n", shortRev(rev))
	}
}

// digestDiff is the categorized result of comparing two PolicyDigests.
type digestDiff struct {
	added   []string
	removed []string
	changed []string
}

func (d digestDiff) empty() bool {
	return len(d.added) == 0 && len(d.removed) == 0 && len(d.changed) == 0
}

func (d digestDiff) render(w bufWriter) {
	if d.empty() {
		fmt.Fprintln(w, "no semantic changes")
		return
	}
	fmt.Fprintf(w, "changes: +%d  -%d  ~%d\n", len(d.added), len(d.removed), len(d.changed))
	for _, k := range d.added {
		fmt.Fprintf(w, "  + %s\n", k)
	}
	for _, k := range d.removed {
		fmt.Fprintf(w, "  - %s\n", k)
	}
	for _, k := range d.changed {
		fmt.Fprintf(w, "  ~ %s\n", k)
	}
}

// diffDigests compares two block digests by key. Keys present only in
// new are added, only in old are removed, in both with differing
// canonical HCL are changed. Each category is sorted for stable output.
func diffDigests(oldD, newD map[string]string) digestDiff {
	var d digestDiff
	for k, nv := range newD {
		ov, ok := oldD[k]
		if !ok {
			d.added = append(d.added, k)
			continue
		}
		if ov != nv {
			d.changed = append(d.changed, k)
		}
	}
	for k := range oldD {
		if _, ok := newD[k]; !ok {
			d.removed = append(d.removed, k)
		}
	}
	sort.Strings(d.added)
	sort.Strings(d.removed)
	sort.Strings(d.changed)
	return d
}

// runConfig dispatches `clawpatrol config <subcommand>`.
func runConfig(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: clawpatrol config history <config.hcl>")
		os.Exit(2)
	}
	switch args[0] {
	case "history":
		runConfigHistory(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown config subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: clawpatrol config history <config.hcl>")
		os.Exit(2)
	}
}

// runConfigHistory lists recorded config versions. The config path is
// used only to resolve the state dir (and thus the DB) — it is not
// re-parsed for policy.
func runConfigHistory(args []string) {
	fs := flag.NewFlagSet("config history", flag.ExitOnError)
	limit := fs.Int("limit", 20, "max versions to show (0 = all)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: clawpatrol config history [--limit N] <config.hcl>")
		os.Exit(2)
	}
	gw, _, err := loadConfig(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "config history: %s: %v\n", rest[0], err)
		os.Exit(1)
	}
	stateDir := resolveStateDir(gw)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "config history: state dir: %v\n", err)
		os.Exit(1)
	}
	db, err := OpenDB(filepath.Join(stateDir, "clawpatrol.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "config history: open db: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	versions, err := listConfigVersions(db, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config history: %v\n", err)
		os.Exit(1)
	}
	if len(versions) == 0 {
		fmt.Println("no config versions recorded yet")
		return
	}
	for _, v := range versions {
		ts := time.Unix(0, v.AppliedNs).Format(applyTimeFormat)
		line := fmt.Sprintf("%s  %s  schema=%d  by %s", ts, shortRev(v.Revision), v.SchemaVersion, orUnknown(v.AppliedBy))
		if v.Note != "" {
			line += "  — " + v.Note
		}
		fmt.Println(line)
	}
}

// --- helpers -------------------------------------------------------

// bufWriter is the minimal io.Writer surface render needs; aliased so
// the signature reads clearly and tests can pass a *strings.Builder.
type bufWriter = interface{ Write([]byte) (int, error) }

func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// resolveApplier picks the recorded identity: explicit --by, then
// $SUDO_USER (apply is usually run as root on the gateway), then $USER.
func resolveApplier(by string) string {
	if by != "" {
		return by
	}
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

// confirm prompts on stderr and reads a yes/no from stdin.
func confirm(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

// writeFileAtomic writes content to a temp file in the same directory
// and renames it over path, preserving the existing file mode (or 0600
// for a new file — the config may hold authkeys / secrets). The
// same-dir temp keeps the rename atomic (no cross-device move).
func writeFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".clawpatrol-apply-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
