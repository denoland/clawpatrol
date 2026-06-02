package main

// `clawpatrol plan`, `clawpatrol apply`, `clawpatrol config history`,
// and `clawpatrol config unlock`.
//
// The state backend is config_versions in the gateway DB: its latest
// row is the deployed config and its id is the serial. This mirrors
// Terraform — the file passed to plan/apply is the *desired* config
// (like a .tf), the DB is the deployed state, and apply reconciles them
// under a lock.
//
//   plan   load + validate the file, diff it against the deployed
//          config, print. Lock-free, read-only.
//   apply  re-plan under an exclusive lock, confirm, compare-and-swap a
//          new version (rejecting a stale apply), release. The running
//          gateway polls the serial and reloads.
//
// "Semantic" diff: each config block is rendered through config's
// deterministic Emit hooks (config.PolicyDigest) and compared by name,
// so reordering blocks or editing a comment shows as no change — only a
// real change to a block's content does.

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
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

// loadDesired loads + compiles the file the operator wants to apply,
// running the same pipeline (including external-plugin verification)
// the daemon runs at startup. An invalid config is rejected here,
// before it can become deployed state. Returns the gateway, compiled
// policy, and raw bytes.
func loadDesired(path string) (*config.Gateway, *config.CompiledPolicy, []byte, error) {
	mgr := extplugin.New(nil)
	defer mgr.Stop()
	config.SetPluginLoader(mgr)
	gw, cp, err := loadConfig(path)
	if err != nil {
		return nil, nil, nil, err
	}
	if d := mgr.Verify(); d.HasErrors() {
		return nil, nil, nil, fmt.Errorf("%s", d.Error())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	return gw, cp, raw, nil
}

// compileBytes validates raw config bytes (load + compile + plugin
// verify), the bytes-input twin of loadDesired. Used by apply, whose
// desired config may come from a file or from a saved plan.
func compileBytes(raw []byte) (*config.Gateway, *config.CompiledPolicy, error) {
	mgr := extplugin.New(nil)
	defer mgr.Stop()
	config.SetPluginLoader(mgr)
	gw, diags := config.LoadBytes(raw, "apply.hcl")
	if diags.HasErrors() {
		return nil, nil, fmt.Errorf("%s", diags.Error())
	}
	cp, err := config.Compile(gw)
	if err != nil {
		return nil, nil, fmt.Errorf("compile: %w", err)
	}
	if d := mgr.Verify(); d.HasErrors() {
		return nil, nil, fmt.Errorf("%s", d.Error())
	}
	return gw, cp, nil
}

// openStateDB resolves the state dir from the config and opens the
// gateway DB (the state backend).
func openStateDB(gw *config.Gateway) (*sql.DB, error) {
	stateDir := resolveStateDir(gw)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	return OpenDB(filepath.Join(stateDir, "clawpatrol.db"))
}

// configPlan is the result of diffing a desired config against the
// deployed state.
type configPlan struct {
	desiredRev     string
	deployedRev    string
	deployedSerial int64
	hasDeployed    bool
	diff           digestDiff
}

func (p configPlan) noChanges() bool { return p.hasDeployed && p.diff.empty() }

// computePlan diffs the desired gateway/raw against the deployed config
// in the backend.
func computePlan(db *sql.DB, gw *config.Gateway, raw []byte) (configPlan, error) {
	p := configPlan{desiredRev: revisionForBytes(raw)}
	content, serial, ok, err := activeConfig(db)
	if err != nil {
		return p, err
	}
	newDigest := config.PolicyDigest(gw)
	var oldDigest map[string]string
	if ok {
		p.hasDeployed = true
		p.deployedSerial = serial
		p.deployedRev = revisionForBytes(content)
		if oldGw, diags := config.LoadBytes(content, "deployed.hcl"); !diags.HasErrors() {
			oldDigest = config.PolicyDigest(oldGw)
		}
	}
	p.diff = diffDigests(oldDigest, newDigest)
	return p, nil
}

func (p configPlan) print(w bufWriter, cp *config.CompiledPolicy) {
	fmt.Fprintf(w, "revision: %s  (%d endpoints, %d profiles)\n", shortRev(p.desiredRev), len(cp.Endpoints), len(cp.Profiles))
	if p.hasDeployed {
		fmt.Fprintf(w, "deployed: %s  (serial %d)\n\n", shortRev(p.deployedRev), p.deployedSerial)
	} else {
		fmt.Fprintln(w, "deployed: (none — backend is empty, this seeds serial 1)")
		fmt.Fprintln(w)
	}
	p.diff.render(w)
}

// savedPlanVersion is the on-disk format version of a saved plan.
const savedPlanVersion = 1

// savedPlan is a plan written by `plan --out` and consumed by `apply
// <planfile>`. It binds the desired config to the serial it was planned
// against (ExpectedSerial); apply refuses it if the deployed serial has
// moved since — Terraform's "saved plan is stale" guard, which is what
// makes a real conflict (not just a lock wait) observable.
type savedPlan struct {
	Version        int      `json:"version"`
	Config         []byte   `json:"config"` // raw desired HCL (base64 in JSON)
	Revision       string   `json:"revision"`
	SchemaVersion  int      `json:"schema_version"`
	ExpectedSerial int64    `json:"expected_serial"`
	Added          []string `json:"added,omitempty"`
	Removed        []string `json:"removed,omitempty"`
	Changed        []string `json:"changed,omitempty"`
	CreatedNs      int64    `json:"created_ns"`
}

// looksLikeSavedPlan reports whether bytes parse as a saved plan (vs raw
// HCL). A plan file is JSON with a positive version; HCL never is.
func looksLikeSavedPlan(b []byte) (savedPlan, bool) {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || t[0] != '{' {
		return savedPlan{}, false
	}
	var sp savedPlan
	if err := json.Unmarshal(t, &sp); err != nil || sp.Version == 0 || len(sp.Config) == 0 {
		return savedPlan{}, false
	}
	return sp, true
}

// runPlan is `clawpatrol plan [-out file] <config.hcl>` — read-only,
// optionally saving a plan for a later `apply <planfile>`.
func runPlan(args []string) {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	out := fs.String("out", "", "write the plan to this file for `clawpatrol apply <planfile>`")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: clawpatrol plan [-out file] <config.hcl>")
		os.Exit(2)
	}
	gw, cp, raw, err := loadDesired(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "plan: %s: %v\n", rest[0], err)
		os.Exit(1)
	}
	db, err := openStateDB(gw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plan: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	p, err := computePlan(db, gw, raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plan: %v\n", err)
		os.Exit(1)
	}
	p.print(os.Stdout, cp)
	if p.noChanges() {
		fmt.Println("\nNo changes. Deployed config is up to date.")
	}
	if *out != "" {
		sp := savedPlan{
			Version:        savedPlanVersion,
			Config:         raw,
			Revision:       p.desiredRev,
			SchemaVersion:  gw.SchemaVersion,
			ExpectedSerial: p.deployedSerial,
			Added:          p.diff.added,
			Removed:        p.diff.removed,
			Changed:        p.diff.changed,
		}
		blob, _ := json.MarshalIndent(sp, "", "  ")
		if err := os.WriteFile(*out, blob, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "plan: write %s: %v\n", *out, err)
			os.Exit(1)
		}
		fmt.Printf("\nplan saved to %s (bound to serial %d) — apply with `clawpatrol apply %s`\n", *out, p.deployedSerial, *out)
	}
}

// runApply is `clawpatrol apply [-y] [--expect N] <config.hcl | planfile>`.
// Given a saved plan it applies that plan, refusing if the deployed
// serial has moved since the plan was made (stale-plan conflict). Given
// an .hcl it plans fresh under the lock; --expect N asserts the base
// serial for CI without a saved plan.
func runApply(args []string) {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	autoApprove := fs.Bool("y", false, "apply without the interactive confirmation prompt")
	expect := fs.Int64("expect", -1, "require the deployed serial to equal this (conflict if not); -1 = no assertion")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: clawpatrol apply [-y] [--expect N] <config.hcl | planfile>")
		os.Exit(2)
	}
	path := rest[0]

	fileBytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply: read %s: %v\n", path, err)
		os.Exit(1)
	}

	// A saved plan carries its own desired config + the serial it was
	// planned against; a raw .hcl is planned fresh.
	var (
		raw            []byte
		expectSerial   int64 = *expect
		fromSavedPlan  bool
		savedSchemaVer int
	)
	if sp, ok := looksLikeSavedPlan(fileBytes); ok {
		fromSavedPlan = true
		raw = sp.Config
		expectSerial = sp.ExpectedSerial
		savedSchemaVer = sp.SchemaVersion
	} else {
		raw = fileBytes
	}

	// Validate the desired config (compile + plugin verify) regardless of
	// source — a stored plan still gets re-checked against this binary.
	gw, cp, err := compileBytes(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply: %s: %v\n", path, err)
		os.Exit(1)
	}
	if fromSavedPlan && savedSchemaVer != gw.SchemaVersion {
		// Defensive: the stored schema_version should match what we just
		// parsed; a mismatch means a tampered/corrupt plan file.
		fmt.Fprintf(os.Stderr, "apply: saved plan schema_version (%d) disagrees with its config (%d)\n", savedSchemaVer, gw.SchemaVersion)
		os.Exit(1)
	}

	db, err := openStateDB(gw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	who := lockHolder()
	locked, cur, err := acquireConfigLock(db, who, "apply "+path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply: lock: %v\n", err)
		os.Exit(1)
	}
	if !locked {
		fmt.Fprintf(os.Stderr, "Error: config is locked by %s since %s%s\nAnother apply may be in progress. If it crashed, run `clawpatrol config unlock %s`.\n",
			cur.Holder, time.Unix(0, cur.LockedNs).Format(applyTimeFormat), reasonSuffix(cur.Reason), path)
		os.Exit(1)
	}

	// Everything below runs while holding the lock. It's wrapped in a
	// closure so the deferred release runs on EVERY exit path — a bare
	// os.Exit here would skip the defer and leak the lock, wedging the
	// next apply until the staleness steal kicks in.
	err = func() error {
		defer releaseConfigLock(db, who)

		deployedSerial, err := currentSerial(db)
		if err != nil {
			return fmt.Errorf("read serial: %w", err)
		}

		// Stale-plan / expectation conflict: the deployed serial moved
		// since the plan was made (or since the asserted base). This is
		// the real conflict the lock alone can't surface — another writer
		// landed a change between plan and apply.
		if expectSerial >= 0 && deployedSerial != expectSerial {
			src := "the saved plan was"
			if !fromSavedPlan {
				src = "--expect was"
			}
			return fmt.Errorf(
				"conflict — deployed serial is %d but %s built against serial %d.\nSomeone applied a change in between. Re-run `clawpatrol plan` and review before applying",
				deployedSerial, src, expectSerial)
		}

		p, err := computePlan(db, gw, raw)
		if err != nil {
			return err
		}
		fmt.Printf("config: %s\n", path)
		p.print(os.Stdout, cp)
		if fromSavedPlan {
			fmt.Println("\n(applying saved plan)")
		}
		fmt.Println()

		if p.noChanges() {
			fmt.Println("No changes. Deployed config is up to date.")
			return nil
		}
		// A reviewed saved plan applies without re-prompting (Terraform
		// behavior); a fresh .hcl prompts unless -y.
		if !fromSavedPlan && !*autoApprove {
			if !confirm("Apply this config?") {
				fmt.Println("aborted.")
				return nil
			}
		}

		rev, serial, ok, err := recordConfigVersionCAS(db, raw, gw.SchemaVersion, deployedSerial)
		if err != nil {
			return fmt.Errorf("record version: %w", err)
		}
		if !ok {
			// Serial moved between the check above and the insert — only
			// possible if the lock was forced mid-apply.
			return fmt.Errorf("state changed during apply (expected serial %d, no longer current). Re-run apply", deployedSerial)
		}
		fmt.Printf("Apply complete. serial %d, revision %s.\n", serial, shortRev(rev))
		fmt.Println("The running gateway will reload from the backend within a few seconds.")
		return nil
	}()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
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
		fmt.Fprintln(os.Stderr, "usage: clawpatrol config <history|unlock> <config.hcl>")
		os.Exit(2)
	}
	switch args[0] {
	case "history":
		runConfigHistory(args[1:])
	case "unlock":
		runConfigUnlock(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown config subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: clawpatrol config <history|unlock> <config.hcl>")
		os.Exit(2)
	}
}

// runConfigHistory lists recorded config versions.
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
	db, err := openStateDB(gw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config history: %v\n", err)
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
		fmt.Printf("serial %-4d  %s  %s  schema=%d\n", v.ID, ts, shortRev(v.Revision), v.SchemaVersion)
	}
}

// runConfigUnlock force-releases the state lock (Terraform's
// force-unlock). For recovering from a crashed apply.
func runConfigUnlock(args []string) {
	fs := flag.NewFlagSet("config unlock", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: clawpatrol config unlock <config.hcl>")
		os.Exit(2)
	}
	gw, _, err := loadConfig(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "config unlock: %s: %v\n", rest[0], err)
		os.Exit(1)
	}
	db, err := openStateDB(gw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config unlock: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	cur, held, _ := readConfigLock(db)
	released, err := forceUnlockConfigLock(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config unlock: %v\n", err)
		os.Exit(1)
	}
	if !released || !held {
		fmt.Println("no lock held.")
		return
	}
	fmt.Printf("released lock held by %s since %s.\n", cur.Holder, time.Unix(0, cur.LockedNs).Format(applyTimeFormat))
}

// --- helpers -------------------------------------------------------

// bufWriter is the minimal io.Writer surface render/print need; aliased
// so signatures read clearly and tests can pass a *strings.Builder.
type bufWriter = interface{ Write([]byte) (int, error) }

func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

// lockHolder is the OS user plus hostname, recorded on the lock so a
// contended lock names a recognizable owner across machines. This is
// Terraform's lock "Who" (user@host) — derived from the environment,
// never a flag.
func lockHolder() string {
	who := "unknown"
	if u := os.Getenv("SUDO_USER"); u != "" {
		who = u
	} else if u := os.Getenv("USER"); u != "" {
		who = u
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return who + "@" + h
	}
	return who
}

// confirm prompts on stderr and reads a yes/no from stdin.
func confirm(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}
