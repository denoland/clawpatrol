package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
)

// runValidate is the CLI entry: print msg, exit with code.
func runValidate(args []string) {
	msg, code := validateCmd(args)
	if code == 0 {
		fmt.Println(msg)
		return
	}
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(code)
}

// parseVerifyFlags pulls the shared --plugin-cache-dir flag out of a
// verification command's args, returning its value and the remaining
// positional args. ok is false on a parse or -h/--help error, in which
// case the caller prints usage. The flag lets a caller (e.g. deploy.sh,
// linting on a machine where the config's state_dir isn't writable) point
// the plugin binary cache somewhere writable; empty means use the config's
// state_dir, the same as the gateway.
func parseVerifyFlags(name string, args []string) (cacheDir string, rest []string, ok bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // callers craft their own usage string
	cd := fs.String("plugin-cache-dir", "", "directory for the plugin binary cache (default: the config's state_dir)")
	if err := fs.Parse(args); err != nil {
		return "", nil, false
	}
	return *cd, fs.Args(), true
}

// newVerifyPluginManager builds a plugin manager for the read-only
// verification commands (validate, test). cacheDir overrides where plugin
// binaries are cached (empty = the config's state_dir); the verification
// commands expose it via --plugin-cache-dir so a config can be linted on a
// machine where its state_dir isn't writable. It verifies build-provenance
// attestations, matching the gateway-run (main.go) and `plugins` command
// paths — without it a cold fetch records the plugin as unattested and
// trips the lockfile's attested=true downgrade guard.
//
// The returned cleanup clears the package-global plugin loader (it points
// at this manager, whose lockfile path is request-scoped; config.Load
// resets to a no-op loader on nil) and stops the manager.
func newVerifyPluginManager(cacheDir string) (*extplugin.Manager, func()) {
	mgr := extplugin.New(nil)
	if cacheDir != "" {
		mgr.SetCacheDir(cacheDir)
	}
	mgr.VerifyProvenance(true)
	cleanup := func() {
		config.SetPluginLoader(nil)
		mgr.Stop()
	}
	return mgr, cleanup
}

// validateCmd is the pure side: same arg parsing, but returns
// (output, exitCode) instead of touching stdio. Same pipeline the
// gateway uses at startup — anything that would crash the daemon
// shows up here first. Exit codes: 0 ok, 1 validation failure,
// 2 usage error.
//
// Also performs schema-level validation against any external
// plugins the config loads: every declared facet's CEL env is
// compiled eagerly, every plugin endpoint's Family is resolved
// against the facet registry. Catches plugin authoring bugs that
// the operator's HCL didn't happen to exercise.
func validateCmd(args []string) (string, int) {
	const usage = "usage: clawpatrol validate [--plugin-cache-dir DIR] <config.hcl>"
	cacheDir, rest, ok := parseVerifyFlags("validate", args)
	if !ok || len(rest) != 1 {
		return usage, 2
	}
	cfgPath := rest[0]
	mgr, cleanup := newVerifyPluginManager(cacheDir)
	defer cleanup()
	// Read-only: report a would-be first-load or an escalation as a
	// diagnostic, but never write the lockfile from `validate`.
	mgr.SetLockfile(extplugin.LockfilePathFor(cfgPath), true)
	config.SetPluginLoader(mgr)
	_, cp, err := loadConfig(cfgPath)
	if err != nil {
		return fmt.Sprintf("%s: %v", cfgPath, err), 1
	}
	if d := mgr.Verify(); d.HasErrors() {
		return fmt.Sprintf("%s: %s", cfgPath, d.Error()), 1
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ok: %s — %d endpoints across %d profile(s)",
		cfgPath, len(cp.Endpoints), len(cp.Profiles))
	for _, c := range mgr.Plugins() {
		mf := c.Manifest()
		if mf == nil {
			continue
		}
		fmt.Fprintf(&b, "\n  plugin %q v%s: %d facet(s), %d credential type(s), %d tunnel type(s), %d endpoint type(s) [sandbox: %s]",
			mf.Name, mf.Version,
			len(mf.Facets), len(mf.Credentials), len(mf.Tunnels), len(mf.Endpoints),
			c.SandboxMode())
	}
	return b.String(), 0
}
