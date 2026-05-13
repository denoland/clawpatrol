package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/extplugin"
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
	if len(args) != 1 || args[0] == "-h" || args[0] == "--help" {
		return "usage: clawpatrol validate <config.hcl>", 2
	}
	mgr := extplugin.New(nil)
	defer mgr.Stop()
	config.SetPluginLoader(mgr)
	_, cp, err := loadConfig(args[0])
	if err != nil {
		return fmt.Sprintf("%s: %v", args[0], err), 1
	}
	if d := mgr.Verify(); d.HasErrors() {
		return fmt.Sprintf("%s: %s", args[0], d.Error()), 1
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ok: %s — %d endpoints across %d profile(s)",
		args[0], len(cp.Endpoints), len(cp.Profiles))
	for _, c := range mgr.Plugins() {
		mf := c.Manifest()
		if mf == nil {
			continue
		}
		fmt.Fprintf(&b, "\n  plugin %q v%s: %d facet(s), %d credential type(s), %d tunnel type(s), %d endpoint type(s)",
			mf.Name, mf.Version,
			len(mf.Facets), len(mf.Credentials), len(mf.Tunnels), len(mf.Endpoints))
	}
	return b.String(), 0
}
