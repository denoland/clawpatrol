package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"

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
// Diagnostics output is one-per-line — hcl.Diagnostics's stock
// String() truncates to the first error followed by "and N other
// diagnostic(s)", which is unhelpful when you want to fix everything
// in a single editor round-trip.
func validateCmd(args []string) (string, int) {
	if len(args) != 1 || args[0] == "-h" || args[0] == "--help" {
		return "usage: clawpatrol validate <config.hcl>", 2
	}
	// Mirror runGateway's plugin-loader setup so external plugins
	// declared in the config resolve here too — otherwise validate
	// would diverge from the runtime and miss "unknown plugin" errors.
	config.SetPluginLoader(extplugin.New(nil))
	path := args[0]
	gw, diags := config.Load(path)
	if diags.HasErrors() {
		return formatHCLDiagnostics(path, diags), 1
	}
	if gw.Listen == "" {
		gw.Listen = ":443"
	}
	cp, err := config.Compile(gw)
	if err != nil {
		return fmt.Sprintf("%s: compile: %v", path, err), 1
	}
	return fmt.Sprintf("ok: %s — %d endpoints across %d profile(s)",
		path, len(cp.Endpoints), len(cp.Profiles)), 0
}

// formatHCLDiagnostics renders one diagnostic per line. Path + line
// number when the diagnostic carries a Subject, summary always, detail
// indented underneath when present.
func formatHCLDiagnostics(path string, diags hcl.Diagnostics) string {
	var b strings.Builder
	for i, d := range diags {
		if i > 0 {
			b.WriteByte('\n')
		}
		loc := path
		if d.Subject != nil {
			loc = fmt.Sprintf("%s:%d", path, d.Subject.Start.Line)
		}
		fmt.Fprintf(&b, "%s: %s", loc, d.Summary)
		if d.Detail != "" {
			fmt.Fprintf(&b, "\n    %s", d.Detail)
		}
	}
	return b.String()
}
