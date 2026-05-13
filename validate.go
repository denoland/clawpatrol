package main

import (
	"fmt"
	"os"

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
func validateCmd(args []string) (string, int) {
	if len(args) != 1 || args[0] == "-h" || args[0] == "--help" {
		return "usage: clawpatrol validate <config.hcl>", 2
	}
	config.SetPluginLoader(extplugin.New(nil))
	_, cp, err := loadConfig(args[0])
	if err != nil {
		return fmt.Sprintf("%s: %v", args[0], err), 1
	}
	return fmt.Sprintf("ok: %s — %d endpoints across %d profile(s)",
		args[0], len(cp.Endpoints), len(cp.Profiles)), 0
}
