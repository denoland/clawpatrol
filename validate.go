package main

import (
	"fmt"
	"os"
)

// runValidate parses + compiles an HCL config and reports diagnostics.
// Exit 0 on success, 1 on validation failure, 2 on usage error. Same
// pipeline the gateway uses at startup — anything that would crash the
// daemon shows up here first.
func runValidate(args []string) {
	if len(args) != 1 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: clawpatrol validate <config.hcl>")
		os.Exit(2)
	}
	_, cp, err := loadConfig(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", args[0], err)
		os.Exit(1)
	}
	fmt.Printf("ok: %s — %d endpoints across %d profile(s)\n",
		args[0], len(cp.Endpoints), len(cp.Profiles))
}
