package main

import (
	"context"
	"fmt"
	"os"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
)

const pluginsHelp = `usage: clawpatrol plugins approve <config.hcl> [name...]

Re-approve external plugins after an intentional upgrade. Probes each
named plugin (or every plugin when none are named), records its
current binary hash and declared permissions in the lockfile
(` + extplugin.LockfileName + ` beside the config), and clears the
escalation block so the gateway will load it.`

func runPlugins(args []string) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, pluginsHelp)
		os.Exit(2)
	}
	switch args[0] {
	case "approve":
		runPluginsApprove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown plugins subcommand %q\n\n%s\n", args[0], pluginsHelp)
		os.Exit(2)
	}
}

func runPluginsApprove(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, pluginsHelp)
		os.Exit(2)
	}
	cfgPath := args[0]
	names := args[1:]

	// Decode the config with a no-op loader so we get the plugin
	// sources without spawning (and without tripping the very
	// escalation block we're here to clear).
	config.SetPluginLoader(nil)
	gw, diags := config.Load(cfgPath)
	if gw == nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", cfgPath, diags.Error())
		os.Exit(1)
	}

	mgr := extplugin.New(nil)
	defer mgr.Stop()
	mgr.SetLockfile(extplugin.LockfilePathFor(cfgPath), false)

	approved, err := mgr.Approve(context.Background(), gw.Plugins, names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "approve: %v\n", err)
		os.Exit(1)
	}
	for _, a := range approved {
		fmt.Printf("approved plugin %q (network=%s)\n", a.Name, a.Network)
	}
	if len(approved) == 0 {
		fmt.Println("no plugins to approve")
	}
}
