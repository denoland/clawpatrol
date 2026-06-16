package main

import (
	"context"
	"fmt"
	"os"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
)

const pluginsHelp = `usage: clawpatrol plugins <command> <config.hcl> [name...]

commands:
  install   Download and cache each GitHub-sourced plugin at the version
            its constraint selects (keeping any already-pinned version),
            recording the resolved version + binary hash + declared
            permissions in ` + extplugin.LockfileName + ` beside the config.
  update    Like install, but re-resolve to the newest release tag that
            satisfies the constraint and re-pin it — the explicit upgrade.
  lock      For each pinned plugin, record the binary hash of every
            platform build the release ships, so one committed lockfile
            verifies the plugin across a mixed-OS team.
  approve   Re-approve a plugin after an intentional permission change,
            clearing the escalation block so the gateway will load it.

With no name arguments a command applies to every plugin in the config.`

func runPlugins(args []string) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Println(pluginsHelp)
		os.Exit(0)
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, pluginsHelp)
		os.Exit(2)
	}
	switch args[0] {
	case "install":
		runPluginsInstall(args[1:], false)
	case "update":
		runPluginsInstall(args[1:], true)
	case "lock":
		runPluginsLock(args[1:])
	case "approve":
		runPluginsApprove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown plugins subcommand %q\n\n%s\n", args[0], pluginsHelp)
		os.Exit(2)
	}
}

// pluginsManager decodes the config (without spawning) and returns a
// manager wired to the lockfile and resolved state dir, plus the plugin
// specs — the shared setup for install/update/lock/approve.
func pluginsManager(args []string) (*extplugin.Manager, []config.PluginSource, []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, pluginsHelp)
		os.Exit(2)
	}
	cfgPath := args[0]
	names := args[1:]

	// Decode with a no-op loader: we want the plugin sources without
	// spawning (and without tripping the escalation block).
	config.SetPluginLoader(nil)
	gw, diags := config.Load(cfgPath)
	if gw == nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", cfgPath, diags.Error())
		os.Exit(1)
	}
	mgr := extplugin.New(nil)
	mgr.SetLockfile(extplugin.LockfilePathFor(cfgPath), false)
	mgr.SetStateDir(gw.ResolvedStateDir())
	mgr.VerifyProvenance(true)
	return mgr, gw.Plugins, names
}

func runPluginsInstall(args []string, upgrade bool) {
	mgr, specs, names := pluginsManager(args)
	defer mgr.Stop()

	verb := "install"
	if upgrade {
		verb = "update"
	}
	installed, err := mgr.Install(context.Background(), specs, names, upgrade)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", verb, err)
		os.Exit(1)
	}
	remote := 0
	for _, p := range installed {
		remote++
		switch {
		case p.WasLocked == "":
			fmt.Printf("installed %q %s (%s, network=%s)\n", p.Name, p.Version, p.Source, p.Network)
		case p.Updated:
			fmt.Printf("updated %q %s -> %s (network=%s)\n", p.Name, p.WasLocked, p.Version, p.Network)
		default:
			fmt.Printf("up to date %q %s (network=%s)\n", p.Name, p.Version, p.Network)
		}
	}
	if remote == 0 {
		fmt.Println("no GitHub-sourced plugins to " + verb)
	}
}

func runPluginsLock(args []string) {
	mgr, specs, names := pluginsManager(args)
	defer mgr.Stop()

	locked, err := mgr.LockPlatforms(context.Background(), specs, names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lock: %v\n", err)
		os.Exit(1)
	}
	for _, p := range locked {
		fmt.Printf("locked %q %s across all release platforms\n", p.Name, p.Version)
	}
	if len(locked) == 0 {
		fmt.Println("no GitHub-sourced plugins to lock")
	}
}

func runPluginsApprove(args []string) {
	mgr, specs, names := pluginsManager(args)
	defer mgr.Stop()

	approved, err := mgr.Approve(context.Background(), specs, names)
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
