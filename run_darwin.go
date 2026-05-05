//go:build darwin

package main

// `clawpatrol run` on macOS shells out to the Clawpatrol.app helper.
// The .app holds a NETransparentProxyProvider system extension that
// intercepts flows and routes them through the gateway via a
// userspace WireGuard + gVisor netstack (see macos/netstack/). The
// Go CLI doesn't talk to the extension directly — it talks to the
// helper binary inside the .app, which talks to the extension via
// NETransparentProxyManager / NEAppRule lifecycle calls.
//
// Bootstrap is idempotent: if the system extension isn't installed
// yet, `Clawpatrol install` triggers the one-time approval prompt;
// subsequent runs reuse the activated extension. If the proxy isn't
// running, `Clawpatrol start` brings it up. If both are running,
// `Clawpatrol run` just forks the user command.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const macHelperPath = "/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol"

func runRun(args []string) {
	if _, err := os.Stat(macHelperPath); err != nil {
		fail("Clawpatrol.app not installed. Build + install from macos/:\n" +
			"  cd macos && ./install.sh\n" +
			"then: clawpatrol join --url <gateway>")
	}
	if err := ensureMacProxyUp(); err != nil {
		fail(fmt.Sprintf("ensure proxy up: %v", err))
	}
	// Stamp CA + placeholder env vars on the current process so the
	// helper inherits them and forwards them to the wrapped child.
	applyEnvPushdown(defaultClawpatrolDir())
	// Forward the command + args through the helper's run subcommand,
	// which forks the cmd as a child of the .app process so the
	// extension's PPID walk picks it up.
	all := append([]string{"run", "--"}, args...)
	c := exec.Command(macHelperPath, all...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = os.Environ()
	if err := c.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fail(fmt.Sprintf("run: %v", err))
	}
}

// ensureMacProxyUp is a no-op when the proxy is already running; it
// installs the system extension on first use and starts the tunnel
// against ~/.config/clawpatrol/wg.conf otherwise. We can't tell from
// the outside whether the proxy is up without round-tripping through
// the helper, so we always call `start` — the helper's start handler
// is idempotent (saveToPreferences + startVPNTunnel both no-op when
// already-saved / already-connected).
func ensureMacProxyUp() error {
	confPath := filepath.Join(os.Getenv("HOME"), ".config", "clawpatrol", "wg.conf")
	if _, err := os.Stat(confPath); err != nil {
		return fmt.Errorf("no wg.conf at %s — run `clawpatrol join --url <gateway>` first", confPath)
	}
	// `install` may surface the system-extension approval prompt the
	// first time; once activated it's a fast no-op.
	cmd := exec.Command(macHelperPath, "install")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	_ = cmd.Run() // tolerate "already installed" exit codes
	cmd = exec.Command(macHelperPath, "start", confPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// helper exits non-zero if profile missing — map to friendlier msg.
			ws := ee.Sys().(syscall.WaitStatus)
			if ws.ExitStatus() != 0 {
				return fmt.Errorf("helper start exit=%d", ws.ExitStatus())
			}
		}
		return err
	}
	return nil
}

// macHelperInstall is invoked from runJoin (on darwin) right after
// the wg.conf is written so the user gets a single-prompt onboarding:
// `clawpatrol join --url ...` → wg conf saved → sysext approved →
// proxy up. wholeMachine maps to the helper's --whole-machine flag.
//
// After saving the profile, push the freshly written wg.conf into the
// extension via `Clawpatrol start` so a re-join (new keys, new peer)
// or a mode switch (per-process ↔ whole-machine) takes effect on the
// running tunnel — the helper's `start` is reload-aware (stop+start
// when conf or mode changed).
func macHelperInstall(wholeMachine bool) error {
	if _, err := os.Stat(macHelperPath); err != nil {
		return fmt.Errorf("Clawpatrol.app not at /Applications — reinstall: curl -fsSL https://clawpatrol.dev/install.sh | sh")
	}
	args := []string{"install"}
	if wholeMachine {
		args = append(args, "--whole-machine")
	}
	c := exec.Command(macHelperPath, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return err
	}
	confPath := filepath.Join(os.Getenv("HOME"), ".config", "clawpatrol", "wg.conf")
	if _, err := os.Stat(confPath); err != nil {
		return nil
	}
	c = exec.Command(macHelperPath, "start", confPath)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}
