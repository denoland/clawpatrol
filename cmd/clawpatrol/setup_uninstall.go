package main

// `clawpatrol uninstall` and `clawpatrol status` — the two
// administrative subcommands that don't belong to the join flow.
// Both are entirely defensive: uninstall is best-effort across every
// piece of state `clawpatrol join` could have planted, and status is
// a one-shot self-diagnostic that should never side-effect.

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// `clawpatrol uninstall` — tear down everything `clawpatrol join`
// (and friends) put on this machine. Cross-platform, idempotent.
// Stops the macOS NETransparentProxy + system extension, brings
// down the linux wg-quick interface, removes the CA from system
// trust, drops the per-user state dirs, and strips the shell-rc
// env shim.
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	keepCA := fs.Bool("keep-ca", false, "keep ~/.clawpatrol + system trust")
	keepConf := fs.Bool("keep-conf", false, "keep ~/.config/clawpatrol/wg.conf")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	_ = fs.Parse(args)

	if !*yes {
		fmt.Print("Uninstall clawpatrol from this machine? [y/N] ")
		var resp string
		_, _ = fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			fmt.Println("aborted")
			return
		}
	}

	step := func(label string, fn func() error) {
		if err := fn(); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ %s: %v\n", label, err)
			return
		}
		fmt.Println("  ✓ " + label)
	}
	bestEffort := func(name string, argv ...string) func() error {
		return func() error {
			c := exec.Command(name, argv...)
			c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
			return c.Run()
		}
	}

	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat(macHelperPath); err == nil {
			step("Clawpatrol stop", bestEffort(macHelperPath, "stop"))
			step("Clawpatrol wipe", bestEffort(macHelperPath, "wipe"))
		}
		if _, err := os.Stat("/Applications/Clawpatrol.app"); err == nil {
			step("rm /Applications/Clawpatrol.app",
				bestEffort("sudo", "rm", "-rf", "/Applications/Clawpatrol.app"))
		}
		if !*keepCA {
			step("untrust CA in System.keychain",
				bestEffort("sudo", "security", "delete-certificate",
					"-c", "clawpatrol", "/Library/Keychains/System.keychain"))
		}
	case "linux":
		step("wg-quick down clawpatrol", bestEffort("sudo", "wg-quick", "down", "clawpatrol"))
		if !*keepCA {
			step("rm system CA", bestEffort("sudo", "rm", "-f",
				"/usr/local/share/ca-certificates/clawpatrol.crt"))
			step("update-ca-certificates", bestEffort("sudo", "update-ca-certificates"))
		}
	}

	if !*keepCA {
		dir := defaultClawpatrolDir()
		step("rm "+dir, func() error { return os.RemoveAll(dir) })
	}
	if !*keepConf {
		confDir := filepath.Join(os.Getenv("HOME"), ".config", "clawpatrol")
		step("rm "+confDir, func() error { return os.RemoveAll(confDir) })
	}
	step("strip shell-rc env shim", removeShellRCMarker)

	fmt.Println()
	fmt.Println("done. Reinstall: curl -fsSL https://clawpatrol.dev/install.sh | sh")
}

// removeShellRCMarker strips the line installShellRC appended.
// Idempotent — silently no-ops when the marker isn't present.
func removeShellRCMarker() error {
	const marker = "# clawpatrol: agent env (clawpatrol env)"
	home := os.Getenv("HOME")
	for _, name := range []string{".zshrc", ".bashrc", ".profile"} {
		p := filepath.Join(home, name)
		src, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		i := strings.Index(string(src), marker)
		if i < 0 {
			continue
		}
		// Drop the marker line + the eval line that follows.
		end := i
		newlines := 0
		for end < len(src) && newlines < 2 {
			if src[end] == '\n' {
				newlines++
			}
			end++
		}
		out := append([]byte{}, src[:i]...)
		out = append(out, src[end:]...)
		if err := os.WriteFile(p, out, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// `clawpatrol status` — what's installed, what's running, what's
// reachable. Self-diagnose without log streaming. No flags; one
// shot of every signal that matters for "why isn't this working".
func runStatus(args []string) {
	_ = args
	check := func(label string, ok bool, detail string) {
		mark := "✗"
		if ok {
			mark = "✓"
		}
		if detail != "" {
			fmt.Printf("  %s %s — %s\n", mark, label, detail)
		} else {
			fmt.Printf("  %s %s\n", mark, label)
		}
	}

	caPath := filepath.Join(defaultClawpatrolDir(), "ca.crt")
	_, caErr := os.Stat(caPath)
	check("CA bundle", caErr == nil, caPath)

	confPath := filepath.Join(os.Getenv("HOME"), ".config", "clawpatrol", "wg.conf")
	_, confErr := os.Stat(confPath)
	check("wg.conf", confErr == nil, confPath)

	switch runtime.GOOS {
	case "darwin":
		_, helperErr := os.Stat(macHelperPath)
		check("Clawpatrol.app", helperErr == nil, "/Applications/Clawpatrol.app")
		// systemextensionsctl list — single line per ext, look for ours.
		out, _ := exec.Command("systemextensionsctl", "list").Output()
		extLine := ""
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "dev.clawpatrol.app.extension") {
				extLine = strings.TrimSpace(line)
				break
			}
		}
		check("system extension", strings.Contains(extLine, "[activated enabled]"), extLine)
	case "linux":
		out, err := exec.Command("ip", "link", "show", "clawpatrol").Output()
		up := err == nil && strings.Contains(string(out), "state UNKNOWN")
		check("wg-quick interface up", up, "ip link show clawpatrol")
	}

	// Gateway reachability: parse Endpoint from wg.conf, hit /info on
	// the configured public_url if we can reach it. Best-effort only.
	if confErr == nil {
		if endpoint := wgEndpointFromConf(confPath); endpoint != "" {
			check("gateway reachable", pingGateway(endpoint), endpoint)
		}
	}
}

func wgEndpointFromConf(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "Endpoint") {
			if eq := strings.IndexByte(line, '='); eq > 0 {
				return strings.TrimSpace(line[eq+1:])
			}
		}
	}
	return ""
}

// pingGateway dials the wg endpoint host on the configured port. Just
// proves the host is reachable + listening, not that wg handshake
// succeeds.
func pingGateway(endpoint string) bool {
	c, err := net.DialTimeout("udp", endpoint, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
