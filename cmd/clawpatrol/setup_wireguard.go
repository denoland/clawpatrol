package main

// WireGuard install helpers used by the join flow when wg-quick is
// the chosen transport (--whole-machine on Linux without Tailscale).
// writeUserWGConf drops the conf at a stable XDG path so
// `clawpatrol run` can build per-process tunnels without sudo, while
// wgQuickUp brings up the system-wide interface. injectSSHExemptPostUp
// pins SSH-reply traffic to the host's main routing table so the
// admin session that just ran `clawpatrol join --whole-machine` survives
// the AllowedIPs = 0.0.0.0/0 default-route swap.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// writeUserWGConf drops a copy of the wg-quick conf at
// ~/.config/clawpatrol/wg.conf (chmod 600) so `clawpatrol run` can
// build per-process tunnels without sudo. Idempotent.
//
// Hardcoded XDG path (~/.config) instead of os.UserConfigDir() —
// the latter returns ~/Library/Application Support on macOS, which
// breaks the cross-platform "always look at ~/.config/clawpatrol/wg.conf"
// contract that the macOS Clawpatrol.app's `start` subcommand expects.
func writeUserWGConf(conf string) error {
	dir := filepath.Join(os.Getenv("HOME"), ".config", "clawpatrol")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "wg.conf")
	return os.WriteFile(path, []byte(conf), 0o600)
}

// wgQuickUp writes the supplied wireguard config to
// /etc/wireguard/<iface>.conf and brings the interface up via
// `wg-quick up`. Installs `wireguard-tools` if missing on linux.
func wgQuickUp(iface, conf string) error {
	if _, err := exec.LookPath("wg-quick"); err != nil {
		if runtime.GOOS == "linux" {
			c := runAsRoot("apt-get", "install", "-y", "wireguard-tools")
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			if err := c.Run(); err != nil {
				return fmt.Errorf("install wireguard-tools: %w", err)
			}
		} else {
			return fmt.Errorf("wg-quick not found — install wireguard-tools / WireGuard.app")
		}
	}
	dst := filepath.Join("/etc/wireguard", iface+".conf")
	if runtime.GOOS == "linux" {
		conf = injectSSHExemptPostUp(conf)
	}
	tmp, err := os.CreateTemp("", "clawpatrol-wg-*.conf")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(conf); err != nil {
		return err
	}
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := runAsRoot("install", "-m", "0600", tmp.Name(), dst).Run(); err != nil {
		return fmt.Errorf("install conf: %w", err)
	}
	// `wg-quick up` is idempotent enough — bring down first if up.
	_ = runAsRoot("wg-quick", "down", iface).Run()
	c := runAsRoot("wg-quick", "up", iface)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

// injectSSHExemptPostUp inserts policy-routing PostUp/PostDown hooks
// into the [Interface] block of a wg-quick conf so packets sourced
// from the host's public IP keep using the original routing table.
//
// Without this, `AllowedIPs = 0.0.0.0/0` makes wg-quick replace the
// default route with one through the tunnel — including reply packets
// for inbound connections. SSH replies route through clawpatrol →
// wrong source IP → in-flight admin session that ran `clawpatrol join
// --whole-machine` dies mid-handshake. Same trick unclaw landed in
// commit 53e0496.
//
// Returns conf unchanged when the host IP can't be detected (best
// effort — better to bring up the tunnel than block on a heuristic).
// Idempotent on the wire because PostUp's `ip rule add` is a single
// rule with a fixed priority; re-runs add a duplicate but PostDown
// removes one at a time and wg-quick down/up cycles cleanly.
func injectSSHExemptPostUp(conf string) string {
	hostIP := detectHostIP()
	if hostIP == "" {
		return conf
	}
	// Priority 5 — must beat wg-quick's two own rules:
	//   pref 8: from all lookup main suppress_prefixlength 0
	//   pref 9: not fwmark 51820 lookup 51820
	// Pref 10 (what unclaw originally used in commit 53e0496) gets
	// shadowed by pref 9 — pref 9 matches every non-fwmarked packet
	// first → table 51820 → clawpatrol iface → SYN-ACK exits the wrong
	// interface, SSH session dies. Observed on Ubuntu 24.04 / Vultr.
	postUp := fmt.Sprintf("PostUp = ip rule add from %s lookup main priority 5", hostIP)
	postDown := fmt.Sprintf("PostDown = ip rule del from %s lookup main priority 5", hostIP)
	if strings.Contains(conf, postUp) {
		return conf
	}
	// Insert before [Peer] (always present, terminates [Interface]).
	// Falls back to append if [Peer] is missing for some reason.
	idx := strings.Index(conf, "[Peer]")
	if idx < 0 {
		return conf + "\n" + postUp + "\n" + postDown + "\n"
	}
	return conf[:idx] + postUp + "\n" + postDown + "\n\n" + conf[idx:]
}

// detectHostIP returns the IPv4 address used to reach the public
// internet, mirroring `ip -4 route get 1.1.1.1 | grep -oP 'src \K...'`.
// Returns "" on any error so callers can decide to skip the rule.
func detectHostIP() string {
	out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return ""
	}
	// Output: "1.1.1.1 via X dev eth0 src Y.Y.Y.Y uid 0 \n cache"
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "src" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
