package main

// Tailscale-specific helpers used by the join flow + tsnet-mode
// browser-open codepath. Holds the JSON shape of `tailscale status`,
// the small set of routing-table tweaks the whole-machine exit-node
// path needs (SSH + public-IP exemptions), and the tailnet-only URL
// detector + QR printer for verify pages whose host is unreachable
// from the operator's current machine.
//
// Linux-only helpers (the iptables/ip-rule tweaks) compile on every
// platform — they shell out to `sudo iptables` / `sudo ip` and only
// run when applyWholeMachineExitNode is called from the Linux join
// path.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	neturl "net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/mdp/qrterminal/v3"
)

type tsStatus struct {
	Self           *tsPeer            `json:"Self"`
	Peer           map[string]*tsPeer `json:"Peer"`
	MagicDNSSuffix string             `json:"MagicDNSSuffix"`
	CurrentTailnet *tsTailnet         `json:"CurrentTailnet"`
	User           map[string]tsUser  `json:"User"`
}

type tsTailnet struct {
	Name string `json:"Name"`
}

type tsUser struct {
	LoginName   string `json:"LoginName"`
	DisplayName string `json:"DisplayName"`
}

type tsPeer struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
	UserID       int64    `json:"UserID"`
}

// applyWholeMachineExitNode finishes the whole-machine Tailscale Linux
// join: pins SSH + public-IP reply traffic to the direct path, flips
// the system tailscaled's exit-node to the gateway, and points DNS at
// the gateway (tsnet has no UDP fallback). CA fetch + trust install +
// shell rc are handled earlier in the join flow.
func applyWholeMachineExitNode(gwName string) error {
	if err := exemptSSHFromExitNode(""); err != nil {
		// Couldn't protect SSH — refuse to flip exit-node so we don't
		// kill an in-flight admin session.
		return fmt.Errorf("protect SSH from exit-node: %w", err)
	}
	if err := exemptPublicIPFromExitNode(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ couldn't protect public IP inbound traffic: %v\n", err)
	}
	tscli, err := tailscaleBin()
	if err != nil {
		return fmt.Errorf("tailscale CLI not found: %w", err)
	}
	st, err := tailscaleStatus(tscli)
	if err != nil {
		return fmt.Errorf("tailscale status: %w", err)
	}
	peer := findPeerByName(st, gwName)
	if peer == nil || len(peer.TailscaleIPs) == 0 {
		return fmt.Errorf("no peer named %q on this tailnet", gwName)
	}
	if err := tsSet(tscli, "--exit-node="+gwName); err != nil {
		return fmt.Errorf("tailscale set --exit-node=%s: %w", gwName, err)
	}
	pinDNSAtGatewayIfNeeded(peer.TailscaleIPs[0])
	return nil
}

// exemptSSHFromExitNode keeps sshd reply traffic on the host's
// direct path even after `tailscale set --exit-node` flips the
// default route. Marks every packet whose source port is 22 with
// fwmark 0x64, then adds an ip rule routing marked traffic via main
// table (default interface). Covers every present and future SSH
// session, not just the one that triggered the install.
//
// Idempotent — duplicate iptables/ip-rule entries return non-zero,
// which we swallow.
func exemptSSHFromExitNode(_ string) error {
	cmds := [][]string{
		{"iptables", "-t", "mangle", "-C", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "MARK", "--set-mark", "0x64"},
		{"ip", "rule", "show"},
	}
	// 1) Mark SSH replies (idempotent: -C check first, only -A if missing)
	check := exec.Command("sudo", cmds[0]...)
	if check.Run() != nil {
		add := append([]string{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "MARK", "--set-mark", "0x64"}, "")
		add = add[:len(add)-1]
		c := exec.Command("sudo", add...)
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("iptables mangle: %w", err)
		}
	}
	// 2) Route marked traffic via the main table (idempotent: check first)
	listed := exec.Command("sudo", cmds[1]...)
	out, _ := listed.Output()
	if !strings.Contains(string(out), "fwmark 0x64") {
		c := exec.Command("sudo", "ip", "rule", "add", "fwmark", "0x64", "lookup", "main", "pref", "50")
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("ip rule: %w", err)
		}
	}
	return nil
}

// exemptPublicIPFromExitNode ensures reply traffic for this machine's public
// IP address routes via the main table (direct interface) rather than the
// Tailscale exit-node. Without this, inbound TCP connections (HTTPS, etc.)
// receive SYN-ACKs from the exit-node's public IP instead of the machine's
// own IP, breaking every server that binds to the public interface.
//
// The fix is a single high-priority policy-routing rule:
//
//	ip rule add from <public-ip> lookup main priority 100
//
// Idempotent. Also writes a networkd-dispatcher script so the rule survives
// reboots (Tailscale's own routing rules are re-installed on every boot, so
// we have to be too).
func exemptPublicIPFromExitNode() error {
	// Find the primary public IPv4: source addr used for the default route.
	out, err := exec.Command("ip", "-o", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return fmt.Errorf("ip route get: %w", err)
	}
	// output: "1.1.1.1 via ... dev eth0 src 203.0.113.5 ..."
	pubIP := ""
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "src" && i+1 < len(fields) {
			pubIP = fields[i+1]
			break
		}
	}
	if pubIP == "" || strings.HasPrefix(pubIP, "100.") || pubIP == "127.0.0.1" {
		return fmt.Errorf("could not determine public IP (got %q)", pubIP)
	}

	// Add ip rule idempotently.
	existing, _ := exec.Command("ip", "rule", "show").Output()
	if !strings.Contains(string(existing), pubIP) {
		c := exec.Command("sudo", "ip", "rule", "add", "from", pubIP, "lookup", "main", "priority", "100")
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("ip rule add: %w", err)
		}
	}

	// Persist via networkd-dispatcher so the rule survives reboots.
	dir := "/etc/networkd-dispatcher/routable.d"
	_ = exec.Command("sudo", "mkdir", "-p", dir).Run()
	script := fmt.Sprintf("#!/bin/sh\n# clawpatrol: keep public IP replies on direct path (not exit-node)\nip rule show | grep -q '%s' || ip rule add from %s lookup main priority 100\n", pubIP, pubIP)
	tmp, err := os.CreateTemp("", "clawpatrol-routing-*")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(script); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Close()
	dst := dir + "/50-clawpatrol-public-ip"
	c := exec.Command("sudo", "sh", "-c", fmt.Sprintf("mv %s %s && chmod +x %s", tmp.Name(), dst, dst))
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("install routing script: %w", err)
	}
	return nil
}

// tsSet runs `tailscale set ...`, prepending sudo on Linux where the
// LocalAPI checkprefs ACL requires it (unless --operator was set on
// `up`). On macOS the GUI app handles auth so plain `tailscale set`
// works.
func tsSet(tscli string, args ...string) error {
	full := append([]string{"set"}, args...)
	if runtime.GOOS == "linux" {
		full = append([]string{tscli}, full...)
		c := exec.Command("sudo", full...)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		return c.Run()
	}
	c := exec.Command(tscli, full...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

// tailnetDisplayName returns a short name for the current tailnet,
// matching the README format ("divy's tailnet"). Prefers the
// CurrentTailnet.Name; falls back to the local user's display name or
// login local-part; final fallback is "your".
func tailnetDisplayName(st *tsStatus) string {
	if st.CurrentTailnet != nil && st.CurrentTailnet.Name != "" {
		// e.g. "divy@github" → "divy"
		n := st.CurrentTailnet.Name
		if i := strings.IndexAny(n, "@."); i > 0 {
			n = n[:i]
		}
		return n
	}
	if st.Self != nil {
		if u, ok := st.User[fmt.Sprint(st.Self.UserID)]; ok {
			if u.DisplayName != "" {
				if first := strings.SplitN(u.DisplayName, " ", 2)[0]; first != "" {
					return strings.ToLower(first)
				}
			}
			if u.LoginName != "" {
				if i := strings.IndexAny(u.LoginName, "@"); i > 0 {
					return u.LoginName[:i]
				}
				return u.LoginName
			}
		}
	}
	return "your"
}

func tailscaleBin() (string, error) {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p, nil
	}
	if runtime.GOOS == "darwin" {
		mac := "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
		if _, err := os.Stat(mac); err == nil {
			return mac, nil
		}
	}
	return "", fmt.Errorf("tailscale binary not on PATH")
}

func tailscaleStatus(bin string) (*tsStatus, error) {
	out, err := exec.Command(bin, "status", "--json").Output()
	if err != nil {
		return nil, err
	}
	var s tsStatus
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// findPeerByName looks up a peer by its tailnet-unique short name. Multiple
// peers may share HostName (Tailscale uses the value the node reports at
// registration — unchanged by name collisions), so prefer matching the
// first label of DNSName which Tailscale disambiguates with "-1", "-2"…
func findPeerByName(s *tsStatus, name string) *tsPeer {
	for _, p := range s.Peer {
		short := p.DNSName
		if i := strings.IndexByte(short, '.'); i > 0 {
			short = short[:i]
		}
		if short == name {
			return p
		}
	}
	for _, p := range s.Peer {
		if p.HostName == name {
			return p
		}
	}
	return nil
}

// installTailscale runs the official one-line installer for the
// platform. Requires sudo.
func installTailscale() error {
	switch runtime.GOOS {
	case "darwin":
		// brew install --cask tailscale; user must launch app once.
		c := exec.Command("brew", "install", "--cask", "tailscale")
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("brew install: %w (or download manually from tailscale.com)", err)
		}
		fmt.Println("  launch Tailscale.app once, then re-run clawpatrol join")
		return fmt.Errorf("manual app launch required")
	case "linux":
		c := exec.Command("sh", "-c", "curl -fsSL https://tailscale.com/install.sh | sh")
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	}
	return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

// isTailnetOnlyURL reports whether u has a host that's only reachable
// inside a Tailscale tailnet: a 100.64.0.0/10 CGNAT address (the
// range Tailscale carves nodes out of) or a name ending in `.ts.net`
// (the MagicDNS suffix). Invalid URLs return false so the caller
// falls back to the regular `tryOpen` path.
func isTailnetOnlyURL(u string) bool {
	p, err := neturl.Parse(u)
	if err != nil || p == nil {
		return false
	}
	host := p.Hostname()
	if host == "" {
		return false
	}
	if strings.HasSuffix(strings.ToLower(host), ".ts.net") {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Is4() && tailscaleCGNAT.Contains(ip)
	}
	return false
}

// tailscaleCGNAT is 100.64.0.0/10 — Tailscale's CGNAT range. Anything
// inside it is unreachable except from a tailnet member.
var tailscaleCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// printVerifyQR writes a terminal QR code encoding url to stdout.
// Used when the verify URL is tailnet-only — the operator scans with a
// phone or another already-onboarded device that can actually reach
// the gateway.
//
// GenerateHalfBlock packs two QR rows per terminal line via the
// ▀ / ▄ / █ / space unicode chars. Half the vertical space of the
// ANSI-colored block-per-cell variant, and renders cleanly when the
// operator pipes the join output to a file or pastes it into chat.
func printVerifyQR(url string) {
	fmt.Println("Tailnet-only URL — scan from a device with tailnet access:")
	fmt.Println()
	qrterminal.GenerateHalfBlock(url, qrterminal.M, os.Stdout)
	fmt.Println()
}
