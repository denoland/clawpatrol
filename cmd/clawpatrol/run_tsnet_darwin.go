//go:build darwin

package main

// `clawpatrol run` in Tailscale mode on macOS.
//
// Uses the same NETransparentProxy system extension as WireGuard mode, but
// with a tsnet.Server as the transport instead of WireGuard + gVisor.
// The extension intercepts all TCP/UDP flows from the child process tree
// via PPID-walk, and routes them through the gateway over the tailnet by
// setting the gateway as the tsnet exit node (ts_netstack_init configures
// ExitNodeIP); ts_netstack_tcp_connect then dials the original dst, which
// tsnet routes via the gateway, where it lands in RegisterFallbackTCPHandler.
//
// Flow:
//  1. Mint ephemeral tsnet auth key from gateway.
//  2. `Clawpatrol install` — ensure NE system extension is loaded.
//  3. `Clawpatrol start-tsnet <authKey> <controlURL> <gwHost> <gwIP>`
//     — NE calls ts_netstack_init: joins tailnet + sets ExitNodeIP=gwIP.
//  4. Poll session socket for `gettsip` → receive 100.x.x.x of NE node.
//  5. Register that IP with gateway (profile dispatch mapping).
//  6. Register session PID via session IPC, then `Clawpatrol run -- <cmd>`.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func runRunTsnet(args []string) {
	warnIfOnGatewayHost()

	if _, err := os.Stat(macHelperPath); err != nil {
		fail("Clawpatrol.app not installed. Build + install from macos/:\n" +
			"  cd macos && ./install.sh\n" +
			"then: clawpatrol join <gateway>")
	}

	dir := defaultClawpatrolDir()

	gwURL := strings.TrimSpace(readFileSilent(filepath.Join(dir, "gateway")))
	gwHost := strings.TrimSpace(readFileSilent(filepath.Join(dir, "tailnet-gateway")))
	gwIP := strings.TrimSpace(readFileSilent(filepath.Join(dir, "tailnet-gateway-ip")))
	controlURL := strings.TrimSpace(readFileSilent(filepath.Join(dir, "control-url")))
	token := strings.TrimSpace(readFileSilent(filepath.Join(dir, "api-token")))
	// tsnet auth key is intentionally NOT read from disk. On macOS the
	// NE extension persists it inside NETransparentProxyManager's
	// providerConfiguration (system VPN preferences). We pass an empty
	// authKey to `start-tsnet` — the container app reuses the stored
	// value, so the user-side CLI never holds the bearer in memory or
	// on disk. An agent inside `clawpatrol run` therefore cannot
	// exfiltrate it.
	if gwHost == "" {
		gwHost = "clawpatrol-gateway"
	}
	if gwURL == "" || token == "" {
		fail("tsnet run: missing gateway url or api-token in %s", dir)
	}
	if gwIP == "" {
		fail("tsnet run: missing tailnet-gateway-ip in %s (re-run `clawpatrol join`)", dir)
	}

	// Ensure system extension is loaded.
	{
		c := exec.Command(macHelperPath, "install")
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		_ = c.Run()
	}

	// Start NE in tsnet mode. ts_netstack_init inside the extension
	// blocks until the tsnet node joins the tailnet (≤90s). Pass
	// token + hostname so the NE itself can POST to the gateway's
	// tailnet-only register endpoint (parent process is on the host
	// network and can't dial a 100.x address from here). Empty
	// authKey arg → container app reuses the value stored in NE
	// preferences at join time.
	hn, _ := os.Hostname()
	fmt.Fprintln(os.Stderr, "clawpatrol: joining tailnet via NE...")
	{
		c := exec.Command(macHelperPath, "start-tsnet", "", controlURL, gwHost, gwIP, token, hn)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				fail("Clawpatrol start-tsnet exit=%d", ee.ExitCode())
			}
			fail("Clawpatrol start-tsnet: %v", err)
		}
	}

	// Wait until the NE reports the tsnet IP so we know the
	// extension finished initializing. The actual /register POST
	// happens *inside* ts_netstack_init via tsServer.Dial — the
	// parent process can't dial 100.x addresses on macOS.
	tsIP := pollTsnetIPFromExtension(90 * time.Second)
	if tsIP == "" {
		fmt.Fprintln(os.Stderr, "warning: NE never reported tsnet IP — run will land in the default profile")
	}
	applyEnvPushdown(dir)

	cleanup := registerSession()
	defer cleanup()

	if len(args) == 0 {
		fail("usage: clawpatrol run -- <cmd> [args...]")
	}
	all := append([]string{"run", "--"}, args...)
	c := exec.Command(macHelperPath, all...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = os.Environ()
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fail("run: %v", err)
	}
}

// pollTsnetIPFromExtension dials the session socket repeatedly, sending
// "gettsip\n", until the extension responds with "tsip <IP>\n" (meaning
// ts_netstack_init has completed and the tsnet node has an address).
// Returns empty string on timeout.
func pollTsnetIPFromExtension(timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ip := queryTsnetIP()
		if ip != "" {
			return ip
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

func queryTsnetIP() string {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.Dial("unix", sessionSockPath)
	if err != nil {
		return ""
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("gettsip\n")); err != nil {
		return ""
	}
	buf := make([]byte, 80)
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	reply := strings.TrimSpace(string(buf[:n]))
	// reply is "tsip 100.x.x.x"
	if after, ok := strings.CutPrefix(reply, "tsip "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}
