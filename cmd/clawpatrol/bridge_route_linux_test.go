//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestBuildTunWGIpcSetsFwmark(t *testing.T) {
	priv, _, pub, err := wgGenKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	ipc, err := buildTunWGIpc(priv, pub, "192.0.2.1:51820", 25, 111)
	if err != nil {
		t.Fatalf("buildTunWGIpc: %v", err)
	}
	if !strings.Contains(ipc, "\nfwmark=111\n") {
		t.Fatalf("IPC has no fwmark line:\n%s", ipc)
	}
	// wireguard-go must accept it as a device-level key.
	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(got, "fwmark=111") {
		t.Fatalf("device fwmark not set:\n%s", got)
	}
}

// markControl sets SO_MARK on dialed sockets. Needs CAP_NET_ADMIN (or
// CAP_NET_RAW on Linux 5.17+).
func TestMarkControlSetsSOMark(t *testing.T) {
	ln, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	d := net.Dialer{Control: markControl(0x6f)}
	c, err := d.DialContext(context.Background(), "udp4", ln.LocalAddr().String())
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("no permission to set SO_MARK: %v", err)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	raw, err := c.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var mark int
	var gerr error
	if err := raw.Control(func(fd uintptr) { mark, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) }); err != nil || gerr != nil {
		t.Fatalf("read SO_MARK: %v %v", err, gerr)
	}
	if mark != 0x6f {
		t.Fatalf("SO_MARK = %#x, want 0x6f", mark)
	}
}

// installUnderlayRouting in a throwaway network namespace: marked packets use
// the underlay, unmarked packets use the tunnel default. It changes the
// namespace's routes, so it runs only when CLAWPATROL_NETNS_TEST=1 (for
// example in a container with NET_ADMIN).
func TestInstallUnderlayRoutingInNetns(t *testing.T) {
	if os.Getenv("CLAWPATROL_NETNS_TEST") != "1" {
		t.Skip("set CLAWPATROL_NETNS_TEST=1 to change this network namespace's routes")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	restoreDefaultRoute(t)
	// An underlay (dummy "eth0" with a gateway) and a tunnel (dummy "tun0").
	run("ip", "link", "add", "under0", "type", "dummy")
	run("ip", "link", "set", "under0", "up")
	run("ip", "addr", "add", "10.99.0.2/24", "dev", "under0")
	run("ip", "link", "add", "tun0", "type", "dummy")
	run("ip", "link", "set", "tun0", "up")
	run("ip", "addr", "add", "10.55.0.2/32", "dev", "tun0")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "under0").Run()
		_ = exec.Command("ip", "link", "del", "tun0").Run()
		_ = exec.Command("ip", "rule", "del", "pref", "90").Run()
		_ = exec.Command("ip", "rule", "del", "pref", "91").Run()
		_ = exec.Command("ip", "route", "flush", "table", "111").Run()
		_ = exec.Command("ip", "route", "del", "default", "dev", "lo", "metric", bridgeFallbackMetric).Run()
	})
	underlay := linuxDefaultRoute{Via: "10.99.0.1", Dev: "under0"}

	for range 2 { // idempotent
		if err := installUnderlayRouting(underlay, linuxDefaultRoute{}, false, 111, 111, "111"); err != nil {
			t.Fatalf("installUnderlayRouting: %v", err)
		}
	}
	if n := strings.Count(run("ip", "rule", "show"), "fwmark 0x6f"); n != 2 {
		t.Fatalf("fwmark rules = %d, want 2 after two installs", n)
	}
	run("ip", "route", "replace", "default", "dev", "tun0")

	if got := run("ip", "route", "get", "192.0.2.10"); !strings.Contains(got, "dev tun0") {
		t.Fatalf("unmarked route = %q, want dev tun0", got)
	}
	if got := run("ip", "route", "get", "192.0.2.10", "mark", "0x6f"); !strings.Contains(got, "via 10.99.0.1 dev under0") {
		t.Fatalf("marked route = %q, want via 10.99.0.1 dev under0", got)
	}
	// A marked packet to an address on a link route keeps its direct path.
	if got := run("ip", "route", "get", "10.99.0.7", "mark", "0x6f"); strings.Contains(got, "via") || !strings.Contains(got, "dev under0") {
		t.Fatalf("marked link-route destination = %q, want direct on under0", got)
	}

	// Tunnel down (the reconnect gap): unmarked traffic falls back to
	// loopback, marked traffic still uses the underlay, and the underlay is
	// recovered from the table rather than the fallback route.
	run("ip", "link", "set", "tun0", "down")
	if got := run("ip", "route", "get", "192.0.2.10"); !strings.Contains(got, "dev lo") {
		t.Fatalf("unmarked route in the gap = %q, want dev lo", got)
	}
	if got := run("ip", "route", "get", "192.0.2.10", "mark", "0x6f"); !strings.Contains(got, "via 10.99.0.1 dev under0") {
		t.Fatalf("marked route in the gap = %q, want via 10.99.0.1 dev under0", got)
	}
	route, src, ok := discoverUnderlayRoute("-4", 111, "tun0")
	if !ok || src != "table" || route != underlay {
		t.Fatalf("discoverUnderlayRoute = %+v, %q, %t; want the table copy", route, src, ok)
	}
}

// The owned routes use the original gateway, a CNI route for the same prefix
// wins, the routes survive a tunnel teardown, and a new list reconciles.
func TestReconcileTunnelSplitRoutesInNetns(t *testing.T) {
	if os.Getenv("CLAWPATROL_NETNS_TEST") != "1" {
		t.Skip("set CLAWPATROL_NETNS_TEST=1 to change this network namespace's routes")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	restoreDefaultRoute(t)
	for _, l := range []struct{ name, addr string }{
		{"under0", "10.99.0.2/24"}, {"under1", "10.98.0.2/24"}, {"tun0", "10.55.0.2/32"},
	} {
		run("ip", "link", "add", l.name, "type", "dummy")
		run("ip", "link", "set", l.name, "up")
		run("ip", "addr", "add", l.addr, "dev", l.name)
	}
	t.Cleanup(func() {
		for _, l := range []string{"under0", "under1", "tun0"} {
			_ = exec.Command("ip", "link", "del", l).Run()
		}
		_ = exec.Command("ip", "rule", "del", "pref", "90").Run()
		_ = exec.Command("ip", "rule", "del", "pref", "91").Run()
		_ = exec.Command("ip", "route", "flush", "table", "111").Run()
		_ = exec.Command("ip", "route", "del", "default", "dev", "lo", "metric", bridgeFallbackMetric).Run()
	})
	owned := func() int { return strings.Count(run("ip", "route", "show", "proto", "111"), "metric 42760") }
	routeGet := func(addr, want string) {
		t.Helper()
		if got := run("ip", "route", "get", addr); !strings.Contains(got, want) {
			t.Fatalf("route to %s = %q, want %q", addr, got, want)
		}
	}

	under := linuxDefaultRoute{Via: "10.99.0.1", Dev: "under0"}
	if err := installUnderlayRouting(under, linuxDefaultRoute{}, false, 111, 111, "111"); err != nil {
		t.Fatal(err)
	}
	run("ip", "route", "add", "10.200.0.0/16", "dev", "under1") // a CNI route
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16"), netip.MustParsePrefix("10.200.0.0/16")}
	for range 2 { // idempotent
		if err := reconcileTunnelSplitRoutes(cidrs, under, linuxDefaultRoute{}, false, "111"); err != nil {
			t.Fatal(err)
		}
	}
	run("ip", "route", "replace", "default", "dev", "tun0")
	if n := owned(); n != 2 {
		t.Fatalf("owned routes = %d, want 2", n)
	}
	routeGet("10.244.1.5", "via 10.99.0.1 dev under0")
	routeGet("10.200.1.1", "dev under1") // the CNI route wins
	routeGet("192.0.2.10", "dev tun0")

	run("ip", "link", "set", "tun0", "down") // the reconnect gap
	routeGet("10.244.1.5", "via 10.99.0.1 dev under0")
	routeGet("192.0.2.10", "dev lo")

	// A narrowed list on a new underlay device.
	under = linuxDefaultRoute{Via: "10.98.0.1", Dev: "under1"}
	if err := reconcileTunnelSplitRoutes(cidrs[:1], under, linuxDefaultRoute{}, false, "111"); err != nil {
		t.Fatal(err)
	}
	if n := owned(); n != 1 {
		t.Fatalf("owned routes after narrowing = %d, want 1", n)
	}
	routeGet("10.244.1.5", "via 10.98.0.1 dev under1")
	if err := reconcileTunnelSplitRoutes(nil, under, linuxDefaultRoute{}, false, "111"); err != nil {
		t.Fatal(err)
	}
	if n := owned(); n != 0 {
		t.Fatalf("owned routes after removal = %d, want 0", n)
	}
	routeGet("10.200.1.1", "dev under1") // the CNI route is untouched
}

// restoreDefaultRoute puts the namespace's IPv4 default route back after a
// test that replaces it, so later tests in the same process keep their
// network. Register it before the test's other cleanups so it runs last.
func restoreDefaultRoute(t *testing.T) {
	t.Helper()
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		t.Fatalf("ip route show default: %v", err)
	}
	orig := strings.Fields(strings.TrimSpace(strings.Split(string(out), "\n")[0]))
	t.Cleanup(func() {
		if len(orig) == 0 {
			return
		}
		args := append([]string{"-4", "route", "replace"}, orig...)
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Errorf("restore default route %q: %v\n%s", orig, err, out)
		}
	})
}

// With loose rp_filter and no main-table default (the tunnel is gone), a
// reply to a marked control-plane socket is accepted only because of the
// loopback fallback route.
func TestMarkedRepliesWithoutTunnelInNetns(t *testing.T) {
	if os.Getenv("CLAWPATROL_NETNS_TEST") != "1" {
		t.Skip("set CLAWPATROL_NETNS_TEST=1 to change this network namespace's routes")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	restoreDefaultRoute(t)
	peer := exec.Command("sleep", "infinity")
	peer.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Process.Kill(); _ = peer.Wait() })
	pid := strconv.Itoa(peer.Process.Pid)
	peerRun := func(args ...string) string {
		t.Helper()
		return run(append([]string{"nsenter", "-t", pid, "-n", "--"}, args...)...)
	}
	const gw, server = "10.47.0.1", "10.47.0.140"
	run("ip", "link", "add", "veth-under", "type", "veth", "peer", "name", "cni", "netns", pid)
	run("ip", "link", "set", "veth-under", "up")
	run("ip", "addr", "add", "10.47.0.22/32", "dev", "veth-under")
	peerRun("ip", "link", "set", "lo", "up")
	peerRun("ip", "link", "set", "cni", "up")
	peerRun("ip", "addr", "add", gw+"/32", "dev", "cni")
	peerRun("ip", "addr", "add", server+"/32", "dev", "cni")
	peerRun("ip", "route", "add", "10.47.0.22/32", "dev", "cni")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "veth-under").Run()
		_ = exec.Command("ip", "rule", "del", "pref", "90").Run()
		_ = exec.Command("ip", "rule", "del", "pref", "91").Run()
		_ = exec.Command("ip", "route", "flush", "table", "111").Run()
		_ = exec.Command("ip", "route", "del", "default", "dev", "lo", "metric", bridgeFallbackMetric).Run()
	})
	for _, scope := range []string{"all", "veth-under"} {
		for key, value := range map[string]string{"rp_filter": "2", "src_valid_mark": "0"} {
			if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+scope+"/"+key, []byte(value), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	under := linuxDefaultRoute{Via: gw, Dev: "veth-under", OnLink: true}
	if err := installUnderlayRouting(under, linuxDefaultRoute{}, false, 111, 111, "111"); err != nil {
		t.Fatal(err)
	}
	// No main-table default other than the loopback fallback.
	for _, line := range strings.Split(strings.TrimSpace(run("ip", "-4", "route", "show", "default")), "\n") {
		if f := strings.Fields(line); len(f) > 0 && !strings.Contains(line, "dev lo ") {
			run(append([]string{"ip", "-4", "route", "del"}, f...)...)
		}
	}
	if route := run("ip", "-4", "route", "get", server); !strings.Contains(route, "dev lo") {
		t.Fatalf("unmarked route without the tunnel: %s", route)
	}

	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	addr := startBridgeBootstrapPeer(t, bin, pid, server)
	if err := markedBootstrapRoundTrip(addr, defaultBridgeFwmark); err != nil {
		t.Fatalf("marked reply with the loopback fallback: %v", err)
	}
	run("ip", "route", "del", "default", "dev", "lo", "metric", bridgeFallbackMetric)
	if err := markedBootstrapRoundTrip(addr, defaultBridgeFwmark); !os.IsTimeout(err) {
		t.Fatalf("marked reply without any main default: %v, want timeout", err)
	}
}

func startBridgeBootstrapPeer(t *testing.T, bin, pid, addr string) string {
	t.Helper()
	cmd := exec.Command("nsenter", "-t", pid, "-n", "--", bin, "-test.run=^TestBridgeBootstrapPeer$")
	cmd.Env = append(os.Environ(), "CLAWPATROL_TEST_BOOTSTRAP_PEER="+addr)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	endpoint, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("open bootstrap peer: %v", err)
	}
	return strings.TrimSpace(endpoint)
}

func markedBootstrapRoundTrip(addr string, mark int) error {
	dialer := net.Dialer{Timeout: time.Second, Control: markControl(mark)}
	conn, err := dialer.DialContext(context.Background(), "udp4", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		return err
	}
	var reply [1]byte
	if _, err := conn.Read(reply[:]); err != nil {
		return err
	}
	if reply[0] != 1 {
		return fmt.Errorf("unexpected bootstrap reply: %v", reply)
	}
	return nil
}

func TestBridgeBootstrapPeer(t *testing.T) {
	addr := os.Getenv("CLAWPATROL_TEST_BOOTSTRAP_PEER")
	if addr == "" {
		t.Skip("helper for the isolated packet test")
	}
	conn, err := net.ListenPacket("udp4", net.JoinHostPort(addr, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintln(os.Stdout, conn.LocalAddr())
	var packet [32]byte
	for {
		n, peer, err := conn.ReadFrom(packet[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.WriteTo(packet[:n], peer); err != nil {
			t.Fatal(err)
		}
	}
}
