//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

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

	route, src, ok := discoverUnderlayRoute("-4", 111, "tun0")
	if !ok || src != "table" || route != underlay {
		t.Fatalf("discoverUnderlayRoute = %+v, %q, %t; want the table copy", route, src, ok)
	}
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
