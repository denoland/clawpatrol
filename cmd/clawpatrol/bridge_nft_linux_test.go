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

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The filter goes out as one batch that replaces the table and adds the
// output chain and its rules.
func TestApplyEgressFilterBatch(t *testing.T) {
	counts := map[int]int{}
	c, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		for _, m := range req {
			counts[int(m.Header.Type)&0xff]++
		}
		return req, nil
	}))
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	if err := applyEgressFilter(c, "clawpatrol0", 111); err != nil {
		t.Fatalf("applyEgressFilter: %v", err)
	}
	want := map[int]int{
		unix.NFT_MSG_NEWTABLE: 2,
		unix.NFT_MSG_DELTABLE: 1,
		unix.NFT_MSG_NEWCHAIN: 1,
		unix.NFT_MSG_NEWRULE:  len(egressFilterRules("clawpatrol0", 111)),
	}
	for typ, n := range want {
		if counts[typ] != n {
			t.Errorf("messages of type %d = %d, want %d (all: %v)", typ, counts[typ], n, counts)
		}
	}
	if got := len(egressFilterRules("clawpatrol0", 111)); got != 7 {
		t.Fatalf("rules = %d, want 7", got)
	}
}

// With the filter and the F1 routing in a throwaway namespace, only tunnel
// and marked traffic can leave. It changes the namespace's routes and
// nftables, so it runs only when CLAWPATROL_NETNS_TEST=1.
func TestEgressFilterInNetns(t *testing.T) {
	if os.Getenv("CLAWPATROL_NETNS_TEST") != "1" {
		t.Skip("set CLAWPATROL_NETNS_TEST=1 to change this network namespace's routes and nftables")
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	restoreDefaultRoute(t)
	run("ip", "link", "add", "under1", "type", "dummy")
	run("ip", "link", "set", "under1", "up")
	run("ip", "addr", "add", "10.98.0.2/24", "dev", "under1")
	run("ip", "link", "add", "tun1", "type", "dummy")
	run("ip", "link", "set", "tun1", "up")
	run("ip", "addr", "add", "10.55.0.3/32", "dev", "tun1")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "under1").Run()
		_ = exec.Command("ip", "link", "del", "tun1").Run()
		_ = exec.Command("ip", "rule", "del", "pref", "90").Run()
		_ = exec.Command("ip", "rule", "del", "pref", "91").Run()
		_ = exec.Command("ip", "route", "flush", "table", "111").Run()
		if c, err := nftables.New(); err == nil {
			c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: bridgeNftTable})
			_ = c.Flush()
		}
	})
	if err := installUnderlayRouting(linuxDefaultRoute{Via: "10.98.0.1", Dev: "under1"}, linuxDefaultRoute{}, false, 111, 111, "111"); err != nil {
		t.Fatalf("installUnderlayRouting: %v", err)
	}
	run("ip", "route", "replace", "default", "dev", "tun1")
	for range 2 { // replacing the table must work
		if err := installEgressFilter("tun1", 111); err != nil {
			t.Fatalf("installEgressFilter: %v", err)
		}
	}

	send := func(mark bool, dst string) error {
		d := net.Dialer{}
		if mark {
			d.Control = markControl(111)
		}
		c, err := d.DialContext(context.Background(), "udp4", dst)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		_, err = c.Write([]byte("x"))
		return err
	}
	// Unmarked traffic on a CNI-style link route is dropped.
	if err := send(false, "10.98.0.7:9"); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("unmarked send on the link route: err = %v, want EPERM", err)
	}
	// The bridge's marked traffic may use it.
	if err := send(true, "10.98.0.7:9"); err != nil {
		t.Fatalf("marked send on the link route: %v", err)
	}
	// Unmarked traffic through the tunnel is allowed.
	if err := send(false, "192.0.2.10:9"); err != nil {
		t.Fatalf("unmarked send through the tunnel: %v", err)
	}
}
