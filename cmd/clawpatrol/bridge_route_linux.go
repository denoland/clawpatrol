//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// tunDevicePath is the device node that wireguard-go opens to create a TUN.
const tunDevicePath = "/dev/net/tun"

// ensureCharDevice creates the character device node path (major:minor) when
// it does not exist. Container runtimes do not always expose /dev/net/tun,
// but the default device cgroup allows 10:200, so a bridge with CAP_MKNOD can
// create the node itself.
func ensureCharDevice(path string, major, minor uint32) error {
	if _, err := os.Stat(path); err == nil || !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	err := unix.Mknod(path, unix.S_IFCHR|0o666, int(unix.Mkdev(major, minor)))
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("mknod %s: %w", path, err)
	}
	if err == nil {
		log.Printf("bridge: created %s (%d:%d)", path, major, minor)
	}
	return nil
}

// markControl sets SO_MARK on a socket before it connects.
func markControl(mark int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("set SO_MARK %#x: %w", mark, serr)
		}
		return nil
	}
}

// newMarkedNet returns a resolver and an HTTP client whose sockets carry
// mark, so their packets use the underlay routes (see bridge_route.go). The
// client dials hosts with a --resolve entry at their entry.
func newMarkedNet(mark int, hosts *bridgeHosts) (*net.Resolver, *http.Client) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: markControl(mark)}
	resolver := &net.Resolver{PreferGo: true, Dial: dialer.DialContext}
	dialer.Resolver = resolver
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = hosts.dialContext(dialer.DialContext)
	return resolver, &http.Client{Timeout: enrollmentHTTPTimeout, Transport: transport}
}

// installUnderlayRouting copies the pod's original default routes into table
// and adds the rules for marked packets. It is idempotent, so every bring-up
// runs it. A family without an underlay route gets only the rules, so its
// marked packets are unreachable. The IPv6 setup is best-effort when IPv4 has
// an underlay, and required when IPv6 is the only underlay.
func installUnderlayRouting(route4 linuxDefaultRoute, have4 bool, route6 linuxDefaultRoute, have6 bool, mark, table int, proto string) error {
	if !have4 && !have6 {
		return fmt.Errorf("no underlay route in either family")
	}
	if have4 {
		if err := runIP(underlayTableArgs("-4", route4, table, proto)...); err != nil {
			return fmt.Errorf("underlay table: %w", err)
		}
	}
	if err := ensureMarkRules("-4", mark, table); err != nil {
		return err
	}
	if err := runIP(fallbackDefaultArgs(proto)...); err != nil {
		return fmt.Errorf("fallback default route: %w", err)
	}
	if !have6 {
		return nil
	}
	err := runIP(underlayTableArgs("-6", route6, table, proto)...)
	if err == nil {
		err = ensureMarkRules("-6", mark, table)
	}
	if err != nil {
		if !have4 {
			return fmt.Errorf("IPv6 underlay: %w", err)
		}
		log.Printf("bridge: IPv6 underlay: %v — continuing without IPv6 control-plane routes", err)
	}
	return nil
}

func ensureMarkRules(family string, mark, table int) error {
	out, err := exec.Command("ip", family, "rule", "show").Output()
	if err != nil {
		return fmt.Errorf("ip %s rule show: %w", family, err)
	}
	for i, pref := range bridgeMarkRulePrefs {
		if ruleShowHas(string(out), pref, mark) {
			continue
		}
		if err := runIP(markRuleArgs(family, mark, table)[i]...); err != nil {
			return fmt.Errorf("mark rule: %w", err)
		}
	}
	return nil
}

// reconcileTunnelSplitRoutes makes the owned main-table routes match cidrs,
// through the original default route of each family. It removes owned routes
// that are no longer listed or that use another device, and never changes
// routes it does not own.
func reconcileTunnelSplitRoutes(cidrs []netip.Prefix, route4 linuxDefaultRoute, have4 bool, route6 linuxDefaultRoute, have6 bool, proto string) error {
	metric := strconv.Itoa(tunnelSplitRouteMetric)
	for _, fam := range []struct {
		flag, host string
		under      linuxDefaultRoute
		v6         bool
	}{{"-4", "/32", route4, false}, {"-6", "/128", route6, true}} {
		if (fam.v6 && !have6) || (!fam.v6 && !have4) {
			continue
		}
		var want []netip.Prefix
		for _, c := range cidrs {
			if c.Addr().Is6() == fam.v6 {
				want = append(want, c)
			}
		}
		out, err := exec.Command("ip", fam.flag, "-j", "route", "show", "table", "main", "proto", proto).Output()
		if err != nil {
			return fmt.Errorf("list owned %s routes: %w", fam.flag, err)
		}
		var routes []struct {
			Dst    string
			Dev    string
			Metric int
		}
		if err := json.Unmarshal(out, &routes); err != nil {
			return fmt.Errorf("decode owned %s routes: %w", fam.flag, err)
		}
		for _, r := range routes {
			if r.Metric != tunnelSplitRouteMetric || r.Dst == "default" {
				continue
			}
			dst := r.Dst
			if !strings.Contains(dst, "/") {
				dst += fam.host
			}
			if p, err := netip.ParsePrefix(dst); err == nil && r.Dev == fam.under.Dev && slices.Contains(want, p) {
				continue
			}
			if err := runIP("ip", fam.flag, "route", "del", r.Dst, "dev", r.Dev, "proto", proto, "metric", metric); err != nil {
				return fmt.Errorf("remove tunnel split route: %w", err)
			}
		}
		for _, c := range want {
			if err := runIP(tunnelSplitRouteArgs("replace", c, fam.under, proto)...); err != nil {
				return fmt.Errorf("tunnel split route: %w", err)
			}
		}
	}
	return nil
}
