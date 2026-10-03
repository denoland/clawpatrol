//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// bridgeResolver resolves the gateway API and WireGuard endpoint names. The
// bridge replaces it with a marked resolver at startup.
var bridgeResolver = net.DefaultResolver

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
// mark, so their packets use the underlay routes (see bridge_route.go).
func newMarkedNet(mark int) (*net.Resolver, *http.Client) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: markControl(mark)}
	resolver := &net.Resolver{PreferGo: true, Dial: dialer.DialContext}
	dialer.Resolver = resolver
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	return resolver, &http.Client{Timeout: enrollmentHTTPTimeout, Transport: transport}
}

// installUnderlayRouting copies the pod's original default routes into table
// and adds the rules for marked packets. It is idempotent, so every bring-up
// runs it. IPv6 is best-effort, like the rest of the bridge's IPv6 setup.
func installUnderlayRouting(route4, route6 linuxDefaultRoute, have6 bool, mark, table int, proto string) error {
	if err := runIP(underlayTableArgs("-4", route4, table, proto)...); err != nil {
		return fmt.Errorf("underlay table: %w", err)
	}
	if err := ensureMarkRules("-4", mark, table); err != nil {
		return err
	}
	if !have6 {
		return nil
	}
	if err := runIP(underlayTableArgs("-6", route6, table, proto)...); err != nil {
		log.Printf("bridge: IPv6 underlay table: %v — continuing without IPv6 control-plane routes", err)
		return nil
	}
	if err := ensureMarkRules("-6", mark, table); err != nil {
		log.Printf("bridge: IPv6 mark rules: %v — continuing without IPv6 control-plane routes", err)
	}
	return nil
}

func ensureMarkRules(family string, mark, table int) error {
	out, err := exec.Command("ip", family, "rule", "show").Output()
	if err != nil {
		return fmt.Errorf("ip %s rule show: %w", family, err)
	}
	for i, pref := range []string{bridgeRuleSuppressPref, bridgeRuleTablePref} {
		if ruleShowHas(string(out), pref, mark) {
			continue
		}
		if err := runIP(markRuleArgs(family, mark, table)[i]...); err != nil {
			return fmt.Errorf("mark rule: %w", err)
		}
	}
	return nil
}
