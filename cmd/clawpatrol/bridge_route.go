package main

import (
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
)

// Control-plane routing for `clawpatrol bridge`.
//
// The bridge's own sockets (WireGuard, gateway API, DNS lookups) carry a
// firewall mark. Three policy rules send marked packets to the underlay:
//
//	pref 90: fwmark M lookup main suppress_prefixlength 0
//	pref 91: fwmark M lookup T
//	pref 92: fwmark M unreachable
//
// The first lets marked packets use the specific routes of the main table
// (the CNI's link and subnet routes) but not its default route, which points
// at the tunnel. The second sends the rest to table T, which holds a copy of
// the pod's original default route. The third stops a marked packet that
// neither rule routes, for example when table T loses its route. Without it
// the packet falls through to the main table's default route, so the
// bridge's WireGuard packets loop back into the tunnel. Unmarked packets, which is all workload
// traffic, use the main table and so the tunnel. A container that shares the
// netns cannot set the mark without CAP_NET_ADMIN or CAP_NET_RAW.
//
// The bridge needs an underlay default route in at least one family. A family
// without one still gets the rules, so its marked packets are unreachable,
// and the tunnel still carries its workload traffic. On a single-stack IPv6
// cluster the workload then reaches IPv4 only through the tunnel.
//
// The main table also gets a last-resort IPv4 default route to loopback with
// the highest metric. Reverse-path filtering drops a received packet whose
// source has no route in the main table, and the pod's netns runs loose
// rp_filter with a read-only /proc/sys. While the tunnel is down the main
// table would have no default route, so replies from DNS and the gateway API
// to the bridge would be dropped and it could not re-enroll. Unmarked packets
// that use the loopback route are dropped, so the pod still fails closed.
const (
	bridgeRuleSuppressPref    = "90"
	bridgeRuleTablePref       = "91"
	bridgeRuleUnreachablePref = "92"
	// defaultBridgeFwmark is the default --fwmark. The same number is the
	// routing table ID.
	defaultBridgeFwmark = 111
)

type linuxDefaultRoute struct {
	Dev    string
	Via    string
	OnLink bool
}

func parseDefaultRoute(out []byte) (linuxDefaultRoute, error) {
	line, _, _ := strings.Cut(string(out), "\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return linuxDefaultRoute{}, fmt.Errorf("no default route")
	}
	var r linuxDefaultRoute
	for i, field := range fields {
		switch {
		case field == "via" && i+1 < len(fields):
			r.Via = fields[i+1]
		case field == "dev" && i+1 < len(fields):
			r.Dev = fields[i+1]
		case field == "onlink":
			r.OnLink = true
		}
	}
	if r.Dev == "" {
		return linuxDefaultRoute{}, fmt.Errorf("default route has no dev: %s", strings.TrimSpace(string(out)))
	}
	return r, nil
}

// bridgeFallbackMetric is the metric of the loopback default route, so any
// other default route wins.
const bridgeFallbackMetric = "4294967295"

// fallbackDefaultArgs adds the loopback default route to the main table.
func fallbackDefaultArgs(proto string) []string {
	return []string{"ip", "-4", "route", "replace", "default", "dev", "lo", "metric", bridgeFallbackMetric, "proto", proto}
}

// firstDefaultRoute returns the first route in `ip route show default` output
// whose device is not in skip.
func firstDefaultRoute(out []byte, skip ...string) (linuxDefaultRoute, bool) {
	for _, line := range strings.Split(string(out), "\n") {
		r, err := parseDefaultRoute([]byte(line))
		if err != nil {
			continue
		}
		skipped := false
		for _, dev := range skip {
			if r.Dev == dev {
				skipped = true
				break
			}
		}
		if !skipped {
			return r, true
		}
	}
	return linuxDefaultRoute{}, false
}

// underlayTableArgs copies the pod's original default route into table,
// tagged with proto.
func underlayTableArgs(family string, route linuxDefaultRoute, table int, proto string) []string {
	args := []string{"ip", family, "route", "replace", "default"}
	if route.Via != "" {
		args = append(args, "via", route.Via)
	}
	args = append(args, "dev", route.Dev, "table", strconv.Itoa(table), "proto", proto)
	if route.OnLink {
		args = append(args, "onlink")
	}
	return args
}

// tunnelSplitRouteMetric and the route protocol mark the main-table routes
// the bridge owns for tunnel_split_cidrs. The high metric lets a route
// that the CNI installed for the same prefix win.
const tunnelSplitRouteMetric = 42760

// bridgeTunnelSplitCIDRs parses the enrolled list. It logs and skips entries
// that are invalid, that contain a tunnel address, or whose family has no
// underlay route in the Pod. The gateway validates the list too, so the
// first two checks only cover version skew.
func bridgeTunnelSplitCIDRs(raw []string, tunnel []netip.Addr, have4, have6 bool) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range raw {
		p, err := config.ParseTunnelSplitCIDRs([]string{s})
		if err != nil {
			log.Printf("bridge: ignoring tunnel_split_cidrs entry: %v", err)
			continue
		}
		c := p[0]
		if c.Addr().Is6() && !have6 {
			log.Printf("bridge: ignoring %s: the Pod has no IPv6 underlay route", c)
			continue
		}
		if c.Addr().Is4() && !have4 {
			log.Printf("bridge: ignoring %s: the Pod has no IPv4 underlay route", c)
			continue
		}
		if i := slices.IndexFunc(tunnel, c.Contains); i >= 0 {
			log.Printf("bridge: ignoring %s: it contains tunnel address %s", c, tunnel[i])
			continue
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// tunnelSplitRouteArgs builds the ip command for one owned route. Only
// replace needs the next hop.
func tunnelSplitRouteArgs(action string, cidr netip.Prefix, under linuxDefaultRoute, proto string) []string {
	family := "-4"
	if cidr.Addr().Is6() {
		family = "-6"
	}
	args := []string{"ip", family, "route", action, cidr.String()}
	if action == "replace" && under.Via != "" {
		args = append(args, "via", under.Via)
	}
	args = append(args, "dev", under.Dev, "proto", proto, "metric", strconv.Itoa(tunnelSplitRouteMetric))
	if action == "replace" && under.OnLink {
		args = append(args, "onlink")
	}
	return args
}

// tunnelSplitRouteSummary describes the split routes of each family with the
// underlay route that carries them, for the bring-up log.
func tunnelSplitRouteSummary(cidrs []netip.Prefix, route4, route6 linuxDefaultRoute) string {
	var parts []string
	for _, fam := range []struct {
		under linuxDefaultRoute
		v6    bool
	}{{route4, false}, {route6, true}} {
		var cs []netip.Prefix
		for _, c := range cidrs {
			if c.Addr().Is6() == fam.v6 {
				cs = append(cs, c)
			}
		}
		if len(cs) == 0 {
			continue
		}
		part := fmt.Sprintf("%v", cs)
		if fam.under.Via != "" {
			part += " via " + fam.under.Via
		}
		parts = append(parts, part+" dev "+fam.under.Dev)
	}
	return strings.Join(parts, "; ")
}

// markRuleArgs returns the policy rules for marked packets, in the order of
// bridgeMarkRulePrefs.
func markRuleArgs(family string, mark, table int) [][]string {
	m := fmt.Sprintf("%#x", mark)
	return [][]string{
		{"ip", family, "rule", "add", "pref", bridgeRuleSuppressPref, "fwmark", m, "lookup", "main", "suppress_prefixlength", "0"},
		{"ip", family, "rule", "add", "pref", bridgeRuleTablePref, "fwmark", m, "lookup", strconv.Itoa(table)},
		{"ip", family, "rule", "add", "pref", bridgeRuleUnreachablePref, "fwmark", m, "unreachable"},
	}
}

var bridgeMarkRulePrefs = []string{bridgeRuleSuppressPref, bridgeRuleTablePref, bridgeRuleUnreachablePref}

// ruleShowHas reports whether `ip rule show` output has a rule at pref that
// matches mark.
func ruleShowHas(out, pref string, mark int) bool {
	want := fmt.Sprintf("fwmark %#x", mark)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, pref+":") && strings.Contains(line, want) {
			return true
		}
	}
	return false
}

// validateBridgeFwmark checks --fwmark. It is also the routing table ID, so
// it must not name the kernel's local, main, or default table.
func validateBridgeFwmark(mark int) error {
	if mark < 1 || mark > 0xffffffff {
		return fmt.Errorf("--fwmark %d must be in 1..4294967295", mark)
	}
	switch mark {
	case 253, 254, 255:
		return fmt.Errorf("--fwmark %d is a reserved routing table (default, main, local)", mark)
	}
	return nil
}
