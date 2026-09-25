package main

import (
	"fmt"
	"strconv"
	"strings"
)

// Control-plane routing for `clawpatrol bridge`.
//
// The bridge's own sockets (WireGuard, gateway API, DNS lookups) carry a
// firewall mark. Two policy rules send marked packets to the underlay:
//
//	pref 90: fwmark M lookup main suppress_prefixlength 0
//	pref 91: fwmark M lookup T
//
// The first lets marked packets use the specific routes of the main table
// (the CNI's link and subnet routes) but not its default route, which points
// at the tunnel. The second sends the rest to table T, which holds a copy of
// the pod's original default route. Unmarked packets, which is all workload
// traffic, use the main table and so the tunnel. A container that shares the
// netns cannot set the mark without CAP_NET_ADMIN or CAP_NET_RAW.
const (
	bridgeRuleSuppressPref = "90"
	bridgeRuleTablePref    = "91"
	// defaultBridgeFwmark is the default --fwmark. The same number is the
	// routing table ID.
	defaultBridgeFwmark = 111
)

type linuxDefaultRoute struct {
	Dev string
	Via string
}

func parseDefaultRoute(out []byte) (linuxDefaultRoute, error) {
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return linuxDefaultRoute{}, fmt.Errorf("no default route")
	}
	var r linuxDefaultRoute
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			r.Via = fields[i+1]
		case "dev":
			r.Dev = fields[i+1]
		}
	}
	if r.Dev == "" {
		return linuxDefaultRoute{}, fmt.Errorf("default route has no dev: %s", strings.TrimSpace(string(out)))
	}
	return r, nil
}

// underlayTableArgs copies the pod's original default route into table,
// tagged with proto.
func underlayTableArgs(family string, route linuxDefaultRoute, table int, proto string) []string {
	args := []string{"ip", family, "route", "replace", "default"}
	if route.Via != "" {
		args = append(args, "via", route.Via)
	}
	return append(args, "dev", route.Dev, "table", strconv.Itoa(table), "proto", proto)
}

// markRuleArgs returns the two policy rules for marked packets, in the order
// of bridgeRuleSuppressPref and bridgeRuleTablePref.
func markRuleArgs(family string, mark, table int) [][]string {
	m := fmt.Sprintf("%#x", mark)
	return [][]string{
		{"ip", family, "rule", "add", "pref", bridgeRuleSuppressPref, "fwmark", m, "lookup", "main", "suppress_prefixlength", "0"},
		{"ip", family, "rule", "add", "pref", bridgeRuleTablePref, "fwmark", m, "lookup", strconv.Itoa(table)},
	}
}

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
