package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	// wgDefaultMTU fits a 1500-byte Ethernet path after the 80 bytes
	// of WireGuard and UDP/IP framing: the wg-quick default.
	wgDefaultMTU = 1420
	// wgMinMTU is a sanity floor for derived and configured values.
	// Tailscale paths land at exactly 1200 (1280 minus 80); anything
	// much lower is a misread rather than a real link.
	wgMinMTU = 1000
	// wgOverhead is what wg-quick subtracts from the egress interface
	// MTU: 32 bytes WireGuard, 8 UDP, up to 40 IPv6.
	wgOverhead = 80
	// wgMTUEnv overrides derivation on the client side.
	wgMTUEnv = "CLAWPATROL_WG_MTU"
)

// wgMTUForPath returns the WireGuard device MTU for an egress
// interface MTU, the way wg-quick derives it: interface MTU minus the
// framing overhead, never above the default and never below the
// sanity floor.
func wgMTUForPath(ifMTU int) int {
	m := ifMTU - wgOverhead
	if m > wgDefaultMTU {
		return wgDefaultMTU
	}
	if m < wgMinMTU {
		return wgMinMTU
	}
	return m
}

// parseRouteDev extracts the interface from one line of `ip route
// get` output ("1.2.3.4 via 10.0.0.1 dev eth0 src ... "). Empty when
// there is no dev token.
func parseRouteDev(line string) string {
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}

// wgMTUFromEnv returns the operator override, if any. Out-of-range
// values are reported rather than silently clamped.
func wgMTUFromEnv() (int, bool, error) {
	v := strings.TrimSpace(os.Getenv(wgMTUEnv))
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < wgMinMTU || n > 1500 {
		return 0, true, fmt.Errorf("%s=%q: want an integer between %d and 1500", wgMTUEnv, v, wgMinMTU)
	}
	return n, true, nil
}
