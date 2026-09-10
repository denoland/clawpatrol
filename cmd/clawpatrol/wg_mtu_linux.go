package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// deriveWGClientMTU picks the client WireGuard MTU for the path to
// the gateway endpoint, the way wg-quick does: the MTU of the
// interface the kernel would use to reach the endpoint, minus the
// framing overhead. A gateway reached over Tailscale sits behind a
// 1280-byte interface, so the default 1420 produces datagrams the
// path cannot carry; nothing adapts, and every transfer over about
// 16 KiB stalls (#790). CLAWPATROL_WG_MTU overrides. The second
// return value says where the number came from, for the log.
func deriveWGClientMTU(endpoint string) (int, string) {
	if n, set, err := wgMTUFromEnv(); set {
		if err != nil {
			return wgDefaultMTU, fmt.Sprintf("default; %v", err)
		}
		return n, wgMTUEnv
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return wgDefaultMTU, "default; endpoint has no host:port"
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return wgDefaultMTU, "default; endpoint did not resolve"
	}
	out, err := exec.Command("ip", "-o", "route", "get", ips[0].String()).Output()
	if err != nil {
		return wgDefaultMTU, "default; ip route get failed"
	}
	dev := parseRouteDev(string(out))
	if dev == "" {
		return wgDefaultMTU, "default; no route device"
	}
	raw, err := os.ReadFile("/sys/class/net/" + dev + "/mtu")
	if err != nil {
		return wgDefaultMTU, "default; no mtu for " + dev
	}
	ifMTU, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || ifMTU <= 0 {
		return wgDefaultMTU, "default; unreadable mtu for " + dev
	}
	return wgMTUForPath(ifMTU), fmt.Sprintf("via %s mtu %d", dev, ifMTU)
}
