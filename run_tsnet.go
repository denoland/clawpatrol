package main

// Cross-platform tsnet helpers shared by `clawpatrol join` (CA fetch
// + node-state seeding) and `clawpatrol run` (per-namespace
// bring-up). The Linux-specific TUN handoff lives in
// run_tsnet_linux.go; everything that can be expressed without a
// tun.Device sits here so the same tsnet glue compiles on both
// linux and darwin.

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

// exitNodePrefs resolves the operator's exit-node value to an IP and
// packages it as a MaskedPrefs. IP literals go straight in;
// anything else is matched (case-insensitively) against peer Hostname
// / DNSName. We surface a clear error when the gateway isn't visible
// yet so the operator hits a real failure ("no peer matched") rather
// than silently routing in the clear.
func exitNodePrefs(status *ipnstate.Status, exitNode string) (*ipn.MaskedPrefs, error) {
	if ip, err := netip.ParseAddr(exitNode); err == nil {
		return &ipn.MaskedPrefs{
			ExitNodeIPSet: true,
			Prefs:         ipn.Prefs{ExitNodeIP: ip},
		}, nil
	}
	want := strings.ToLower(strings.TrimSuffix(exitNode, "."))
	for _, p := range status.Peer {
		if p == nil {
			continue
		}
		dns := strings.ToLower(strings.TrimSuffix(p.DNSName, "."))
		host := strings.ToLower(p.HostName)
		// MagicDNS DNSNames look like "host.tail-xxxx.ts.net"; an
		// operator supplying just "host" should still match.
		if want == host || want == dns || strings.HasPrefix(dns, want+".") {
			if len(p.TailscaleIPs) == 0 {
				return nil, fmt.Errorf("tsnet exit-node %q matched peer but it has no tailnet IP yet", exitNode)
			}
			return &ipn.MaskedPrefs{
				ExitNodeIPSet: true,
				Prefs:         ipn.Prefs{ExitNodeIP: p.TailscaleIPs[0]},
			}, nil
		}
	}
	return nil, fmt.Errorf("tsnet exit-node %q: no peer matched (peer must be online and visible to this tailnet)", exitNode)
}

// joinAddrs renders a slice of "ip/prefix" strings into the wg-quick
// `Address =` style ("v4/32, v6/128") that the netns-side child
// passes to `ip addr add`.
func joinAddrs(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		out := parts[0]
		for _, p := range parts[1:] {
			out += ", " + p
		}
		return out
	}
}

// defaultTsnetClientDir is the on-disk path holding the tsnet client
// node identity persisted by `clawpatrol join` and reused by
// `clawpatrol run`. Living under defaultClawpatrolDir keeps it next
// to ca.crt / api-token / wg.conf — the join's other side-effects.
func defaultTsnetClientDir() string {
	return filepath.Join(defaultClawpatrolDir(), tsnetClientDir)
}
