package main

import (
	"net"
	"net/url"
	"strings"
)

// isLocalGateway reports whether the gateway URL points at the
// current host. Two signals:
//
//   - URL host is a loopback alias (localhost / 127.0.0.1 / ::1 /
//     0.0.0.0).
//   - URL host resolves to an address assigned to a local interface.
//
// reason describes which signal matched; empty when local is false.
// Used to reject `clawpatrol join --whole-machine` against the
// gateway host itself, where wg-quick's catch-all routing creates a
// loop that captures the gateway daemon's own outbound traffic.
func isLocalGateway(gatewayURL string) (local bool, reason string) {
	u, err := url.Parse(gatewayURL)
	if err != nil {
		return false, ""
	}
	if u.Host == "" {
		// Schemeless input like `localhost:9080` parses as
		// Scheme/Opaque; retry with http:// to extract the host.
		u, err = url.Parse("http://" + gatewayURL)
		if err != nil {
			return false, ""
		}
	}
	host := u.Hostname()
	if host == "" {
		return false, ""
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true, "host is " + host
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return false, ""
	}
	locals, err := localInterfaceIPs()
	if err != nil {
		return false, ""
	}
	for _, ip := range ips {
		for _, lip := range locals {
			if ip == lip {
				return true, host + " resolves to " + ip +
					" (local interface)"
			}
		}
	}
	return false, ""
}

// localInterfaceIPs returns every IP assigned to a local interface
// as a flat string slice for cheap comparison against resolved
// gateway IPs.
func localInterfaceIPs() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		out = append(out, ip.String())
	}
	return out, nil
}
