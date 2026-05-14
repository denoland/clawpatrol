package config

import "net"

// BindIsPublic reports whether a listen-address host portion would
// expose the listener to the public internet. Returns true for:
//
//   - empty host or "0.0.0.0" or "::" — bind on all interfaces
//   - any IP literal that isn't loopback / RFC1918 / RFC4193 ULA /
//     link-local / CGNAT (100.64.0.0/10, where Tailscale lives)
//
// Hostnames are treated conservatively as public — operators who
// want to bind a tailnet hostname should resolve it themselves and
// use the IP literal, or accept the warning.
func BindIsPublic(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true // hostname — can't tell, assume public
	}
	if ip.IsUnspecified() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	// CGNAT 100.64.0.0/10 — Tailscale's range, not covered by
	// IsPrivate but private in practice.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	return true
}

// BindStringIsPublic parses a "host:port" listen string and reports
// whether the host portion would expose the listener publicly.
// Returns true on parse error (conservative).
func BindStringIsPublic(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	return BindIsPublic(host)
}
