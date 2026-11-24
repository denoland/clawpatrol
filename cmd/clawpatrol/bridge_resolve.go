package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// bridgeResolver resolves the gateway API and WireGuard endpoint names that
// have no --resolve entry. The bridge replaces it with a marked resolver at
// startup.
var bridgeResolver = net.DefaultResolver

// bridgeStaticHosts holds the --resolve entries of the running bridge. It is
// nil until the bridge starts.
var bridgeStaticHosts *bridgeHosts

// bridgeHostMap is the value of the repeatable --resolve flag. Keys are host
// names in lower case without a trailing dot.
type bridgeHostMap map[string]netip.Addr

func (m *bridgeHostMap) String() string {
	if m == nil || len(*m) == 0 {
		return ""
	}
	entries := make([]string, 0, len(*m))
	for host, ip := range *m {
		entries = append(entries, host+"="+ip.String())
	}
	sort.Strings(entries)
	return strings.Join(entries, ",")
}

// Set parses one <host>=<ip> entry.
func (m *bridgeHostMap) Set(v string) error {
	rawHost, rawIP, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("--resolve %q must be <host>=<ip>", v)
	}
	host := normalizeBridgeHost(rawHost)
	if err := validateBridgeHost(host); err != nil {
		return fmt.Errorf("--resolve %q: %w", v, err)
	}
	ip, err := netip.ParseAddr(rawIP)
	if err != nil {
		return fmt.Errorf("--resolve %q: %q is not an IP address", v, rawIP)
	}
	if *m == nil {
		*m = bridgeHostMap{}
	}
	if _, dup := (*m)[host]; dup {
		return fmt.Errorf("--resolve %q: %s has more than one entry", v, host)
	}
	(*m)[host] = ip.Unmap()
	return nil
}

func normalizeBridgeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// validateBridgeHost accepts a DNS name: dot-separated labels of letters,
// digits, hyphens, and underscores. It rejects ports, IP literals, and
// brackets.
func validateBridgeHost(host string) error {
	if host == "" {
		return fmt.Errorf("host must not be empty")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return fmt.Errorf("host %q is an IP address; it does not use DNS", host)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("host %q is not a valid DNS name", host)
		}
		for _, r := range label {
			if !isBridgeHostRune(r) {
				return fmt.Errorf("host %q is not a valid DNS name", host)
			}
		}
	}
	return nil
}

func isBridgeHostRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_'
}

// bridgeHosts answers lookups from the --resolve entries and logs each name
// that has no entry once, when there is at least one entry.
type bridgeHosts struct {
	static bridgeHostMap

	mu     sync.Mutex
	viaDNS map[string]bool
}

func newBridgeHosts(m bridgeHostMap) *bridgeHosts {
	return &bridgeHosts{static: m, viaDNS: map[string]bool{}}
}

// logMappings logs each entry once, at startup.
func (h *bridgeHosts) logMappings() {
	if h == nil {
		return
	}
	hosts := make([]string, 0, len(h.static))
	for host := range h.static {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		log.Printf("bridge: --resolve maps %s to %s; this name does not use DNS", host, h.static[host])
	}
}

// lookup returns the entry for host. When host has no entry, it logs once
// that host uses DNS.
func (h *bridgeHosts) lookup(host string) (netip.Addr, bool) {
	if h == nil || len(h.static) == 0 {
		return netip.Addr{}, false
	}
	key := normalizeBridgeHost(host)
	if ip, ok := h.static[key]; ok {
		return ip, true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.viaDNS[key] {
		h.viaDNS[key] = true
		log.Printf("bridge: resolving %s through DNS (no --resolve entry)", key)
	}
	return netip.Addr{}, false
}

// dialContext returns a dial function that sends a connection to a mapped
// host to its --resolve address. The caller keeps the URL host, so TLS SNI,
// certificate verification, and the Host header use the name.
func (h *bridgeHosts) dialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err == nil {
			if _, perr := netip.ParseAddr(host); perr != nil {
				if ip, ok := h.lookup(host); ok {
					addr = net.JoinHostPort(ip.String(), port)
				}
			}
		}
		return dial(ctx, network, addr)
	}
}

// lookupHostIPs resolves host: an IP literal as is, a --resolve name to its
// entry, and other names through bridgeResolver.
func lookupHostIPs(host string) ([]netip.Addr, error) {
	if host == "" {
		return nil, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if ip, ok := bridgeStaticHosts.lookup(host); ok {
		return []netip.Addr{ip}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := bridgeResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		// Unmap 4-in-6 so Is4()/family checks behave.
		out = append(out, addr.Unmap())
	}
	return out, nil
}
