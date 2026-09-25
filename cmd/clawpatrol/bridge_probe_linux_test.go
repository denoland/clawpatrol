//go:build linux

package main

import (
	"errors"
	"net/netip"
	"testing"
)

// The prober reuses one socket for many probes and matches each reply to
// its own sequence number.
func TestICMPProberLoopback(t *testing.T) {
	p, err := openICMPProber(netip.MustParseAddr("127.0.0.1"))
	if errors.Is(err, errProbeUnavailable) {
		t.Skipf("no ICMP socket in this environment: %v", err)
	}
	if err != nil {
		t.Fatalf("openICMPProber: %v", err)
	}
	defer func() { _ = p.Close() }()
	t.Logf("raw socket: %t", p.raw)
	for i := range 3 {
		if err := p.Probe(wgProbeTimeout); err != nil {
			t.Fatalf("probe %d (raw=%t): %v", i+1, p.raw, err)
		}
	}
}
