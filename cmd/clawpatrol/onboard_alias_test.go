package main

import (
	"testing"
	"time"
)

func TestUniqueIPForHostname(t *testing.T) {
	r := newOnboardRegistry()
	r.knownDeviceIPs["100.1.1.1"] = true
	r.hostnameByIP["100.1.1.1"] = "avocet2"

	if got := r.UniqueIPForHostname("avocet2"); got != "100.1.1.1" {
		t.Fatalf("single-match: got %q, want %q", got, "100.1.1.1")
	}
	if got := r.UniqueIPForHostname("unknown-host"); got != "" {
		t.Fatalf("no-match: got %q, want empty", got)
	}
	if got := r.UniqueIPForHostname(""); got != "" {
		t.Fatalf("empty hostname: got %q, want empty", got)
	}

	// Second device with same hostname → collision, must refuse.
	r.knownDeviceIPs["100.2.2.2"] = true
	r.hostnameByIP["100.2.2.2"] = "avocet2"
	if got := r.UniqueIPForHostname("avocet2"); got != "" {
		t.Fatalf("collision: got %q, want empty", got)
	}

	// Hostname entry without a corresponding devices row (e.g. an
	// in-memory tsnet placeholder) must not satisfy a unique match —
	// otherwise UniqueIPForHostname would point traffic at a placeholder
	// ID that isn't actually a device.
	r2 := newOnboardRegistry()
	r2.hostnameByIP["tsnet-foo"] = "foo"
	if got := r2.UniqueIPForHostname("foo"); got != "" {
		t.Fatalf("placeholder-only hostname: got %q, want empty", got)
	}
}

func TestClaimAliasResolve(t *testing.T) {
	r := newOnboardRegistry()

	// First call for an unknown IP claims the resolution slot.
	if !r.ClaimAliasResolve("100.9.9.9", time.Minute) {
		t.Fatal("first claim should succeed")
	}
	// Second call within the window must be denied (negative cache).
	if r.ClaimAliasResolve("100.9.9.9", time.Minute) {
		t.Fatal("second claim within window should be denied")
	}
	// Backdating the trie entry past the window re-opens the slot.
	r.resolveTriedAt["100.9.9.9"] = time.Now().Add(-2 * time.Minute)
	if !r.ClaimAliasResolve("100.9.9.9", time.Minute) {
		t.Fatal("expired claim should re-open")
	}

	// Known devices and registered aliases never trigger a WhoIs lookup.
	r.knownDeviceIPs["100.1.1.1"] = true
	if r.ClaimAliasResolve("100.1.1.1", time.Minute) {
		t.Fatal("known device must not claim")
	}
	r.canonicalByAlias["100.5.5.5"] = "100.1.1.1"
	if r.ClaimAliasResolve("100.5.5.5", time.Minute) {
		t.Fatal("aliased IP must not claim")
	}

	// Empty IP is rejected so a missing-source-address bug never spams
	// WhoIs lookups for the empty string.
	if r.ClaimAliasResolve("", time.Minute) {
		t.Fatal("empty ip must not claim")
	}
}
