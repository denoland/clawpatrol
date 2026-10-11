package main

import (
	"testing"
	"time"
)

func TestUniqueIPForNodeID(t *testing.T) {
	r := newOnboardRegistry()
	r.knownDeviceIPs["100.1.1.1"] = true
	r.nodeIDByIP["100.1.1.1"] = "nodeAAAA"

	if got := r.UniqueIPForNodeID("nodeAAAA"); got != "100.1.1.1" {
		t.Fatalf("single-match: got %q, want %q", got, "100.1.1.1")
	}
	if got := r.UniqueIPForNodeID("nodeZZZZ"); got != "" {
		t.Fatalf("no-match: got %q, want empty", got)
	}
	if got := r.UniqueIPForNodeID(""); got != "" {
		t.Fatalf("empty node id: got %q, want empty", got)
	}

	// Second device bound to the same node → collision, must refuse.
	r.knownDeviceIPs["100.2.2.2"] = true
	r.nodeIDByIP["100.2.2.2"] = "nodeAAAA"
	if got := r.UniqueIPForNodeID("nodeAAAA"); got != "" {
		t.Fatalf("collision: got %q, want empty", got)
	}

	// A node binding without a corresponding devices row (e.g. an
	// in-memory tsnet placeholder) must not satisfy a unique match —
	// otherwise UniqueIPForNodeID would point traffic at a placeholder
	// ID that isn't actually a device.
	r2 := newOnboardRegistry()
	r2.nodeIDByIP["tsnet-foo"] = "nodeBBBB"
	if got := r2.UniqueIPForNodeID("nodeBBBB"); got != "" {
		t.Fatalf("placeholder-only binding: got %q, want empty", got)
	}
}

// A hostname is self-asserted by the node and released again when an
// ephemeral node goes offline, so a device row's name must not be
// enough to absorb another peer's traffic — and with it the profile's
// credentials.
func TestHostnameAloneYieldsNoAlias(t *testing.T) {
	r := newOnboardRegistry()
	r.knownDeviceIPs["100.1.1.1"] = true
	r.hostnameByIP["100.1.1.1"] = "privileged-agent"
	r.nodeIDByIP["100.1.1.1"] = "nodeAAAA"

	// The name the privileged device row carries, asserted by a node
	// that is not the one the row is bound to.
	if got := r.UniqueIPForNodeID("nodeIMPOSTOR"); got != "" {
		t.Fatalf("impostor node matched %q by name", got)
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

// AssignProfile must propagate across an IP's alias group. A Tailscale
// peer's IPv6 ULA is aliased to its IPv4; reassigning the profile on
// either address (e.g. from the dashboard) must update the whole group,
// or traffic on the un-updated address resolves to the stale profile
// while the dashboard shows the new one.
func TestAssignProfilePropagatesAcrossAlias(t *testing.T) {
	r := newOnboardRegistry()
	const v4 = "100.106.145.49"
	const v6 = "fd7a:115c:a1e0::1234"

	// Initial assignment + alias (mirrors join: v4 gets a profile, the
	// v6 ULA is linked and copies it).
	r.AssignProfile(v4, "default")
	r.RegisterIPAlias(v6, v4)
	if got := r.ProfileForIP(v6); got != "default" {
		t.Fatalf("after alias: ProfileForIP(v6) = %q, want default", got)
	}

	// Operator reassigns via the dashboard (apiAgentProfile → AssignProfile
	// on the canonical v4). The v6 alias must follow.
	r.AssignProfile(v4, "avocet2")
	if got := r.ProfileForIP(v4); got != "avocet2" {
		t.Fatalf("ProfileForIP(v4) = %q, want avocet2", got)
	}
	if got := r.ProfileForIP(v6); got != "avocet2" {
		t.Fatalf("ProfileForIP(v6) = %q, want avocet2 (alias must follow reassignment)", got)
	}

	// Reassigning via the alias address must update the canonical too.
	r.AssignProfile(v6, "default")
	if got := r.ProfileForIP(v4); got != "default" {
		t.Fatalf("ProfileForIP(v4) = %q, want default (canonical must follow alias reassignment)", got)
	}
}
