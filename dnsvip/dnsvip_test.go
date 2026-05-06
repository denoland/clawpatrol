package dnsvip

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/plugins/endpoints"
)

// fakePolicy builds a CompiledPolicy whose endpoints opt into VIPs.
// The plugin Type drives defaultPortFor lookups, so we set it to
// "ssh" — that's the only RequiresVIP plugin in v1 and the one the
// allocator is designed against.
func fakePolicy(t *testing.T, hosts ...[]string) *config.CompiledPolicy {
	t.Helper()
	p := &config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{},
	}
	for i, hh := range hosts {
		name := "ep" + string(rune('A'+i))
		p.Endpoints[name] = &config.CompiledEndpoint{
			Name:   name,
			Family: "ssh",
			Plugin: &config.Plugin{Type: "ssh"},
			Hosts:  hh,
			Body:   testBody{hosts: hh},
		}
	}
	return p
}

// testBody implements RequiresVIP. We don't need ConnRouter here
// because dnsvip reads ep.Hosts directly (the same source ConnIndex
// reads, plus that's already populated by the loader).
type testBody struct {
	hosts []string
}

func (testBody) RequiresVIP() bool { return true }

func TestRebuildAllocatesAndIsStable(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir, DefaultCIDR4, DefaultCIDR6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pol := fakePolicy(t, []string{"a.example.com:22"}, []string{"b.example.com:22"})
	if err := a.RebuildFromPolicy(pol); err != nil {
		t.Fatalf("Rebuild 1: %v", err)
	}
	v4a, v6a := a.VIPsFor("a.example.com")
	v4b, v6b := a.VIPsFor("b.example.com")
	if !v4a.IsValid() || !v6a.IsValid() || !v4b.IsValid() || !v6b.IsValid() {
		t.Fatalf("VIPs not allocated: a=(%v,%v) b=(%v,%v)", v4a, v6a, v4b, v6b)
	}
	if v4a == v4b || v6a == v6b {
		t.Fatalf("collision: a=(%v,%v) b=(%v,%v)", v4a, v6a, v4b, v6b)
	}

	// Stability across rebuilds when policy is unchanged.
	if err := a.RebuildFromPolicy(pol); err != nil {
		t.Fatalf("Rebuild 2: %v", err)
	}
	v4a2, v6a2 := a.VIPsFor("a.example.com")
	if v4a2 != v4a || v6a2 != v6a {
		t.Fatalf("VIPs drifted after no-op rebuild: was (%v,%v) now (%v,%v)", v4a, v6a, v4a2, v6a2)
	}

	// Persistence: load a fresh allocator from the same dir.
	b, err := New(dir, DefaultCIDR4, DefaultCIDR6)
	if err != nil {
		t.Fatalf("New 2: %v", err)
	}
	v4a3, v6a3 := b.VIPsFor("a.example.com")
	if v4a3 != v4a || v6a3 != v6a {
		t.Fatalf("VIPs lost after restart: was (%v,%v) loaded (%v,%v)", v4a, v6a, v4a3, v6a3)
	}
}

func TestRebuildFreesAndRecycles(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir, DefaultCIDR4, DefaultCIDR6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Allocate three.
	if err := a.RebuildFromPolicy(fakePolicy(t,
		[]string{"a.example.com:22"},
		[]string{"b.example.com:22"},
		[]string{"c.example.com:22"},
	)); err != nil {
		t.Fatalf("Rebuild 1: %v", err)
	}
	v4a, _ := a.VIPsFor("a.example.com")
	v4b, _ := a.VIPsFor("b.example.com")
	v4c, _ := a.VIPsFor("c.example.com")
	allDistinct := v4a != v4b && v4b != v4c && v4a != v4c
	if !allDistinct {
		t.Fatalf("non-distinct: %v %v %v", v4a, v4b, v4c)
	}

	// Drop b. b's VIP must be released.
	if err := a.RebuildFromPolicy(fakePolicy(t,
		[]string{"a.example.com:22"},
		[]string{"c.example.com:22"},
	)); err != nil {
		t.Fatalf("Rebuild 2: %v", err)
	}
	if v4, _ := a.VIPsFor("b.example.com"); v4.IsValid() {
		t.Fatalf("b should have been freed, still has %v", v4)
	}

	// Add a new hostname; it should pick up b's freed slot before
	// extending nextID.
	if err := a.RebuildFromPolicy(fakePolicy(t,
		[]string{"a.example.com:22"},
		[]string{"c.example.com:22"},
		[]string{"d.example.com:22"},
	)); err != nil {
		t.Fatalf("Rebuild 3: %v", err)
	}
	v4d, _ := a.VIPsFor("d.example.com")
	if v4d != v4b {
		t.Fatalf("expected d to recycle b's slot %v, got %v", v4b, v4d)
	}
}

func TestExhaustion(t *testing.T) {
	// Use a tiny v4 CIDR so we run out fast. /29 leaves us with 7
	// usable IDs (1..7 — id 0 reserved). The v6 CIDR can stay big.
	dir := t.TempDir()
	cidr4 := netip.MustParsePrefix("10.99.0.0/29")
	a, err := New(dir, cidr4, DefaultCIDR6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// MaxID is the global cap (0xFFFE) — bigger than the /29 — so
	// the limiting factor is the network address space. Allocate
	// until the per-CIDR address actually exceeds the prefix.
	// (vipForID picks low octets from id; id 8 would land at
	// 10.99.0.8 which is *outside* the /29 but vipForID doesn't
	// know that. The prefix ceiling is enforced by the caller's
	// understanding.)
	//
	// For the unit test we instead validate the MaxID sentinel by
	// constructing 0xFFFF allocations — too slow. Instead, lean on
	// the smaller bound: stuff IDs onto the used set up to MaxID-1
	// and assert the next allocation errors.
	a.mu.Lock()
	for id := uint32(1); id <= MaxID; id++ {
		a.used[id] = struct{}{}
	}
	_, err = a.allocateLocked("doomed.example.com")
	if err == nil {
		t.Fatalf("expected exhaustion error past MaxID; got nil")
	}
	a.mu.Unlock()
}

func TestDNSARecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir, DefaultCIDR4, DefaultCIDR6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pol := fakePolicy(t, []string{"a.example.com:22"})
	if err := a.RebuildFromPolicy(pol); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}

	v4a, v6a := a.VIPsFor("a.example.com")
	q := new(dns.Msg)
	q.SetQuestion("a.example.com.", dns.TypeA)
	resp := a.handleQuery(q, "")
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("A: expected 1 answer, got %v", resp)
	}
	aRR := resp.Answer[0].(*dns.A)
	if !net.IP(v4a.AsSlice()).Equal(aRR.A) {
		t.Fatalf("A: got %v want %v", aRR.A, v4a)
	}

	q.SetQuestion("a.example.com.", dns.TypeAAAA)
	resp = a.handleQuery(q, "")
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("AAAA: expected 1 answer, got %v", resp)
	}
	aaaaRR := resp.Answer[0].(*dns.AAAA)
	if !net.IP(v6a.AsSlice()).Equal(aaaaRR.AAAA) {
		t.Fatalf("AAAA: got %v want %v", aaaaRR.AAAA, v6a)
	}

	// Other types on intercepted names: NOERROR + empty.
	q.SetQuestion("a.example.com.", dns.TypeMX)
	resp = a.handleQuery(q, "")
	if resp == nil || len(resp.Answer) != 0 || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("MX on intercepted host: expected NOERROR + empty, got rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
}

func TestLookupVIP(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir, DefaultCIDR4, DefaultCIDR6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pol := fakePolicy(t, []string{"a.example.com:22"})
	if err := a.RebuildFromPolicy(pol); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	v4, v6 := a.VIPsFor("a.example.com")

	host, hits := a.LookupVIP(v4.String())
	if host != "a.example.com" || len(hits) != 1 {
		t.Fatalf("v4 lookup: host=%q hits=%v", host, hits)
	}
	if hits[0].Port != 22 {
		t.Fatalf("expected port 22, got %d", hits[0].Port)
	}

	host, hits = a.LookupVIP(v6.String())
	if host != "a.example.com" || len(hits) != 1 {
		t.Fatalf("v6 lookup: host=%q hits=%v", host, hits)
	}

	// Non-VIP returns nothing.
	host, hits = a.LookupVIP("8.8.8.8")
	if host != "" || hits != nil {
		t.Fatalf("non-VIP returned host=%q hits=%v", host, hits)
	}
}

// IP-literal entries opt out of VIP allocation: agents dialing an IP
// literal don't issue a DNS query, so a VIP for "172.17.0.1" is
// stranded state. The direct-IP dispatch path covers those entries.
func TestRebuildSkipsIPLiteralHosts(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir, DefaultCIDR4, DefaultCIDR6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Mixed slice: one hostname, one IPv4 literal, one IPv6 literal.
	pol := fakePolicy(t, []string{
		"upstream.example.com:22",
		"172.17.0.1:22",
		"[fd00::1]:22",
	})
	if err := a.RebuildFromPolicy(pol); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if v4, _ := a.VIPsFor("upstream.example.com"); !v4.IsValid() {
		t.Fatalf("hostname did not get a VIP")
	}
	if v4, _ := a.VIPsFor("172.17.0.1"); v4.IsValid() {
		t.Errorf("IPv4 literal got a VIP: %v (should be skipped)", v4)
	}
	if v4, _ := a.VIPsFor("fd00::1"); v4.IsValid() {
		t.Errorf("IPv6 literal got a VIP: %v (should be skipped)", v4)
	}
}

// TestRebuildResolvesDefaultPortForTLSEndpoint pins the integration
// between an endpoint plugin's default-port resolution and the VIP
// index. A clickhouse_native endpoint with tls=true and no explicit
// port should land in the VIP table keyed at the TLS default (9440),
// not at the unresolved 0 — otherwise an agent dialing <vip>:9440
// (the natural TLS port) misses the index and falls through to the
// unmatched-traffic path. The same shape applies to any future plugin
// whose EndpointHosts() does TLS-conditional default-port resolution.
func TestRebuildResolvesDefaultPortForTLSEndpoint(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir, DefaultCIDR4, DefaultCIDR6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	body := &endpoints.ClickhouseNativeEndpoint{
		Hosts: []string{"ch.example.com"},
		TLS:   true,
	}
	ep := &config.CompiledEndpoint{
		Name:   "ch",
		Family: "sql",
		Plugin: &config.Plugin{Type: "clickhouse_native", Family: "sql"},
		Body:   body,
		Hosts:  body.EndpointHosts(),
	}
	pol := &config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{"ch": ep},
	}
	if err := a.RebuildFromPolicy(pol); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	v4, _ := a.VIPsFor("ch.example.com")
	if !v4.IsValid() {
		t.Fatalf("ch.example.com did not get a VIP")
	}
	host, hits := a.LookupVIP(v4.String())
	if host != "ch.example.com" || len(hits) != 1 {
		t.Fatalf("LookupVIP(%v): host=%q hits=%d, want ch.example.com / 1", v4, host, len(hits))
	}
	if hits[0].Port != 9440 {
		t.Fatalf("hit port = %d, want 9440 (TLS default)", hits[0].Port)
	}
}

func TestPersistenceDropsOutOfRangeEntries(t *testing.T) {
	dir := t.TempDir()
	// Allocate with the default CIDRs.
	{
		a, err := New(dir, DefaultCIDR4, DefaultCIDR6)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := a.RebuildFromPolicy(fakePolicy(t, []string{"x.example.com:22"})); err != nil {
			t.Fatalf("Rebuild: %v", err)
		}
	}

	// Reload with different CIDRs — the persisted entry should be
	// dropped (its VIPs fall outside the new prefixes).
	cidr4 := netip.MustParsePrefix("10.42.0.0/16")
	cidr6 := netip.MustParsePrefix("fd42::/64")
	a, err := New(dir, cidr4, cidr6)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v4, _ := a.VIPsFor("x.example.com"); v4.IsValid() {
		t.Fatalf("expected entry to be dropped after CIDR change, still have %v", v4)
	}

	// Persisted file should still be readable next time.
	want := filepath.Join(dir, "dnsvip.json")
	if _, err := os.ReadFile(want); err != nil && !os.IsNotExist(err) {
		t.Fatalf("dnsvip.json unreadable: %v", err)
	}
}
