package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/net/tsaddr"

	"github.com/denoland/clawpatrol/internal/config"
)

func publicRelayPolicy() relayDestPolicy {
	return relayDestPolicy{mode: relayDestPublic}
}

func tailnetRelayPolicy() relayDestPolicy {
	return relayDestPolicy{mode: relayDestPublic, tailnet: true}
}

// The classes an agent has no business steering the gateway onto. The
// gateway dials from the host, which sits on the host's own loopback,
// the operator's LAN, and — on a cloud instance — a metadata service
// whose credentials are the gateway's own.
func TestRelayDestRefusesHostNetworks(t *testing.T) {
	refused := []string{
		"127.0.0.1",
		"127.1.2.3",
		"::1",
		"0.0.0.0",
		"::",
		"169.254.169.254", // cloud instance metadata
		"169.254.0.1",
		"fe80::1",
		"10.0.0.5",
		"172.16.9.9",
		"192.168.1.1",
		"fc00::1",
		"fd12:3456::1",
		"224.0.0.1",
		"ff02::1",
		"::ffff:169.254.169.254", // the same metadata address, v4-mapped
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.5",
	}
	for _, raw := range refused {
		t.Run(raw, func(t *testing.T) {
			ip := netip.MustParseAddr(raw)
			if err := relayDestAllowed(ip, publicRelayPolicy()); err == nil {
				t.Fatalf("relayDestAllowed(%s) = nil, want a refusal", raw)
			}
		})
	}
}

func TestRelayDestAllowsPublicAddresses(t *testing.T) {
	for _, raw := range []string{
		"1.1.1.1",
		"93.184.216.34",
		"2606:4700:4700::1111",
		"8.8.8.8",
	} {
		t.Run(raw, func(t *testing.T) {
			if err := relayDestAllowed(netip.MustParseAddr(raw), publicRelayPolicy()); err != nil {
				t.Fatalf("relayDestAllowed(%s) = %v, want nil", raw, err)
			}
		})
	}
}

// 100.64.0.0/10 is both carrier-grade NAT and the whole of a tailnet's
// IPv4 space. A gateway with a tailnet is meant to reach it; a
// WireGuard-only gateway has no tailnet to reach, so the range is
// refused there with the rest.
func TestRelayDestCGNATFollowsTheTailnet(t *testing.T) {
	tailnetAddrs := []string{"100.64.0.1", "100.101.102.103", "fd7a:115c:a1e0::1234"}
	for _, raw := range tailnetAddrs {
		ip := netip.MustParseAddr(raw)
		if err := relayDestAllowed(ip, tailnetRelayPolicy()); err != nil {
			t.Errorf("with a tailnet: relayDestAllowed(%s) = %v, want nil", raw, err)
		}
		if err := relayDestAllowed(ip, publicRelayPolicy()); err == nil {
			t.Errorf("without a tailnet: relayDestAllowed(%s) = nil, want a refusal", raw)
		}
	}
	// The ChromeOS VM range is carved out of CGNAT and handed to
	// something that is not a tailnet node.
	chromeOS := netip.MustParseAddr("100.115.92.5")
	if err := relayDestAllowed(chromeOS, tailnetRelayPolicy()); err == nil {
		t.Errorf("relayDestAllowed(%s) = nil, want a refusal even with a tailnet", chromeOS)
	}
}

// A 4via6 destination is an IPv6 address that encodes an IPv4 one, and
// the via range sits inside Tailscale's ULA — so allowing that range
// wholesale would carry the metadata service through it.
func TestRelayDestUnwraps4via6(t *testing.T) {
	metadata := netip.MustParseAddr("169.254.169.254")
	via := tsaddrMapVia(t, 1, netip.MustParsePrefix("169.254.169.254/32"))
	err := relayDestAllowed(via, tailnetRelayPolicy())
	if err == nil {
		t.Fatalf("relayDestAllowed(%s) = nil, want a refusal — it encodes %s", via, metadata)
	}
	var refusal *relayDestRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want a *relayDestRefusal", err)
	}
	if refusal.via != metadata {
		t.Fatalf("refusal.via = %v, want %v", refusal.via, metadata)
	}
	// A via address encoding a public IPv4 is still reachable.
	ok := tsaddrMapVia(t, 1, netip.MustParsePrefix("1.1.1.1/32"))
	if err := relayDestAllowed(ok, tailnetRelayPolicy()); err != nil {
		t.Fatalf("relayDestAllowed(%s) = %v, want nil", ok, err)
	}
}

// relay_allow_cidrs is consulted ahead of every refused class, which is
// how one internal subnet stays reachable without turning the policy
// off.
func TestRelayDestAllowCIDRs(t *testing.T) {
	policy := relayDestPolicy{
		mode:  relayDestPublic,
		allow: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
	}
	if err := relayDestAllowed(netip.MustParseAddr("10.20.1.1"), policy); err != nil {
		t.Fatalf("declared subnet: got %v, want nil", err)
	}
	// Neighbouring private space is still refused.
	if err := relayDestAllowed(netip.MustParseAddr("10.21.1.1"), policy); err == nil {
		t.Fatal("10.21.1.1 = nil, want a refusal")
	}
	// And the allowance does not reach the metadata service.
	if err := relayDestAllowed(netip.MustParseAddr("169.254.169.254"), policy); err == nil {
		t.Fatal("169.254.169.254 = nil, want a refusal")
	}
}

// "any" restores the unclassified dial for an operator who wants it.
func TestRelayDestAnyAllowsEverything(t *testing.T) {
	policy := relayDestPolicy{mode: relayDestAny}
	for _, raw := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"} {
		if err := relayDestAllowed(netip.MustParseAddr(raw), policy); err != nil {
			t.Errorf("relay_destinations=any: relayDestAllowed(%s) = %v, want nil", raw, err)
		}
	}
}

// recordingDialer captures the address a dial was asked for, so a test
// can assert the connection was aimed at the address that was
// classified rather than at the name.
type recordingDialer struct {
	asked []string
	// deadlines is the context deadline each attempt was handed, so a
	// test can tell a per-address budget from a shared one.
	deadlines []time.Time
}

func (d *recordingDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *recordingDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	d.asked = append(d.asked, address)
	if dl, ok := ctx.Deadline(); ok {
		d.deadlines = append(d.deadlines, dl)
	}
	return nil, fmt.Errorf("recordingDialer does not connect")
}

// staticResolver answers every lookup with the same addresses, however
// often it is asked.
type staticResolver struct {
	byHost map[string][]netip.Addr
}

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r.byHost[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no such host %q", host)
}

// tableResolver answers from a table, and can answer differently each
// time it is asked — which is how a rebinding window is detected.
type tableResolver struct {
	answers [][]netip.Addr
	calls   int
}

func (r *tableResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	if r.calls >= len(r.answers) {
		return nil, fmt.Errorf("no more answers")
	}
	a := r.answers[r.calls]
	r.calls++
	return a, nil
}

func relayDialTestGateway(t *testing.T, res relayResolver, tailscale bool) (*Gateway, *recordingDialer) {
	t.Helper()
	d := &recordingDialer{}
	g := &Gateway{dialer: d, resolver: res}
	settings := &config.GatewaySettings{}
	if tailscale {
		settings.Tailscale = &config.TailscaleBlock{AuthKey: "tskey-test"}
		// The tailnet allowance follows the running transport, so a
		// gateway standing in for one needs a tsnet client.
		g.tsnetLC = &local.Client{}
	} else {
		settings.WireGuard = &config.WireGuardBlock{SubnetCIDR: "10.55.0.0/24"}
	}
	g.cfg.Store(&config.Gateway{Settings: settings, Policy: &config.Policy{}})
	g.policy.Store(&config.CompiledPolicy{})
	return g, d
}

func addrs(t *testing.T, raw ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(raw))
	for _, r := range raw {
		out = append(out, netip.MustParseAddr(r))
	}
	return out
}

// A name resolving to the cloud metadata service is refused, and the
// dialer is never reached. This is the SNI path: an agent sends a
// ClientHello naming an internal host to any address on :443 and the
// gateway resolves the name itself.
func TestDialRelayHostRefusesNameResolvingToMetadata(t *testing.T) {
	res := &tableResolver{answers: [][]netip.Addr{addrs(t, "169.254.169.254")}}
	g, d := relayDialTestGateway(t, res, true)

	_, err := g.dialRelayHost(context.Background(), "metadata.internal", 443)
	if err == nil {
		t.Fatal("dialRelayHost = nil error, want a refusal")
	}
	var refusal *relayDestRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want a *relayDestRefusal", err)
	}
	if refusal.class != "link-local" {
		t.Fatalf("refusal.class = %q, want link-local", refusal.class)
	}
	if len(d.asked) != 0 {
		t.Fatalf("dialer was asked for %v, want no dial at all", d.asked)
	}
}

// The check lands on the address that is dialled, so there is no window
// between it and the dial for a second DNS answer to slip through: the
// dial is handed the literal the check ran on, and the resolver is
// asked exactly once.
func TestDialRelayHostDialsTheCheckedAddress(t *testing.T) {
	res := &tableResolver{answers: [][]netip.Addr{
		addrs(t, "93.184.216.34"),
		// A second answer the dial must never see. If the dial
		// re-resolved the name, this is what it would land on.
		addrs(t, "169.254.169.254"),
	}}
	g, d := relayDialTestGateway(t, res, true)

	_, _ = g.dialRelayHost(context.Background(), "rebind.example", 443)

	if res.calls != 1 {
		t.Fatalf("resolver called %d times, want exactly 1 — a second lookup is the rebinding window", res.calls)
	}
	if len(d.asked) != 1 {
		t.Fatalf("dialer asked = %v, want exactly one address", d.asked)
	}
	if d.asked[0] != "93.184.216.34:443" {
		t.Fatalf("dialer asked for %q, want the literal that was checked", d.asked[0])
	}
	if strings.Contains(d.asked[0], "rebind.example") {
		t.Fatalf("dialer asked for the name %q — the dial would resolve it again", d.asked[0])
	}
}

// A name answering with both a public address and the metadata service
// is a name steering the gateway at its metadata service. Which of the
// two a given lookup puts first is not something to settle by racing.
func TestDialRelayHostRefusesMixedAnswer(t *testing.T) {
	for _, order := range [][]string{
		{"93.184.216.34", "169.254.169.254"},
		{"169.254.169.254", "93.184.216.34"},
	} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			res := &tableResolver{answers: [][]netip.Addr{addrs(t, order...)}}
			g, d := relayDialTestGateway(t, res, true)
			if _, err := g.dialRelayHost(context.Background(), "mixed.example", 443); err == nil {
				t.Fatal("dialRelayHost = nil error, want a refusal")
			}
			if len(d.asked) != 0 {
				t.Fatalf("dialer was asked for %v, want no dial at all", d.asked)
			}
		})
	}
}

// A literal destination needs no lookup and is classified as itself.
func TestDialRelayHostClassifiesLiterals(t *testing.T) {
	res := &tableResolver{}
	g, d := relayDialTestGateway(t, res, true)

	if _, err := g.dialRelayHost(context.Background(), "169.254.169.254", 443); err == nil {
		t.Fatal("literal metadata address: want a refusal")
	}
	if res.calls != 0 {
		t.Fatalf("resolver called %d times for a literal, want 0", res.calls)
	}
	if len(d.asked) != 0 {
		t.Fatalf("dialer was asked for %v, want no dial", d.asked)
	}

	// A tailnet literal passes on a gateway with a tailnet, and the
	// dial is aimed at it.
	if _, err := g.dialRelayHost(context.Background(), "100.64.0.9", 22); err != nil {
		var refusal *relayDestRefusal
		if errors.As(err, &refusal) {
			t.Fatalf("tailnet literal refused: %v", err)
		}
	}
	if len(d.asked) != 1 || d.asked[0] != "100.64.0.9:22" {
		t.Fatalf("dialer asked = %v, want [100.64.0.9:22]", d.asked)
	}
}

// relayDestOK is the literal-destination entry point the TCP and UDP
// relays use, and it reads the live policy.
func TestRelayDestOKReadsLivePolicy(t *testing.T) {
	g, _ := relayDialTestGateway(t, &tableResolver{}, true)

	if err := g.relayDestOK("169.254.169.254"); err == nil {
		t.Fatal("relayDestOK(169.254.169.254) = nil, want a refusal")
	}
	if err := g.relayDestOK("100.64.0.9"); err != nil {
		t.Fatalf("relayDestOK(100.64.0.9) on a tailnet gateway = %v, want nil", err)
	}
	if err := g.relayDestOK("not-an-address"); err == nil {
		t.Fatal("relayDestOK(not-an-address) = nil, want an error")
	}

	// relay_destinations = any opts back out.
	g.policy.Store(&config.CompiledPolicy{RelayDestinations: relayDestAny})
	if err := g.relayDestOK("169.254.169.254"); err != nil {
		t.Fatalf("relay_destinations=any: got %v, want nil", err)
	}

	// And a declared CIDR is honoured from the live policy.
	g.policy.Store(&config.CompiledPolicy{
		RelayAllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
	})
	if err := g.relayDestOK("10.20.3.4"); err != nil {
		t.Fatalf("declared CIDR: got %v, want nil", err)
	}
	if err := g.relayDestOK("10.21.3.4"); err == nil {
		t.Fatal("10.21.3.4 = nil, want a refusal")
	}
}

// A gateway that has not reached its config yet must not dial the
// host's private networks on an agent's word.
func TestRelayDestDefaultsToPublicWithNoPolicy(t *testing.T) {
	g := &Gateway{}
	if err := g.relayDestOK("169.254.169.254"); err == nil {
		t.Fatal("relayDestOK with no config = nil, want a refusal")
	}
	if err := g.relayDestOK("127.0.0.1"); err == nil {
		t.Fatal("relayDestOK(127.0.0.1) with no config = nil, want a refusal")
	}
}

// tsaddrMapVia builds a 4via6 address for one IPv4 — the form a
// subnet router hands out so an IPv4-only destination is reachable
// over IPv6.
func tsaddrMapVia(t *testing.T, siteID uint32, v4 netip.Prefix) netip.Addr {
	t.Helper()
	via, err := tsaddr.MapVia(siteID, v4)
	if err != nil {
		t.Fatalf("MapVia(%d, %s): %v", siteID, v4, err)
	}
	return via.Addr()
}

// The SNI path end to end: an agent sends a ClientHello naming an
// internal host to any address on :443, the gateway resolves the name
// itself, and under unknown_host = "passthrough" splice is what dials
// it. The dialer must never be reached, and must never be handed the
// name — handing it a name is the dial doing its own lookup, which is
// the window the classification exists to close.
func TestSpliceRefusesSNIResolvingToMetadata(t *testing.T) {
	sink, err := NewSink(nil, 16)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	res := &tableResolver{answers: [][]netip.Addr{addrs(t, "169.254.169.254")}}
	g, d := relayDialTestGateway(t, res, true)
	g.sink = sink
	g.onboard = newOnboardRegistry()

	agent, gw := net.Pipe()
	defer func() { _ = agent.Close() }()
	g.splice(gw, "metadata.internal")

	for _, asked := range d.asked {
		t.Errorf("dialer was asked for %q; the destination is refused, so nothing should be dialled", asked)
	}
	if strings.Contains(strings.Join(d.asked, " "), "metadata.internal") {
		t.Error("dialer was handed the name, so the dial would resolve it a second time")
	}
}

// And a public name still splices, aimed at the address that was
// classified.
func TestSpliceDialsCheckedAddressForPublicSNI(t *testing.T) {
	sink, err := NewSink(nil, 16)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	res := &tableResolver{answers: [][]netip.Addr{addrs(t, "93.184.216.34")}}
	g, d := relayDialTestGateway(t, res, true)
	g.sink = sink
	g.onboard = newOnboardRegistry()

	agent, gw := net.Pipe()
	defer func() { _ = agent.Close() }()
	g.splice(gw, "example.test")

	if len(d.asked) != 1 || d.asked[0] != "93.184.216.34:443" {
		t.Fatalf("dialer asked = %v, want [93.184.216.34:443]", d.asked)
	}
}

// wgRelay is the transparent TCP catch-all, reached once no endpoint
// claims the destination. It holds a literal the agent put in the
// packet and dials it from the gateway host, so the refusal has to land
// before the dial — which is what the emitted event and the absence of
// a dial timeout show.
func TestWgRelayRefusesHostNetworkDestination(t *testing.T) {
	sink, err := NewSink(nil, 4)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	g, _ := relayDialTestGateway(t, &tableResolver{}, true)
	g.sink = sink
	g.onboard = newOnboardRegistry()

	agent, gw := net.Pipe()
	defer func() { _ = agent.Close() }()
	// A device row, so the deny event is emitted rather than suppressed
	// as a stray probe.
	g.onboard.knownDeviceIPs[peerIP(gw)] = true

	start := time.Now()
	g.wgRelay(gw, "169.254.169.254", 80)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("wgRelay took %s — the refusal has to land before the dial, not after it times out", elapsed)
	}

	ev := awaitRelayEvent(t, sink)
	if ev.Action != "deny" {
		t.Fatalf("event action = %q, want deny", ev.Action)
	}
	if !strings.Contains(ev.Reason, "link-local") {
		t.Fatalf("event reason = %q, want it to name the refused class", ev.Reason)
	}
	if ev.Host != "169.254.169.254:80" {
		t.Fatalf("event host = %q", ev.Host)
	}
}

// And a public destination is still relayed: the refusal is not a
// blanket stop on the catch-all.
func TestWgRelayAllowsPublicDestination(t *testing.T) {
	sink, err := NewSink(nil, 4)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	g, _ := relayDialTestGateway(t, &tableResolver{}, true)
	g.sink = sink
	g.onboard = newOnboardRegistry()

	// A listener standing in for the upstream, so the dial succeeds and
	// the relay reaches its allow event.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	// 127.0.0.1 is refused under "public", so this case needs the
	// loopback declared — which also pins that relay_allow_cidrs reaches
	// the wgRelay path and not only the splice one.
	g.policy.Store(&config.CompiledPolicy{
		RelayAllowCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	})

	agent, gw := net.Pipe()
	g.onboard.knownDeviceIPs[peerIP(gw)] = true
	go func() {
		// Close the agent side so the relay's copy loops finish.
		time.Sleep(50 * time.Millisecond)
		_ = agent.Close()
	}()
	g.wgRelay(gw, host, portNum)

	ev := awaitRelayEvent(t, sink)
	if ev.Action == "deny" {
		t.Fatalf("declared CIDR was still refused: %q", ev.Reason)
	}
}

// awaitRelayEvent returns the first event the sink recorded. Emit hands
// the event to the sink's drain goroutine, so the ring is what a test
// reads and it has to wait for the handoff.
func awaitRelayEvent(t *testing.T, sink *Sink) Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		recent, _, cancel := sink.RecentAndSubscribe()
		cancel()
		if len(recent) > 0 {
			return recent[len(recent)-1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no event emitted")
	return Event{}
}

// The tailnet allowance follows the running transport, not the declared
// config. A `tailscale {}` block is restart-only, so a hot reload that
// adds one describes a tailnet this process is not on — reading the
// declaration would open CGNAT and Tailscale's ULA before any tailnet
// existed to reach.
func TestRelayDestTailnetFollowsRunningTransport(t *testing.T) {
	g, _ := relayDialTestGateway(t, &tableResolver{}, false)
	// Declared, but no tsnet is up.
	g.cfg.Load().Settings.Tailscale = &config.TailscaleBlock{AuthKey: "tskey-test"}
	if err := g.relayDestOK("100.64.0.9"); err == nil {
		t.Fatal("a declared-but-not-running tailnet allowed CGNAT")
	}
	if err := g.relayDestOK("fd7a:115c:a1e0::1"); err == nil {
		t.Fatal("a declared-but-not-running tailnet allowed its ULA")
	}
	// Once the tsnet is up, both resolve.
	g.tsnetLC = &local.Client{}
	if err := g.relayDestOK("100.64.0.9"); err != nil {
		t.Fatalf("running tailnet refused CGNAT: %v", err)
	}
	if err := g.relayDestOK("fd7a:115c:a1e0::1"); err != nil {
		t.Fatalf("running tailnet refused its ULA: %v", err)
	}
}

// The forms that carry another address inside them are classified on the
// address a dial would actually reach.
func TestRelayDestUnwrapsV4InV6Encodings(t *testing.T) {
	cases := []struct {
		addr string
		why  string
	}{
		{"::127.0.0.1", "IPv4-compatible loopback"},
		{"::169.254.169.254", "IPv4-compatible metadata"},
		{"64:ff9b::a9fe:a9fe", "NAT64 metadata"},
		{"64:ff9b::7f00:1", "NAT64 loopback"},
		{"2002:a9fe:a9fe::", "6to4 metadata"},
		{"2002:0a00:0001::", "6to4 private"},
		{"2001::1", "Teredo"},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			if err := relayDestAllowed(netip.MustParseAddr(tc.addr), tailnetRelayPolicy()); err == nil {
				t.Fatalf("%s (%s) = nil, want a refusal", tc.addr, tc.why)
			}
		})
	}
	// An encoding carrying a public IPv4 is still a public destination.
	for _, ok := range []string{"64:ff9b::0101:0101", "2002:0101:0101::"} {
		if err := relayDestAllowed(netip.MustParseAddr(ok), tailnetRelayPolicy()); err != nil {
			t.Errorf("%s = %v, want nil", ok, err)
		}
	}
}

// A zone names an interface of the gateway's. `::%lo` is not the
// unspecified address to netip, but it is the local system to the
// dialer, so the bit tests alone do not catch it.
func TestRelayDestRefusesZonedAddresses(t *testing.T) {
	for _, raw := range []string{"::%lo", "::%lo0", "::1%lo", "fe80::1%eth0"} {
		t.Run(raw, func(t *testing.T) {
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				t.Skipf("netip rejects %q: %v", raw, err)
			}
			if err := relayDestAllowed(ip, tailnetRelayPolicy()); err == nil {
				t.Fatalf("relayDestAllowed(%s) = nil, want a refusal", raw)
			}
		})
	}
}

// "This network" and the broadcast address are not destinations an agent
// may steer the gateway at either.
func TestRelayDestRefusesThisNetworkAndBroadcast(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "0.1.2.3", "0.255.255.255", "255.255.255.255"} {
		t.Run(raw, func(t *testing.T) {
			if err := relayDestAllowed(netip.MustParseAddr(raw), tailnetRelayPolicy()); err == nil {
				t.Fatalf("relayDestAllowed(%s) = nil, want a refusal", raw)
			}
		})
	}
}

// A name answering with two allowed addresses has each of them tried, in
// the order the resolver gave them and as literals, and each attempt is
// handed its own slice of the dial budget rather than the whole of it —
// so a first address that black-holes cannot leave the second untried.
// With one shared deadline both attempts would carry the full budget.
func TestDialRelayHostTriesEachAllowedAddress(t *testing.T) {
	res := &tableResolver{answers: [][]netip.Addr{
		addrs(t, "93.184.216.34", "2606:4700:4700::1111"),
	}}
	g, d := relayDialTestGateway(t, res, true)

	start := time.Now()
	if _, err := g.dialRelayHost(context.Background(), "dual.example", 443); err == nil {
		t.Fatal("dialRelayHost = nil error, want the recording dialer's failure")
	}
	if res.calls != 1 {
		t.Fatalf("resolver called %d times, want exactly 1", res.calls)
	}
	want := []string{"93.184.216.34:443", "[2606:4700:4700::1111]:443"}
	if !slices.Equal(d.asked, want) {
		t.Fatalf("dialer asked = %v, want %v", d.asked, want)
	}
	if len(d.deadlines) != len(want) {
		t.Fatalf("attempts with a deadline = %d, want %d", len(d.deadlines), len(want))
	}
	// Two addresses share relayDialTimeout, so neither attempt may be
	// given more than half of it (plus slack for the test itself).
	limit := relayDialTimeout/2 + time.Second
	for i, dl := range d.deadlines {
		if budget := dl.Sub(start); budget > limit {
			t.Fatalf("attempt %d budget %s exceeds its share %s of %s — the deadline is shared, not per-address", i, budget, limit, relayDialTimeout)
		}
	}
}
