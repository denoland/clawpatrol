package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/denoland/clawpatrol/internal/config"
)

// whoisRoundTripper answers the local API's whois call with a canned
// node, which is what lets resolveTsnetAlias be driven end to end
// without a tailnet. local.Client.Transport exists for exactly this.
type whoisRoundTripper struct {
	t    *testing.T
	resp *apitype.WhoIsResponse
}

func (rt whoisRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.t.Helper()
	body, err := json.Marshal(rt.resp)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

// stubWhoisNode builds the node a stubbed whois returns. addrs are the
// addresses the control plane says the node holds.
func stubWhoisNode(stableID, computedName string, addrs ...string) *apitype.WhoIsResponse {
	n := &tailcfg.Node{
		ID:           1,
		StableID:     tailcfg.StableNodeID(stableID),
		Name:         computedName + ".example.ts.net.",
		ComputedName: computedName,
		Key:          key.NewNode().Public(),
	}
	for _, a := range addrs {
		n.Addresses = append(n.Addresses, netip.MustParsePrefix(a))
	}
	n.Hostinfo = (&tailcfg.Hostinfo{Hostname: computedName}).View()
	return &apitype.WhoIsResponse{
		Node:        n,
		UserProfile: &tailcfg.UserProfile{LoginName: "someone@example.com"},
	}
}

func gatewayWithStubbedWhois(t *testing.T, r *onboardRegistry, resp *apitype.WhoIsResponse) *Gateway {
	t.Helper()
	g := &Gateway{
		onboard: r,
		tsnetLC: &local.Client{
			Transport: whoisRoundTripper{t: t, resp: resp},
			OmitAuth:  true,
		},
	}
	g.cfg.Store(&config.Gateway{Policy: &config.Policy{
		Order: []string{"default", "prod"},
		Profiles: map[string]*config.Profile{
			"default": {Name: "default"},
			"prod":    {Name: "prod"},
		},
	}})
	return g
}

// A node that claims a privileged device's hostname must not inherit
// that device's row, and so must not inherit its profile. The name is
// whatever the node asserts (`tailscale set --hostname`) and an
// ephemeral node releases it when it goes offline, so a name match
// would hand any tailnet member that can route through the gateway the
// credentials the privileged profile injects.
func TestResolveTsnetAliasRefusesHostnameImpersonation(t *testing.T) {
	r := newOnboardRegistry()
	const victimIP = "100.1.1.1"
	r.knownDeviceIPs[victimIP] = true
	r.hostnameByIP[victimIP] = "privileged-agent"
	r.profileByIP[victimIP] = "prod"
	r.nodeIDByIP[victimIP] = "nodeVICTIM"

	const attackerIP = "100.9.9.9"
	g := gatewayWithStubbedWhois(t, r,
		stubWhoisNode("nodeATTACKER", "privileged-agent", attackerIP+"/32"))

	if got := g.resolveTsnetAlias(attackerIP); got != "" {
		t.Fatalf("resolveTsnetAlias(%s) = %q, want empty — a claimed hostname must not alias onto a device row", attackerIP, got)
	}
	if got := r.ProfileForIP(attackerIP); got != "" {
		t.Fatalf("ProfileForIP(%s) = %q, want empty", attackerIP, got)
	}
	if got := r.AgentIPFor(attackerIP); got != attackerIP {
		t.Fatalf("AgentIPFor(%s) = %q, want it unaliased", attackerIP, got)
	}
	if got := g.profileFor(attackerIP); got == "prod" {
		t.Fatalf("profileFor(%s) resolved to the victim's profile", attackerIP)
	}
}

// The node the device row is bound to is folded on, even when it
// reaches the gateway from an address the row does not carry — the
// control plane reassigned it, or it arrived on a family the row never
// recorded.
func TestResolveTsnetAliasFoldsSameNode(t *testing.T) {
	r := newOnboardRegistry()
	const deviceIP = "100.1.1.1"
	r.knownDeviceIPs[deviceIP] = true
	r.hostnameByIP[deviceIP] = "privileged-agent"
	r.profileByIP[deviceIP] = "prod"
	r.nodeIDByIP[deviceIP] = "nodeVICTIM"

	const newIP = "100.7.7.7"
	g := gatewayWithStubbedWhois(t, r,
		stubWhoisNode("nodeVICTIM", "privileged-agent", newIP+"/32"))

	if got := g.resolveTsnetAlias(newIP); got != deviceIP {
		t.Fatalf("resolveTsnetAlias(%s) = %q, want %q", newIP, got, deviceIP)
	}
	if got := r.ProfileForIP(newIP); got != "prod" {
		t.Fatalf("ProfileForIP(%s) = %q, want prod", newIP, got)
	}
}

// The address pass is both the primary match and where a devices row
// written before ts_node_id existed acquires its binding: the node
// names the row's IP among its own addresses, so the two addresses
// belong to one node.
func TestResolveTsnetAliasBindsNodeOnAddressMatch(t *testing.T) {
	r := newOnboardRegistry()
	const deviceIP = "100.1.1.1"
	r.knownDeviceIPs[deviceIP] = true
	r.hostnameByIP[deviceIP] = "privileged-agent"
	r.profileByIP[deviceIP] = "prod"
	// No nodeIDByIP entry — an upgraded deployment's existing row.

	const ula = "fd7a:115c:a1e0::1234"
	g := gatewayWithStubbedWhois(t, r,
		stubWhoisNode("nodeVICTIM", "privileged-agent", deviceIP+"/32", ula+"/128"))

	if got := g.resolveTsnetAlias(ula); got != deviceIP {
		t.Fatalf("resolveTsnetAlias(%s) = %q, want %q", ula, got, deviceIP)
	}
	if got := r.NodeIDForIP(deviceIP); got != "nodeVICTIM" {
		t.Fatalf("NodeIDForIP(%s) = %q, want the node that asserted the address", deviceIP, got)
	}
}

// A row that predates the node binding matches nothing until the node
// behind it is observed, which is what keeps an upgraded deployment's
// rows from being absorbed by a name.
func TestResolveTsnetAliasIgnoresUnboundRow(t *testing.T) {
	r := newOnboardRegistry()
	const victimIP = "100.1.1.1"
	r.knownDeviceIPs[victimIP] = true
	r.hostnameByIP[victimIP] = "privileged-agent"
	r.profileByIP[victimIP] = "prod"

	const attackerIP = "100.9.9.9"
	g := gatewayWithStubbedWhois(t, r,
		stubWhoisNode("nodeATTACKER", "privileged-agent", attackerIP+"/32"))

	if got := g.resolveTsnetAlias(attackerIP); got != "" {
		t.Fatalf("resolveTsnetAlias(%s) = %q, want empty", attackerIP, got)
	}
}

// A device row bound to one node must not be rebound by another node
// that has acquired the row's address — which is what IP reuse after a
// device is deleted looks like. Rebinding would both hand the new node
// the old device's profile and leave the row pointing at it, so every
// later address of that node would resolve through it too.
func TestResolveTsnetAliasRefusesRebindingABoundRow(t *testing.T) {
	r := newOnboardRegistry()
	const victimIP = "100.1.1.1"
	r.knownDeviceIPs[victimIP] = true
	r.hostnameByIP[victimIP] = "privileged-agent"
	r.profileByIP[victimIP] = "prod"
	r.nodeIDByIP[victimIP] = "nodeVICTIM"

	// The attacker's node now holds the victim's old IPv4 among its own
	// addresses, and reaches the gateway on its IPv6.
	const attackerULA = "fd7a:115c:a1e0::9999"
	g := gatewayWithStubbedWhois(t, r,
		stubWhoisNode("nodeATTACKER", "whatever", victimIP+"/32", attackerULA+"/128"))

	if got := g.resolveTsnetAlias(attackerULA); got != "" {
		t.Fatalf("resolveTsnetAlias(%s) = %q, want empty", attackerULA, got)
	}
	if got := r.NodeIDForIP(victimIP); got != "nodeVICTIM" {
		t.Fatalf("NodeIDForIP(%s) = %q, want the row's original binding", victimIP, got)
	}
	if got := r.ProfileForIP(attackerULA); got != "" {
		t.Fatalf("ProfileForIP(%s) = %q, want empty", attackerULA, got)
	}
}

// A WhoIs that reports no StableID carries no identity, so it must not
// bind a row — the address match still folds, because the control plane
// named the row's address as this node's, but nothing is recorded.
func TestResolveTsnetAliasFoldsWithoutBindingOnEmptyNodeID(t *testing.T) {
	r := newOnboardRegistry()
	const deviceIP = "100.1.1.1"
	r.knownDeviceIPs[deviceIP] = true
	r.profileByIP[deviceIP] = "prod"

	const ula = "fd7a:115c:a1e0::1234"
	g := gatewayWithStubbedWhois(t, r,
		stubWhoisNode("", "privileged-agent", deviceIP+"/32", ula+"/128"))

	if got := g.resolveTsnetAlias(ula); got != deviceIP {
		t.Fatalf("resolveTsnetAlias(%s) = %q, want %q", ula, got, deviceIP)
	}
	if got := r.NodeIDForIP(deviceIP); got != "" {
		t.Fatalf("NodeIDForIP(%s) = %q, want nothing recorded", deviceIP, got)
	}
	// And an empty node id never matches a row on the node pass.
	if got := r.UniqueIPForNodeID(""); got != "" {
		t.Fatalf("UniqueIPForNodeID(\"\") = %q, want empty", got)
	}
}

// ForgetIP retires the row, so a fold onto it afterwards must not
// resurrect it.
func TestFoldAliasOntoDeviceRefusesForgottenRow(t *testing.T) {
	r := newOnboardRegistry()
	const deviceIP = "100.1.1.1"
	r.knownDeviceIPs[deviceIP] = true
	r.profileByIP[deviceIP] = "prod"
	r.nodeIDByIP[deviceIP] = "nodeA"

	r.ForgetIP(deviceIP)
	if r.HasDevice(deviceIP) {
		t.Fatal("HasDevice still reports a forgotten row")
	}
	if r.FoldAliasOntoDevice("100.9.9.9", deviceIP, "nodeA") {
		t.Fatal("folded onto a forgotten row")
	}
}

// The node pass folds in one critical section, so a row deleted while
// the fold is in flight cannot acquire an alias pointing at it.
func TestFoldAliasOntoNode(t *testing.T) {
	r := newOnboardRegistry()
	const deviceIP = "100.1.1.1"
	r.knownDeviceIPs[deviceIP] = true
	r.profileByIP[deviceIP] = "prod"
	r.nodeIDByIP[deviceIP] = "nodeA"

	const alias = "100.7.7.7"
	if got := r.FoldAliasOntoNode(alias, "nodeA"); got != deviceIP {
		t.Fatalf("FoldAliasOntoNode = %q, want %q", got, deviceIP)
	}
	if got := r.ProfileForIP(alias); got != "prod" {
		t.Fatalf("ProfileForIP(%s) = %q, want prod", alias, got)
	}
	// No row bound to the node, an empty node id, and the alias being
	// the canonical itself all fold nothing.
	if got := r.FoldAliasOntoNode("100.8.8.8", "nodeZ"); got != "" {
		t.Fatalf("unknown node folded onto %q", got)
	}
	if got := r.FoldAliasOntoNode("100.8.8.8", ""); got != "" {
		t.Fatalf("empty node id folded onto %q", got)
	}
	if got := r.FoldAliasOntoNode(deviceIP, "nodeA"); got != "" {
		t.Fatalf("canonical folded onto itself: %q", got)
	}
	// Two rows bound to one node is a collision, never a merge.
	r.knownDeviceIPs["100.2.2.2"] = true
	r.nodeIDByIP["100.2.2.2"] = "nodeA"
	if got := r.FoldAliasOntoNode("100.9.9.9", "nodeA"); got != "" {
		t.Fatalf("collision folded onto %q", got)
	}
}

// A forgotten row is not foldable through the node pass either.
func TestFoldAliasOntoNodeRefusesForgottenRow(t *testing.T) {
	r := newOnboardRegistry()
	const deviceIP = "100.1.1.1"
	r.knownDeviceIPs[deviceIP] = true
	r.profileByIP[deviceIP] = "prod"
	r.nodeIDByIP[deviceIP] = "nodeA"

	r.ForgetIP(deviceIP)
	if got := r.FoldAliasOntoNode("100.9.9.9", "nodeA"); got != "" {
		t.Fatalf("folded onto a forgotten row: %q", got)
	}
}
