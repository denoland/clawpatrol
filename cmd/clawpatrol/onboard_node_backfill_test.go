package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"

	"github.com/denoland/clawpatrol/internal/config"
)

// whoisByAddrRoundTripper answers the local API's whois call per
// address: a canned node for the addresses it knows, 404 (which
// local.Client reports as ErrPeerNotFound) for every other one. The
// boot-time binding pass asks about several rows in one go, so a
// single canned answer cannot drive it.
type whoisByAddrRoundTripper struct {
	t     *testing.T
	byIP  map[string]*apitype.WhoIsResponse
	asked []string
	// onAsk, when set, runs before the answer for host is produced —
	// what happens to the registry while a WhoIs is in flight.
	onAsk func(host string)
}

func (rt *whoisByAddrRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.t.Helper()
	host, _, err := net.SplitHostPort(req.URL.Query().Get("addr"))
	if err != nil {
		rt.t.Fatalf("whois addr %q: %v", req.URL.Query().Get("addr"), err)
	}
	rt.asked = append(rt.asked, host)
	if rt.onAsk != nil {
		rt.onAsk(host)
	}
	resp, ok := rt.byIP[host]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("peer not found")),
			Request:    req,
		}, nil
	}
	body, err := json.Marshal(resp)
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

func gatewayWithWhoisByAddr(t *testing.T, r *onboardRegistry, byIP map[string]*apitype.WhoIsResponse) (*Gateway, *whoisByAddrRoundTripper) {
	t.Helper()
	rt := &whoisByAddrRoundTripper{t: t, byIP: byIP}
	g := &Gateway{
		onboard: r,
		tsnetLC: &local.Client{Transport: rt, OmitAuth: true},
	}
	return g, rt
}

// captureLog routes the standard logger into a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// A row written before ts_node_id existed is bound at boot when the
// control plane reports a node holding the row's IP among its own
// addresses — the same statement the address pass relies on. Here the
// row's recorded hostname is the node's name, the common case, and the
// log line says nothing about names.
func TestBindUnboundDevicesBindsRowWhoseNodeHoldsItsIPUnderTheSameName(t *testing.T) {
	r := newOnboardRegistry()
	const ip = "100.64.1.1"
	r.knownDeviceIPs[ip] = true
	r.profileByIP[ip] = "prod"
	r.hostnameByIP[ip] = "agent"

	g, rt := gatewayWithWhoisByAddr(t, r, map[string]*apitype.WhoIsResponse{
		ip: stubWhoisNode("nodeA", "agent", ip+"/32", "fd7a:115c:a1e0::1/128"),
	})
	logs := captureLog(t)

	bound, unbound := g.bindUnboundDevicesFromWhoIs()
	if !slices.Equal(bound, []string{ip}) || len(unbound) != 0 {
		t.Fatalf("bound = %v, unbound = %v; want [%s], []", bound, unbound, ip)
	}
	if got := r.NodeIDForIP(ip); got != "nodeA" {
		t.Fatalf("NodeIDForIP(%s) = %q, want nodeA", ip, got)
	}
	if got := r.UnboundDeviceIPs(); len(got) != 0 {
		t.Fatalf("UnboundDeviceIPs = %v after binding, want none", got)
	}
	if !slices.Equal(rt.asked, []string{ip}) {
		t.Fatalf("WhoIs asked about %v, want only %s", rt.asked, ip)
	}
	if !strings.Contains(logs.String(), "bound device "+ip+" to tailnet node nodeA (agent)") {
		t.Fatalf("no per-row log line naming the node; logs:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "name mismatch") {
		t.Fatalf("mismatch reported for a row whose hostname is the node's name; logs:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "not bound") {
		t.Fatalf("summary line emitted with nothing unbound; logs:\n%s", logs.String())
	}
	// And the binding now makes the row reachable through the node pass.
	if got := r.UniqueIPForNodeID("nodeA"); got != ip {
		t.Fatalf("UniqueIPForNodeID(nodeA) = %q, want %s", got, ip)
	}
}

// The binding rests on the address alone. A row registered under one
// hostname whose IP the control plane now reports as held by a node of
// another name — the address was reused after the original node left,
// or the client simply reported a different name than MagicDNS
// computed — is still bound to that node: it is the node already being
// served the row's profile on that address, and leaving the row
// unbound would not change that. The mismatch is logged, naming both,
// so the operator can judge it.
func TestBindUnboundDevicesBindsIPReusedByAnotherNode(t *testing.T) {
	r := newOnboardRegistry()
	const ip = "100.64.1.1"
	r.knownDeviceIPs[ip] = true
	r.profileByIP[ip] = "prod"
	r.hostnameByIP[ip] = "victim"

	g, _ := gatewayWithWhoisByAddr(t, r, map[string]*apitype.WhoIsResponse{
		ip: stubWhoisNode("nodeSTRANGER", "stranger", ip+"/32"),
	})
	logs := captureLog(t)

	bound, unbound := g.bindUnboundDevicesFromWhoIs()
	if !slices.Equal(bound, []string{ip}) || len(unbound) != 0 {
		t.Fatalf("bound = %v, unbound = %v; want [%s], []", bound, unbound, ip)
	}
	if got := r.NodeIDForIP(ip); got != "nodeSTRANGER" {
		t.Fatalf("NodeIDForIP(%s) = %q, want nodeSTRANGER", ip, got)
	}
	if got := r.HostnameForIP(ip); got != "victim" {
		t.Fatalf("HostnameForIP(%s) = %q after binding, want the row's own name kept", ip, got)
	}
	if !strings.Contains(logs.String(), "bound device "+ip+" to tailnet node nodeSTRANGER (stranger)") {
		t.Fatalf("no per-row log line; logs:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), `(name mismatch: row "victim", node "stranger")`) {
		t.Fatalf("mismatch not reported with both names; logs:\n%s", logs.String())
	}
}

// The binding reaches the devices row, not just the in-memory map, so
// it survives the next boot.
func TestBindUnboundDevicesPersistsBinding(t *testing.T) {
	const ip = "100.64.1.1"
	w := newOnboardAuthTestWebMuxForControl(t, "tailscale")
	if err := w.g.onboard.Load(w.g.db); err != nil {
		t.Fatalf("Load: %v", err)
	}
	w.g.onboard.AssignProfile(ip, "default") // writes a row with NULL ts_node_id
	if got := w.g.onboard.UnboundDeviceIPs(); !slices.Equal(got, []string{ip}) {
		t.Fatalf("UnboundDeviceIPs = %v, want [%s]", got, ip)
	}
	rt := &whoisByAddrRoundTripper{t: t, byIP: map[string]*apitype.WhoIsResponse{
		ip: stubWhoisNode("nodeA", "agent", ip+"/32"),
	}}
	w.g.tsnetLC = &local.Client{Transport: rt, OmitAuth: true}

	w.g.bindUnboundDevicesFromWhoIs()

	var stored string
	if err := w.g.db.QueryRow("SELECT ts_node_id FROM devices WHERE id = ?", ip).Scan(&stored); err != nil {
		t.Fatalf("read ts_node_id: %v", err)
	}
	if stored != "nodeA" {
		t.Fatalf("devices.ts_node_id = %q, want nodeA", stored)
	}
	// A fresh registry loading the same table sees the row bound.
	r2 := newOnboardRegistry()
	if err := r2.Load(w.g.db); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := r2.NodeIDForIP(ip); got != "nodeA" {
		t.Fatalf("NodeIDForIP(%s) after reload = %q, want nodeA", ip, got)
	}
}

// A WhoIs that names a node which does not hold the row's IP is not a
// statement about that row: the row is left unbound and reported, so
// the operator knows which rows to delete.
func TestBindUnboundDevicesLeavesRowWhoseNodeNamesAnotherAddress(t *testing.T) {
	r := newOnboardRegistry()
	const ip = "100.64.1.1"
	r.knownDeviceIPs[ip] = true
	r.profileByIP[ip] = "prod"

	g, _ := gatewayWithWhoisByAddr(t, r, map[string]*apitype.WhoIsResponse{
		ip: stubWhoisNode("nodeB", "agent", "100.64.2.2/32"),
	})
	logs := captureLog(t)

	bound, unbound := g.bindUnboundDevicesFromWhoIs()
	if len(bound) != 0 || !slices.Equal(unbound, []string{ip}) {
		t.Fatalf("bound = %v, unbound = %v; want [], [%s]", bound, unbound, ip)
	}
	if got := r.NodeIDForIP(ip); got != "" {
		t.Fatalf("NodeIDForIP(%s) = %q, want nothing recorded", ip, got)
	}
	if !strings.Contains(logs.String(), "1 device row(s) not bound") || !strings.Contains(logs.String(), ip) {
		t.Fatalf("summary line missing or does not name the row; logs:\n%s", logs.String())
	}
}

// A row already bound is never asked about and never rebound, whatever
// WhoIs would say about its address now.
func TestBindUnboundDevicesLeavesBoundRowAlone(t *testing.T) {
	r := newOnboardRegistry()
	const ip = "100.64.1.1"
	r.knownDeviceIPs[ip] = true
	r.profileByIP[ip] = "prod"
	r.nodeIDByIP[ip] = "nodeVICTIM"

	g, rt := gatewayWithWhoisByAddr(t, r, map[string]*apitype.WhoIsResponse{
		ip: stubWhoisNode("nodeATTACKER", "agent", ip+"/32"),
	})

	bound, unbound := g.bindUnboundDevicesFromWhoIs()
	if len(bound) != 0 || len(unbound) != 0 {
		t.Fatalf("bound = %v, unbound = %v; want nothing touched", bound, unbound)
	}
	if got := r.NodeIDForIP(ip); got != "nodeVICTIM" {
		t.Fatalf("NodeIDForIP(%s) = %q, want the original binding", ip, got)
	}
	if len(rt.asked) != 0 {
		t.Fatalf("WhoIs asked about %v for a bound row", rt.asked)
	}
	// Nor does the registry take a rebind even when asked directly.
	if r.BindNodeIfUnbound(ip, "nodeATTACKER") {
		t.Fatal("BindNodeIfUnbound rebound a bound row")
	}
}

// A WhoIs error — the node is not in the netmap — leaves the row as it
// is, reported in the summary.
func TestBindUnboundDevicesLeavesRowOnWhoisError(t *testing.T) {
	r := newOnboardRegistry()
	const gone = "100.64.1.1"
	const present = "100.64.3.3"
	r.knownDeviceIPs[gone] = true
	r.knownDeviceIPs[present] = true

	g, _ := gatewayWithWhoisByAddr(t, r, map[string]*apitype.WhoIsResponse{
		// Nothing for gone → 404 → local.ErrPeerNotFound.
		present: stubWhoisNode("nodeC", "agent", present+"/32"),
	})
	logs := captureLog(t)

	bound, unbound := g.bindUnboundDevicesFromWhoIs()
	if !slices.Equal(bound, []string{present}) || !slices.Equal(unbound, []string{gone}) {
		t.Fatalf("bound = %v, unbound = %v; want [%s], [%s]", bound, unbound, present, gone)
	}
	if got := r.NodeIDForIP(gone); got != "" {
		t.Fatalf("NodeIDForIP(%s) = %q, want nothing recorded", gone, got)
	}
	if got := r.NodeIDForIP(present); got != "nodeC" {
		t.Fatalf("NodeIDForIP(%s) = %q, want nodeC", present, got)
	}
	if !strings.Contains(logs.String(), gone) || strings.Contains(logs.String(), "not bound to a tailnet node — WhoIs failed, reported no node ID, or named another address; delete them if the device is gone: "+present) {
		t.Fatalf("summary should name %s and not %s; logs:\n%s", gone, present, logs.String())
	}
}

// A WhoIs with no StableID carries no identity: nothing is recorded.
func TestBindUnboundDevicesSkipsEmptyNodeID(t *testing.T) {
	r := newOnboardRegistry()
	const ip = "100.64.1.1"
	r.knownDeviceIPs[ip] = true

	g, _ := gatewayWithWhoisByAddr(t, r, map[string]*apitype.WhoIsResponse{
		ip: stubWhoisNode("", "agent", ip+"/32"),
	})

	if bound, unbound := g.bindUnboundDevicesFromWhoIs(); len(bound) != 0 || !slices.Equal(unbound, []string{ip}) {
		t.Fatalf("bound = %v, unbound = %v; want [], [%s]", bound, unbound, ip)
	}
	if got := r.NodeIDForIP(ip); got != "" {
		t.Fatalf("NodeIDForIP(%s) = %q, want nothing recorded", ip, got)
	}
}

// BindNodeIfUnbound only binds rows that exist: a row deleted during
// the WhoIs round-trip must not be re-created by the binding.
func TestBindNodeIfUnboundRefusesForgottenRow(t *testing.T) {
	r := newOnboardRegistry()
	const ip = "100.64.1.1"
	r.knownDeviceIPs[ip] = true
	r.ForgetIP(ip)

	if r.BindNodeIfUnbound(ip, "nodeA") {
		t.Fatal("bound a forgotten row")
	}
	if r.HasDevice(ip) {
		t.Fatal("binding re-created a forgotten row")
	}
	if r.BindNodeIfUnbound("", "nodeA") || r.BindNodeIfUnbound(ip, "") {
		t.Fatal("bound with an empty ip or node id")
	}
}

// A gateway running both transports has WireGuard rows with no node
// binding and no node behind them. They are not candidates: never
// asked about, never reported as rows to delete.
func TestBindUnboundDevicesSkipsNonTailnetRows(t *testing.T) {
	r := newOnboardRegistry()
	const wgIP = "10.55.0.7"
	const tsIP = "100.64.1.1"
	r.knownDeviceIPs[wgIP] = true
	r.knownDeviceIPs[tsIP] = true

	g, rt := gatewayWithWhoisByAddr(t, r, map[string]*apitype.WhoIsResponse{
		tsIP: stubWhoisNode("nodeA", "agent", tsIP+"/32"),
	})
	logs := captureLog(t)

	bound, unbound := g.bindUnboundDevicesFromWhoIs()
	if !slices.Equal(bound, []string{tsIP}) || len(unbound) != 0 {
		t.Fatalf("bound = %v, unbound = %v; want [%s], []", bound, unbound, tsIP)
	}
	if !slices.Equal(rt.asked, []string{tsIP}) {
		t.Fatalf("WhoIs asked about %v, want only %s", rt.asked, tsIP)
	}
	if strings.Contains(logs.String(), wgIP) {
		t.Fatalf("WireGuard row reported; logs:\n%s", logs.String())
	}
	// It stays unbound in the registry's own view, which is correct:
	// nothing on the tailnet side has anything to say about it.
	if got := r.UnboundDeviceIPs(); !slices.Equal(got, []string{wgIP}) {
		t.Fatalf("UnboundDeviceIPs = %v, want [%s]", got, wgIP)
	}
}

// A row that is bound or deleted while its WhoIs is in flight — the
// daemon re-registered, the operator removed the device — is neither
// bound by this pass nor reported as a row to delete.
func TestBindUnboundDevicesDoesNotReportRowsChangedDuringWhois(t *testing.T) {
	r := newOnboardRegistry()
	const registered = "100.64.1.1"
	const deleted = "100.64.2.2"
	const gone = "100.64.3.3"
	r.knownDeviceIPs[registered] = true
	r.knownDeviceIPs[deleted] = true
	r.knownDeviceIPs[gone] = true

	g, rt := gatewayWithWhoisByAddr(t, r, map[string]*apitype.WhoIsResponse{
		// Both answers would have bound the row had nothing moved.
		registered: stubWhoisNode("nodeA", "agent", registered+"/32"),
		deleted:    stubWhoisNode("nodeB", "agent", deleted+"/32"),
	})
	rt.onAsk = func(host string) {
		switch host {
		case registered:
			r.SetNodeID(registered, "nodeREG") // the register path landed first
		case deleted:
			r.ForgetIP(deleted)
		}
	}
	logs := captureLog(t)

	bound, unbound := g.bindUnboundDevicesFromWhoIs()
	if len(bound) != 0 || !slices.Equal(unbound, []string{gone}) {
		t.Fatalf("bound = %v, unbound = %v; want [], [%s]", bound, unbound, gone)
	}
	if got := r.NodeIDForIP(registered); got != "nodeREG" {
		t.Fatalf("NodeIDForIP(%s) = %q, want the register path's binding kept", registered, got)
	}
	if r.HasDevice(deleted) {
		t.Fatalf("deleted row %s was re-created", deleted)
	}
	if strings.Contains(logs.String(), registered) || strings.Contains(logs.String(), deleted) {
		t.Fatalf("a row that moved during WhoIs was reported; logs:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), gone) {
		t.Fatalf("the row with no node was not reported; logs:\n%s", logs.String())
	}
}

// A WireGuard subnet carved out of the CGNAT range is still the
// WireGuard transport's: its rows are excluded by configuration, not
// by range.
func TestBindUnboundDevicesSkipsWireGuardSubnetInsideCGNAT(t *testing.T) {
	r := newOnboardRegistry()
	const wgIP = "100.100.0.7"
	const tsIP = "100.64.1.1"
	r.knownDeviceIPs[wgIP] = true
	r.knownDeviceIPs[tsIP] = true

	g, rt := gatewayWithWhoisByAddr(t, r, map[string]*apitype.WhoIsResponse{
		wgIP: stubWhoisNode("nodeX", "stranger", wgIP+"/32"),
		tsIP: stubWhoisNode("nodeA", "agent", tsIP+"/32"),
	})
	g.cfg.Store(&config.Gateway{Settings: &config.GatewaySettings{
		Tailscale: &config.TailscaleBlock{AuthKey: "tskey-test"},
		WireGuard: &config.WireGuardBlock{SubnetCIDR: "100.100.0.0/24"},
	}})

	bound, unbound := g.bindUnboundDevicesFromWhoIs()
	if !slices.Equal(bound, []string{tsIP}) || len(unbound) != 0 {
		t.Fatalf("bound = %v, unbound = %v; want [%s], []", bound, unbound, tsIP)
	}
	if !slices.Equal(rt.asked, []string{tsIP}) {
		t.Fatalf("WhoIs asked about %v, want only %s", rt.asked, tsIP)
	}
	if got := r.NodeIDForIP(wgIP); got != "" {
		t.Fatalf("NodeIDForIP(%s) = %q, want a WireGuard row left alone", wgIP, got)
	}
}

// Without a tsnet LocalClient (WireGuard mode) the pass is a no-op.
func TestBindUnboundDevicesNoopWithoutTsnet(t *testing.T) {
	r := newOnboardRegistry()
	r.knownDeviceIPs["100.64.1.1"] = true
	g := &Gateway{onboard: r}
	if bound, unbound := g.bindUnboundDevicesFromWhoIs(); bound != nil || unbound != nil {
		t.Fatalf("bound = %v, unbound = %v; want nil, nil", bound, unbound)
	}
}
