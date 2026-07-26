//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// bridgeState is the sidecar's retained in-memory state.
type bridgeState struct {
	reconnects     int
	bringUpFails   int
	handoffWritten bool
}

// bridgeSession is one live tunnel: the userspace WireGuard device, its TUN,
// and the peer API token for deregister.
type bridgeSession struct {
	dev          *device.Device
	tun          wgtun.Device
	apiToken     string
	stopWatchdog context.CancelFunc
	reconnect    chan struct{}
}

func (s *bridgeSession) close() {
	if s.stopWatchdog != nil {
		s.stopWatchdog()
	}
	if s.dev != nil {
		s.dev.Close()
	}
	if s.tun != nil {
		_ = s.tun.Close()
	}
}

// bridgeRun is the resident, privileged data plane behind `clawpatrol bridge`.
func bridgeRun(ctx context.Context, opt bridgeOptions) error {
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st := &bridgeState{}
	backoff := time.Second
	for {
		sess, err := bridgeBringUp(sigCtx, opt, st)
		if err != nil {
			if sigCtx.Err() != nil {
				return nil
			}
			st.bringUpFails++
			log.Printf("bridge: bring-up failed (attempt %d): %v — retrying in %s", st.bringUpFails, err, backoff)
			select {
			case <-sigCtx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = minDuration(backoff*2, 30*time.Second)
			continue
		}
		st.bringUpFails = 0
		backoff = time.Second

		select {
		case <-sigCtx.Done():
			// Graceful shutdown: best-effort deregister (bounded so a hung
			// gateway/DNS call can't delay pod termination past the grace
			// period), then tear the tunnel down. The netns goes with the pod.
			delCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			enrollmentDeregister(delCtx, opt.GatewayURL, sess.apiToken)
			cancel()
			sess.close()
			return nil
		case <-sess.reconnect:
			// The watchdog gave up on this session. Tear it down — egress fails
			// closed during the gap — and loop: bring-up re-discovers DNS +
			// underlay and reconciles the tagged pins before re-enrolling. Skip
			// deregister: the peer is either reaped already or reused by IP.
			st.reconnects++
			log.Printf("bridge: liveness lost — reconnecting in-process (reconnect #%d)", st.reconnects)
			sess.close()
		}
	}
}

// bridgeBringUp performs one enroll + tunnel bring-up and returns a live
// session. It is re-callable: every call re-reads /etc/resolv.conf and
// re-discovers the underlay.
func bridgeBringUp(ctx context.Context, opt bridgeOptions, st *bridgeState) (_ *bridgeSession, err error) {
	claims, credential, err := gatherEnrollmentClaims(opt.AuthorizerType, opt.KubeTokenPath)
	if err != nil {
		return nil, err
	}
	clientPrivB64, _, clientPubB64, err := wgGenKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate wireguard keypair: %w", err)
	}

	// Underlay route: the pod's pre-tunnel default on first boot, or a surviving
	// tagged pin after an in-process reconnect / genuine restart (clawpatrol0 is
	// gone, so there is no default route).
	route4, src4, ok4 := discoverUnderlayRoute("-4", opt.RouteProto)
	if !ok4 {
		return nil, fmt.Errorf("no usable underlay route: neither a default route nor a tagged clawpatrol pin was found")
	}
	// IPv6 is optional: present only when the pod already has a v6 underlay route.
	route6, _, have6 := discoverUnderlayRoute("-6", opt.RouteProto)

	if st.reconnects == 0 && st.bringUpFails == 0 {
		if src4 == "pin" {
			log.Printf("bridge: no default route at start — recovered underlay gateway via %s dev %s from tagged pins (proto %s); recovery boot, re-enrolling", route4.Via, route4.Dev, opt.RouteProto)
		} else {
			log.Printf("bridge: starting; underlay gateway via %s dev %s, enrolling with %s", route4.Via, route4.Dev, opt.AuthorizerName)
		}
	}

	// Re-read resolv.conf every bring-up (it may have swapped).
	resolverIPs := resolvConfNameservers()
	_ = pinHosts(resolverIPs, route4, route6, have6, opt.RouteProto, false)

	apiURL, err := url.Parse(opt.GatewayURL)
	if err != nil {
		return nil, fmt.Errorf("gateway-url: %w", err)
	}

	apiIPs, err := lookupHostIPs(apiURL.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve gateway api host %q: %w", apiURL.Hostname(), err)
	}
	if err := pinHosts(apiIPs, route4, route6, have6, opt.RouteProto, true); err != nil {
		return nil, err
	}

	registerResp, err := enrollmentRegister(ctx, opt.GatewayURL, credential, enrollmentRegisterRequest{
		Transport:          enrollmentTransportWireGuard,
		Authorizer:         opt.AuthorizerName,
		WireGuardPublicKey: clientPubB64,
		Claims:             claims,
		// The sidecar is the sole authoritative keepalive sender; request the
		// resolved interval + reap count so it can keepalive and size its
		// watchdog escalation. The gateway should not keepalive back.
		Keepalive: true,
	})
	if err != nil {
		return nil, err
	}
	if registerResp.MTU != 0 {
		opt.MTU = registerResp.MTU
	}
	log.Printf("bridge: enrolled peer_ip=%s keepalive=%ds reap_count=%d gateway_tunnel_ip=%s",
		registerResp.PeerIP, registerResp.KeepaliveIntervalSeconds, registerResp.KeepaliveReapCount, registerResp.GatewayTunnelIP)

	endpointIP, endpointAddr, err := resolveWGEndpoint(registerResp.Endpoint)
	if err != nil {
		return nil, err
	}
	if err := pinHosts([]netip.Addr{endpointIP}, route4, route6, have6, opt.RouteProto, true); err != nil {
		return nil, fmt.Errorf("pin wg endpoint: %w", err)
	}
	// Now that the full desired set is known, prune any tagged pin no longer needed
	want := map[netip.Addr]bool{endpointIP: true}
	for _, ip := range resolverIPs {
		want[ip] = true
	}
	for _, ip := range apiIPs {
		want[ip] = true
	}
	pruneStalePins(want, opt.RouteProto)

	gwTunIP, err := netip.ParseAddr(strings.TrimSpace(registerResp.GatewayTunnelIP))
	if err != nil {
		return nil, fmt.Errorf("gateway did not return a usable tunnel IP %q: %w", registerResp.GatewayTunnelIP, err)
	}

	tunDev, err := wgtun.CreateTUN(opt.Iface, opt.MTU)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = tunDev.Close()
		}
	}()
	ifaceName, err := tunDev.Name()
	if err != nil {
		return nil, fmt.Errorf("tun name: %w", err)
	}
	logger := device.NewLogger(device.LogLevelError, "[clawpatrol tun wg] ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	defer func() {
		if !ok {
			dev.Close()
		}
	}()

	if err := setupTunDevice(ifaceName, opt.MTU, registerResp.PeerIP, registerResp.PeerIPv6); err != nil {
		return nil, err
	}
	keepaliveSecs := registerResp.KeepaliveIntervalSeconds
	if keepaliveSecs <= 0 {
		keepaliveSecs = 25
	}
	ipc, err := buildTunWGIpc(clientPrivB64, registerResp.ServerPublicKey, endpointAddr, keepaliveSecs)
	if err != nil {
		return nil, err
	}
	if err := dev.IpcSet(ipc); err != nil {
		return nil, fmt.Errorf("wg IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("wg up: %w", err)
	}
	if err := replaceDefaultRoutes(ifaceName, have6); err != nil {
		return nil, err
	}

	// env + CA handoff only on the first successful bring-up: the workload reads
	// it once, and it does not change across reconnects for the same subject.
	if !st.handoffWritten {
		envVars, err := enrollmentFetchEnv(ctx, opt.GatewayURL, registerResp.APIToken)
		if err != nil {
			return nil, err
		}
		if err := writeTunFiles(opt, envVars, registerResp.CAPEM); err != nil {
			return nil, err
		}
		st.handoffWritten = true
	}

	// Watchdog: rx_bytes is the cheap positive signal, an ICMP echo to the
	// gateway tunnel IP is the active probe when rx goes quiet. Cadence and
	// escalation reuse the keepalive interval and the server-dictated reap
	// count so the client stays in lock-step with the reaper.
	keepalive := time.Duration(keepaliveSecs) * time.Second
	reconnectAfter := registerResp.KeepaliveReapCount
	rekeyAfter := bridgeWatchdogResetMisses(opt.LocalResetMisses, reconnectAfter)

	wdCtx, stopWatchdog := context.WithCancel(context.Background())
	sess := &bridgeSession{
		dev:          dev,
		tun:          tunDev,
		apiToken:     registerResp.APIToken,
		stopWatchdog: stopWatchdog,
		reconnect:    make(chan struct{}, 1),
	}
	ticker := time.NewTicker(bridgeWatchdogPoll)
	go func() {
		defer ticker.Stop()
		runBridgeWatchdogLoop(wdCtx, bridgeWatchdogConfig{
			rx: func() uint64 {
				uapi, err := dev.IpcGet()
				if err != nil {
					return 0
				}
				if s := parsePeerStats(uapi); s != nil {
					return s.rxBytes
				}
				return 0
			},
			probe: func() error { return pingGatewayTunnel(gwTunIP, wgProbeTimeout) },
			rekey: func() error { return dev.IpcSet(ipc) },
			reconnect: func() {
				select {
				case sess.reconnect <- struct{}{}:
				default:
				}
			},
			tick: ticker.C,
			now:  time.Now,

			probeAfter:          keepalive,
			probeInterval:       keepalive,
			rekeyAfterFails:     rekeyAfter,
			reconnectAfterFails: reconnectAfter,
		})
	}()
	ok = true
	return sess, nil
}

// pinHosts pins each host to its family's underlay route, tagged with proto.
// When fatal, the first pin error aborts (an unpinned control-plane host
// blackholes the path); otherwise pins are best-effort. Hosts of a family with
// no underlay route are skipped.
func pinHosts(hosts []netip.Addr, route4, route6 linuxDefaultRoute, have6 bool, proto string, fatal bool) error {
	for _, ip := range hosts {
		if !ip.Is4() && !have6 {
			continue
		}
		if err := pinHostRoute(ip, route4, route6, have6, proto); err != nil {
			if fatal {
				return fmt.Errorf("pin host route %s: %w", ip, err)
			}
			log.Printf("bridge: pin route %s: %v — continuing", ip, err)
		}
	}
	return nil
}

// pruneStalePins deletes every proto-tagged route whose destination host is
// not in want. The proto tag makes the pinned set self-identifying, so the
// bridge can rebuild its control-plane routes without ever touching CNI ones.
func pruneStalePins(want map[netip.Addr]bool, proto string) {
	for _, fam := range []string{"-4", "-6"} {
		for _, ip := range listPinnedHosts(fam, proto) {
			if want[ip] {
				continue
			}
			dst := ip.String() + "/32"
			if ip.Is6() {
				dst = ip.String() + "/128"
			}
			_ = runIP("ip", fam, "route", "del", dst, "proto", proto)
		}
	}
}

// listPinnedHosts returns the destination host of every proto-tagged route in
// the given family ("-4"/"-6") — the bridge's own control-plane pins.
func listPinnedHosts(family, proto string) []netip.Addr {
	out, err := exec.Command("ip", family, "route", "show", "proto", proto).Output()
	if err != nil {
		return nil
	}
	var hosts []netip.Addr
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		dst, _, _ := strings.Cut(fields[0], "/")
		if ip, err := netip.ParseAddr(dst); err == nil {
			hosts = append(hosts, ip)
		}
	}
	return hosts
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func buildTunWGIpc(privateKeyB64, serverPublicKeyB64, endpoint string, keepaliveSeconds int) (string, error) {
	privHex, err := base64DecodeToHex(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	pubRaw, err := normalizeWGPublicKey(serverPublicKeyB64)
	if err != nil {
		return "", fmt.Errorf("server public key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pubRaw)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	// The gateway returns the client keepalive cadence at enrollment. Fall back
	// to 25s for compatibility with older responses.
	if keepaliveSeconds <= 0 {
		keepaliveSeconds = 25
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepaliveSeconds)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	return b.String(), nil
}

func setupTunDevice(iface string, mtu int, peerIP, peerIPv6 string) error {
	steps := [][]string{
		{"ip", "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu), "up"},
		{"ip", "addr", "replace", peerIP + "/32", "dev", iface},
	}
	for _, step := range steps {
		if err := runIP(step...); err != nil {
			return err
		}
	}
	// IPv6 is best-effort: a netns without IPv6 (e.g. the host booted with
	// ipv6.disable=1) must still bring up the v4 tunnel. This mirrors the
	// optional v6 default route in replaceDefaultRoutes and the child-netns
	// degradation in run_linux.go — never let a missing v6 stack be fatal.
	if peerIPv6 != "" {
		if err := runIP("ip", "-6", "addr", "replace", peerIPv6+"/128", "dev", iface); err != nil {
			log.Printf("bridge: ip -6 addr replace %s/128 dev %s: %v — continuing without IPv6 in the sandbox", peerIPv6, iface, err)
		}
	}
	return nil
}

// discoverUnderlayRoute resolves the pod's pre-tunnel route for a family
// ("-4" / "-6"). It prefers the live default route (the normal first-boot
// case) and falls back to a surviving tagged clawpatrol pin, which is how an
// in-process reconnect recovers the underlay gateway when there is no default
// route left. The middle return value is the source: "default" when it came
// from the live default route (normal first boot) or "pin" when it was
// recovered from a tagged pin (an in-process reconnect). Source "" with ok=false
// means neither was available — for v4 that's fatal to bring-up; for v6 it
// just means "no IPv6 underlay", same as before.
func discoverUnderlayRoute(family, proto string) (linuxDefaultRoute, string, bool) {
	if out, err := exec.Command("ip", family, "route", "show", "default").Output(); err == nil {
		if r, err := parseDefaultRoute(out); err == nil && r.Dev != "" {
			return r, "default", true
		}
	}
	// No usable default during reconnect. Recover via/dev from a pin we
	// tagged on first boot; they live on the underlay device and survive.
	out, err := exec.Command("ip", family, "route", "show", "proto", proto).Output()
	if err != nil {
		return linuxDefaultRoute{}, "", false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if r, err := parsePinnedRoute(line); err == nil && r.Dev != "" {
			return r, "pin", true
		}
	}
	return linuxDefaultRoute{}, "", false
}

// parsePinnedRoute extracts the via/dev from one `ip route show proto` line
// (e.g. "10.96.0.1 via 10.244.0.1 dev eth0 proto 111"). Unlike a default
// route, the leading token is the pinned host, so we only read via/dev.
func parsePinnedRoute(line string) (linuxDefaultRoute, error) {
	fields := strings.Fields(line)
	var r linuxDefaultRoute
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			r.Via = fields[i+1]
		case "dev":
			r.Dev = fields[i+1]
		}
	}
	if r.Dev == "" {
		return linuxDefaultRoute{}, fmt.Errorf("no dev in route line %q", line)
	}
	return r, nil
}

// resolvConfNameservers returns the nameserver IPs from /etc/resolv.conf.
// resolv.conf nameservers are always IP literals, so each parses cleanly; a
// missing or nameserver-less file yields nil (DNS pinning is best-effort).
func resolvConfNameservers() []netip.Addr {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip, err := netip.ParseAddr(fields[1]); err == nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

func replaceDefaultRoutes(iface string, replace6 bool) error {
	if err := runIP("ip", "route", "replace", "default", "dev", iface); err != nil {
		return err
	}
	if replace6 {
		// Only tunnel v6 when the pod already had a v6 default route — never
		// create one, which would blackhole v6 that previously had no route.
		_ = runIP("ip", "-6", "route", "replace", "default", "dev", iface)
	}
	return nil
}

type linuxDefaultRoute struct {
	Dev string
	Via string
}

func parseDefaultRoute(out []byte) (linuxDefaultRoute, error) {
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return linuxDefaultRoute{}, fmt.Errorf("no default route")
	}
	var r linuxDefaultRoute
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			r.Via = fields[i+1]
		case "dev":
			r.Dev = fields[i+1]
		}
	}
	if r.Dev == "" {
		return linuxDefaultRoute{}, fmt.Errorf("default route has no dev: %s", strings.TrimSpace(string(out)))
	}
	return r, nil
}

func pinHostRoute4(ip netip.Addr, route linuxDefaultRoute, proto string) error {
	dst := ip.String() + "/32"
	args := []string{"ip", "route", "replace", dst}
	if route.Via != "" {
		args = append(args, "via", route.Via)
	}
	args = append(args, "dev", route.Dev, "proto", proto)
	return runIP(args...)
}

func pinHostRoute6(ip netip.Addr, route linuxDefaultRoute, proto string) error {
	dst := ip.String() + "/128"
	args := []string{"ip", "-6", "route", "replace", dst}
	if route.Via != "" {
		args = append(args, "via", route.Via)
	}
	args = append(args, "dev", route.Dev, "proto", proto)
	return runIP(args...)
}

// pinHostRoute pins ip to its family's pre-tunnel default route, tagged with
// proto so it can be recovered during an in-process reconnect.
func pinHostRoute(ip netip.Addr, route4, route6 linuxDefaultRoute, have6 bool, proto string) error {
	if ip.Is4() {
		return pinHostRoute4(ip, route4, proto)
	}
	if !have6 {
		return fmt.Errorf("no IPv6 default route to pin %s", ip)
	}
	return pinHostRoute6(ip, route6, proto)
}

// resolveWGEndpoint resolves the WireGuard endpoint host:port to a concrete
// ip:port, preferring IPv4 (see preferV4). Returns the chosen IP so the
// caller can pin a host route to it before the default route flips to the
// tunnel.
func resolveWGEndpoint(endpoint string) (netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	ips, err := lookupHostIPs(host)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("resolve endpoint %q: %w", host, err)
	}
	ip, ok := preferV4(ips)
	if !ok {
		return netip.Addr{}, "", fmt.Errorf("resolve endpoint %q: no A/AAAA records", host)
	}
	return ip, net.JoinHostPort(ip.String(), port), nil
}

func lookupHostIPs(host string) ([]netip.Addr, error) {
	if host == "" {
		return nil, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			// Unmap 4-in-6 so Is4()/family checks and route pinning behave.
			out = append(out, addr.Unmap())
		}
	}
	return out, nil
}

func runIP(args ...string) error {
	if len(args) == 0 {
		return nil
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func writeTunFiles(opt bridgeOptions, vars []pushdownEnvVar, caPEM string) error {
	if err := os.MkdirAll(filepath.Dir(opt.EnvOut), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opt.CAOut), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opt.ReadyFile), 0o755); err != nil {
		return err
	}
	if caPEM != "" {
		if err := os.WriteFile(opt.CAOut, []byte(caPEM), 0o644); err != nil {
			return fmt.Errorf("write ca: %w", err)
		}
	}
	vars = append(caPathPushdownVars(opt.CAOut), vars...)
	var buf bytes.Buffer
	for _, ev := range vars {
		if ev.Name == "" {
			continue
		}
		fmt.Fprintf(&buf, "export %s=%q\n", ev.Name, ev.Value)
	}
	if err := os.WriteFile(opt.EnvOut, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write env: %w", err)
	}
	if err := os.WriteFile(opt.ReadyFile, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write ready: %w", err)
	}
	return nil
}
