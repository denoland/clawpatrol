//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
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
// the liveness prober (nil when unavailable), and the peer API token for
// deregister.
type bridgeSession struct {
	dev          *device.Device
	tun          wgtun.Device
	prober       *icmpProber
	apiToken     string
	stopWatchdog context.CancelFunc
	reconnect    chan struct{}
}

func (s *bridgeSession) close() {
	if s.stopWatchdog != nil {
		s.stopWatchdog()
	}
	_ = s.prober.Close()
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

	// The bridge's own traffic to the gateway and DNS carries the mark, so it
	// uses the underlay routes while workload traffic uses the tunnel.
	bridgeResolver, enrollmentHTTPClient = newMarkedNet(opt.FWMark)
	if !opt.EgressFilter {
		log.Printf("bridge: WARNING: --egress-filter=off; pod traffic can leave outside the tunnel through CNI link and subnet routes")
	}

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

	// Underlay route: the pod's pre-tunnel default on first boot, or the copy
	// in the bridge's table after an in-process reconnect or a restart
	// (clawpatrol0 is gone, so the main table has no default route).
	route4, src4, ok4 := discoverUnderlayRoute("-4", opt.FWMark, opt.Iface)
	if !ok4 {
		return nil, fmt.Errorf("no usable underlay route: neither a default route nor the bridge's routing table %d has one", opt.FWMark)
	}
	// IPv6 is optional: present only when the pod already has a v6 underlay route.
	route6, _, have6 := discoverUnderlayRoute("-6", opt.FWMark, opt.Iface)

	if st.reconnects == 0 && st.bringUpFails == 0 {
		if src4 == "table" {
			log.Printf("bridge: no default route at start — recovered underlay gateway via %s dev %s from routing table %d; recovery boot, re-enrolling", route4.Via, route4.Dev, opt.FWMark)
		} else {
			log.Printf("bridge: starting; underlay gateway via %s dev %s, enrolling with %s", route4.Via, route4.Dev, opt.AuthorizerName)
		}
	}
	if err := installUnderlayRouting(route4, route6, have6, opt.FWMark, opt.FWMark, opt.RouteProto); err != nil {
		return nil, err
	}
	if opt.EgressFilter {
		if err := installEgressFilter(opt.Iface, opt.FWMark); err != nil {
			return nil, err
		}
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
	if endpointIP.Is6() && !have6 {
		return nil, fmt.Errorf("wireguard endpoint %s is IPv6 but the pod has no IPv6 underlay route", endpointAddr)
	}

	gwTunIP, err := netip.ParseAddr(strings.TrimSpace(registerResp.GatewayTunnelIP))
	if err != nil {
		return nil, fmt.Errorf("gateway did not return a usable tunnel IP %q: %w", registerResp.GatewayTunnelIP, err)
	}

	tunDev, err := wgtun.CreateTUN(opt.Iface, opt.MTU)
	if err != nil {
		return nil, fmt.Errorf("create tun %s: %w (the bridge needs the /dev/net/tun device and NET_ADMIN; see \"Runtime compatibility\" in the Kubernetes enrollment docs)", opt.Iface, err)
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
	ipc, err := buildTunWGIpc(clientPrivB64, registerResp.ServerPublicKey, endpointAddr, keepaliveSecs, opt.FWMark)
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
	prober, err := openICMPProber(gwTunIP)
	if err != nil {
		if !errors.Is(err, errProbeUnavailable) {
			return nil, err
		}
		log.Printf("bridge: WARNING: %v. Set the pod sysctl net.ipv4.ping_group_range=\"0 2147483647\" or keep NET_RAW on the bridge container. Until then the watchdog uses WireGuard handshake age, which detects a dead tunnel more slowly.", err)
		prober = nil
	}
	defer func() {
		if !ok {
			_ = prober.Close()
		}
	}()
	var probe func() error
	if prober != nil {
		probe = func() error { return prober.Probe(wgProbeTimeout) }
	}
	lastHandshake := func() time.Time {
		uapi, err := dev.IpcGet()
		if err != nil {
			return time.Time{}
		}
		if s := parsePeerStats(uapi); s != nil {
			return s.lastHandshake
		}
		return time.Time{}
	}

	// Readiness needs a working data path, not only a reachable API: a
	// blocked or wrong WireGuard endpoint must not let the workload start.
	if err := waitForTunnel(ctx, lastHandshake, probe, bridgeTunnelReadyPoll, bridgeTunnelReadyTimeout); err != nil {
		return nil, fmt.Errorf("tunnel to %s is not ready: %w", endpointAddr, err)
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
		prober:       prober,
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
			probe:               probe,
			lastHandshake:       lastHandshake,
			handshakeStaleAfter: bridgeHandshakeStaleAfter(keepalive),
			rekey:               func() error { return dev.IpcSet(ipc) },
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

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func buildTunWGIpc(privateKeyB64, serverPublicKeyB64, endpoint string, keepaliveSeconds, fwmark int) (string, error) {
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
	// Mark the tunnel's UDP socket so its packets use the underlay routes.
	fmt.Fprintf(&b, "fwmark=%d\n", fwmark)
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

// discoverUnderlayRoute resolves the pod's pre-tunnel default route for a
// family ("-4" / "-6"). It prefers the live default route in the main table
// (the normal first boot) and falls back to the copy in the bridge's routing
// table, which is how a reconnect or a restarted bridge recovers the underlay
// when clawpatrol0 and its default route are gone. The middle return value is
// the source: "default" or "table". ok=false means neither has a route; for v4
// that's fatal to bring-up, for v6 it just means "no IPv6 underlay".
func discoverUnderlayRoute(family string, table int, iface string) (linuxDefaultRoute, string, bool) {
	if out, err := exec.Command("ip", family, "route", "show", "default").Output(); err == nil {
		if r, err := parseDefaultRoute(out); err == nil && r.Dev != "" && r.Dev != iface {
			return r, "default", true
		}
	}
	out, err := exec.Command("ip", family, "route", "show", "default", "table", strconv.Itoa(table)).Output()
	if err != nil {
		return linuxDefaultRoute{}, "", false
	}
	if r, err := parseDefaultRoute(out); err == nil && r.Dev != "" {
		return r, "table", true
	}
	return linuxDefaultRoute{}, "", false
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

// resolveWGEndpoint resolves the WireGuard endpoint host:port to a concrete
// ip:port, preferring IPv4 (see preferV4). Returns the chosen IP so the
// caller can check that its family has an underlay route.
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
	// Drop gateway-sent CA vars: the local bundle must win, and the last
	// export of a name wins in a shell.
	vars = append(caPathPushdownVars(opt.CAOut), dropClawpatrolCAVars(vars)...)
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
