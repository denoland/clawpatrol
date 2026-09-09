//go:build linux

package main

// wgTransport: daemonTransport implementation backed by an in-process
// wireguard-go device + gVisor netstack. Same pattern as
// macos/netstack/wgnetstack.go (client-side WG netstack for the NE),
// adapted to the Linux daemon's lifecycle.
//
// One wireguard-go device per daemon — the persistent peer minted at
// `clawpatrol join` time, keyed by the wg.conf at
// ~/.config/clawpatrol/wg.conf. Every `clawpatrol run` session
// multiplexes through this single device via the per-session gVisor
// TCP forwarder built in daemon_linux.go.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	// wgClientMTU mirrors the per-process wireguard-go MTU used by
	// the macOS NE and the gateway side. Path-MTU + ICMP frag-needed
	// in wireguard-go shaves this down further when needed.
	wgClientMTU = 1420
	// wgClientKeepalive forces wireguard-go to send periodic keepalives
	// so the first user flow doesn't race the initial handshake. See
	// macos/netstack/wgnetstack.go for the same rationale.
	wgClientKeepalive = 10
	// wgWatchdogPoll is how often the handshake-recovery watchdog samples
	// the peer's last_handshake_time_sec + tx_bytes. The watchdog only
	// acts once the handshake is older than wgWatchdogStuckTimeout, so a
	// few seconds between polls is plenty and stays cheap.
	wgWatchdogPoll = 5 * time.Second
	// wgWatchdogStuckTimeout mirrors wireguard's RejectAfterTime (180s):
	// below this a stale last_handshake is normal (no rekey was due), so
	// rebuilding the peer would only add churn. Past it, with traffic
	// still being staged, the handshake is genuinely wedged.
	wgWatchdogStuckTimeout = 3 * time.Minute
	// wgWatchdogResetCooldown holds off back-to-back rebuilds so a fresh
	// initiation has time to complete before the watchdog fires again.
	wgWatchdogResetCooldown = time.Minute
)

type wgTransport struct {
	dev         *device.Device
	tun         *wgClientTun
	localAddr   netip.Addr
	bootWarning string

	// stopWatchdog cancels the handshake-recovery watchdog goroutine.
	// Set by startWGTransport, invoked by Close.
	stopWatchdog context.CancelFunc
}

func (t *wgTransport) LocalAddr() netip.Addr { return t.localAddr }
func (t *wgTransport) BootWarning() string   { return t.bootWarning }

func (t *wgTransport) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// daemon's TCP forwarder always hands us an IP literal (it
		// reads dst directly off the gVisor TCP forwarder request); DNS
		// is handled separately by the UDP forwarder.
		return nil, fmt.Errorf("wg dial: host %q is not an IP literal", host)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, fmt.Errorf("wg dial: parse port %q: %w", portStr, err)
	}
	proto := ipv4.ProtocolNumber
	if ip.Is6() {
		proto = ipv6.ProtocolNumber
	}
	full := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: port,
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialContextTCP(ctx, t.tun.stack, full, proto)
	case "udp", "udp4", "udp6":
		return gonet.DialUDP(t.tun.stack, nil, &full, proto)
	default:
		return nil, fmt.Errorf("wg dial: unsupported network %q", network)
	}
}

func (t *wgTransport) Close() error {
	if t.stopWatchdog != nil {
		t.stopWatchdog()
	}
	if t.dev != nil {
		t.dev.Close()
	}
	if t.tun != nil {
		_ = t.tun.Close()
	}
	return nil
}

// startWGTransport reads the user wg.conf written by `clawpatrol join`,
// brings up a wireguard-go device + gVisor stack, and waits for the
// first handshake to complete so the first user flow doesn't race
// the initial wg negotiation.
func startWGTransport() (daemonTransport, error) {
	confPath := defaultRunConf()
	cfg, err := parseRunConf(confPath)
	if err != nil {
		return nil, fmt.Errorf("wg conf %s: %w (re-run `clawpatrol join`)", confPath, err)
	}

	addrs := splitWGAddresses(cfg.Address)
	var clientIP, clientIP6 netip.Addr
	for _, a := range addrs {
		s := a
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		ip, perr := netip.ParseAddr(s)
		if perr != nil {
			continue
		}
		if ip.Is4() && !clientIP.IsValid() {
			clientIP = ip
		} else if ip.Is6() && !clientIP6.IsValid() {
			clientIP6 = ip
		}
	}
	if !clientIP.IsValid() {
		return nil, fmt.Errorf("wg conf: no IPv4 in Address %q", cfg.Address)
	}

	tun, err := newWGClientTun(clientIP, clientIP6, wgClientMTU)
	if err != nil {
		return nil, fmt.Errorf("netTUN: %w", err)
	}
	// forceReset lets the watchdog short-circuit its poll cadence the
	// instant wireguard-go logs the keypair-derivation failure, so the
	// stuck handshake state machine is rebuilt within milliseconds
	// rather than after the next stuck-timeout poll. Buffered to one so
	// concurrent failures coalesce into a single wake-up.
	forceReset := make(chan struct{}, 1)
	logger := wrapWGLogger(
		device.NewLogger(device.LogLevelError, "[clawpatrol daemon wg] "),
		forceReset,
	)
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	if err := dev.IpcSet(buildDaemonWGIpc(cfg)); err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("wg IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("wg up: %w", err)
	}

	log.Printf("daemon: wg device up, local addr %s", clientIP)

	// Wait for the first handshake so the first user flow doesn't race.
	// 10s is generous — under normal conditions the keepalive-driven
	// initiation completes well under one second. Treat a timeout as a
	// boot warning rather than a hard failure: traffic will still flow
	// once the peer eventually responds (could be a packet-loss spike
	// or DNS hiccup at startup).
	bootWarning := ""
	if !waitWGHandshake(dev, 10*time.Second) {
		bootWarning = "wg probe: no handshake from gateway within 10s. " +
			"Outbound traffic from `clawpatrol run` may stall until the " +
			"peer responds. Check the gateway endpoint and the host's " +
			"egress UDP/51820 path."
		log.Printf("%s", bootWarning)
	} else {
		log.Printf("daemon: wg handshake established")
	}

	// Start the handshake-recovery watchdog. Without it, a gateway
	// restart (which drops the gateway's in-memory peer/session state)
	// leaves the device holding a dead session: it keeps encrypting with
	// the old keypair until RejectAfterTime, then re-initiates — but the
	// wireguard-go state machine can wedge in handshakeInitiationCreated
	// and never recover, black-holing every flow (including tunnelled
	// DNS) until the daemon is killed and the peer rebuilt by hand. The
	// watchdog automates that rebuild: poll the handshake age, and when
	// it goes stale while traffic is still being staged, re-IpcSet the
	// peer to force a clean fresh initiation.
	watchdogCtx, stopWatchdog := context.WithCancel(context.Background())
	ticker := time.NewTicker(wgWatchdogPoll)
	go func() {
		defer ticker.Stop()
		runWGWatchdogLoop(watchdogCtx, wgWatchdogConfig{
			stats: func() *wgPeerStats {
				uapi, err := dev.IpcGet()
				if err != nil {
					return nil
				}
				return parsePeerStats(uapi)
			},
			reset:         func() error { return dev.IpcSet(buildDaemonWGIpc(cfg)) },
			log:           logger,
			forceReset:    forceReset,
			tick:          ticker.C,
			stuckTimeout:  wgWatchdogStuckTimeout,
			resetCooldown: wgWatchdogResetCooldown,
			now:           time.Now,
		})
	}()

	return &wgTransport{
		dev:          dev,
		tun:          tun,
		localAddr:    clientIP,
		bootWarning:  bootWarning,
		stopWatchdog: stopWatchdog,
	}, nil
}

// buildDaemonWGIpc renders the wireguard-go IpcSet payload from a
// parsed wg-quick conf. Forces a keepalive on so the handshake runs
// before the first user flow appears.
func buildDaemonWGIpc(c *runConf) string {
	var b strings.Builder
	privHex, _ := base64DecodeToHex(c.PrivateKey)
	pubHex, _ := base64DecodeToHex(c.PeerPubKey)
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pubHex)
	if ep, err := resolveEndpoint(c.Endpoint); err == nil {
		fmt.Fprintf(&b, "endpoint=%s\n", ep)
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", wgClientKeepalive)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	return b.String()
}

// base64DecodeToHex converts a wg-quick base64 key to wireguard-go's
// hex IPC encoding.
func base64DecodeToHex(b64 string) (string, error) {
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(dec), nil
}

// waitWGHandshake polls IpcGet for last_handshake_time_sec until it
// becomes non-zero or timeout. Returns true on success.
func waitWGHandshake(d *device.Device, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cfg, err := d.IpcGet(); err == nil {
			for _, line := range strings.Split(cfg, "\n") {
				if strings.HasPrefix(line, "last_handshake_time_sec=") {
					var sec int64
					_, _ = fmt.Sscanf(line, "last_handshake_time_sec=%d", &sec)
					if sec > 0 {
						return true
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// --- client-side wg-go tun adapter ----------------------------------

// wgClientTun is a wireguard-go tun.Device backed by a gVisor stack.
// wireguard-go calls Read to pull outbound IP packets (we hand it
// what the user's app injected into the stack) and Write to push
// inbound IP packets (we inject them into the stack so its sockets
// see them).
//
// Distinct from the gateway-side netTun in wireguard.go — that one
// is server-facing (different routing, separate metric stack). Don't
// merge the two without thinking through the global atomic pointer
// in wireguard.go's init().
type wgClientTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan wgtun.Event
	incomingPacket chan []byte
	done           chan struct{}
	mtu            int
	closed         bool
}

type wgClientEpNotify struct{ t *wgClientTun }

func (n *wgClientEpNotify) WriteNotify() {
	for {
		pkt := n.t.ep.Read()
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		pkt.DecRef()
		b := v.AsSlice()
		cp := make([]byte, len(b))
		copy(cp, b)
		select {
		case n.t.incomingPacket <- cp:
		case <-n.t.done:
			return
		}
	}
}

func newWGClientTun(addr, addr6 netip.Addr, mtu int) (*wgClientTun, error) {
	t := &wgClientTun{
		ep: channel.New(netstackQueueSize, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol, ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol, udp.NewProtocol,
			},
			HandleLocal: false,
		}),
		events:         make(chan wgtun.Event, 10),
		incomingPacket: make(chan []byte, netstackQueueSize),
		done:           make(chan struct{}),
		mtu:            mtu,
	}
	t.ep.AddNotify(&wgClientEpNotify{t: t})

	// TCP tuning — mirror the gateway/macos netstack values so behavior
	// matches across both sides of the tunnel.
	sackOpt := tcpip.TCPSACKEnabled(true)
	t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)
	rackOpt := tcpip.TCPRecovery(0)
	t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &rackOpt)
	ccOpt := tcpip.CongestionControlOption("reno")
	t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)
	minRTOOpt := tcpip.TCPMinRTOOption(time.Second)
	t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &minRTOOpt)
	rxBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &rxBufOpt)
	txBufOpt := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 6 << 20}
	t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &txBufOpt)

	if e := t.stack.CreateNIC(1, t.ep); e != nil {
		return nil, fmt.Errorf("CreateNIC: %v", e)
	}
	pa4 := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
	}
	if e := t.stack.AddProtocolAddress(1, pa4, stack.AddressProperties{}); e != nil {
		return nil, fmt.Errorf("AddProtocolAddress v4: %v", e)
	}
	if addr6.IsValid() {
		pa6 := tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(addr6.AsSlice()).WithPrefix(),
		}
		if e := t.stack.AddProtocolAddress(1, pa6, stack.AddressProperties{}); e != nil {
			return nil, fmt.Errorf("AddProtocolAddress v6: %v", e)
		}
	}
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})

	// Promiscuous + spoofing so dials originating from the gVisor stack
	// itself (gonet.DialContextTCP) can use any local address as src —
	// matches how the per-session gVisor stack on the client side is
	// configured (see newRunStack in daemon_session_linux.go).
	if e := t.stack.SetPromiscuousMode(1, true); e != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %v", e)
	}
	if e := t.stack.SetSpoofing(1, true); e != nil {
		return nil, fmt.Errorf("SetSpoofing: %v", e)
	}

	t.events <- wgtun.EventUp
	return t, nil
}

func (t *wgClientTun) File() *os.File             { return nil }
func (t *wgClientTun) Name() (string, error)      { return "clawpatrol-wg-client", nil }
func (t *wgClientTun) MTU() (int, error)          { return t.mtu, nil }
func (t *wgClientTun) Events() <-chan wgtun.Event { return t.events }
func (t *wgClientTun) BatchSize() int             { return tunBatchSize }

func (t *wgClientTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-t.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	count := 1
	for count < len(bufs) {
		select {
		case more, ok := <-t.incomingPacket:
			if !ok {
				return count, os.ErrClosed
			}
			sizes[count] = copy(bufs[count][offset:], more)
			count++
		default:
			return count, nil
		}
	}
	return count, nil
}

func (t *wgClientTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		})
		switch pkt[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
		}
	}
	return len(bufs), nil
}

func (t *wgClientTun) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	t.stack.RemoveNIC(1)
	t.stack.Close()
	close(t.events)
	close(t.done)
	close(t.incomingPacket)
	return nil
}
