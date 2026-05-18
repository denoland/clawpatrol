//go:build linux

package main

// `clawpatrol run` in Tailscale mode. Spins up an ephemeral tsnet.Server
// per invocation and bridges the child's netns TUN to the gateway via
// gVisor's TCP stack. No system-wide Tailscale required — tsnet runs
// entirely in-process.
//
// Why PROXY headers instead of the exit-node iptables REDIRECT path
// (origdst_linux.go):
//
// The exit-node REDIRECT path intercepts traffic from Tailscale exit-node
// clients — machines that have configured this gateway as their exit node via
// `tailscale set --exit-node=<gw>`. In that model, client traffic arrives on
// the gateway's tailscale0 interface and iptables diverts it to the gateway
// listener before kernel forwarding.
//
// `clawpatrol run` clients are NOT exit-node clients. The child process runs
// in its own network namespace with a gVisor TCP/IP stack as the default
// route. Each TCP connection the child makes is intercepted by gVisor and
// dialed out via tsnet directly to the gateway node over the tailnet — a
// peer-to-peer connection, not exit-node-forwarded traffic. The connection
// arrives at the gateway's TCP listener as a direct tailnet connection from
// the ephemeral node's 100.x.x.x; iptables REDIRECT on tailscale0 does not
// apply because the traffic is delivered to the gateway's own address, not
// forwarded onward.
//
// The PROXY header carries the original 4-tuple (srcIP, dstIP, srcPort,
// dstPort) so the gateway accept loop recovers what the child process was
// actually trying to reach (e.g., api.openai.com:443) and dispatches it
// identically to the WireGuard and exit-node paths.
//
// Flow:
//  1. POST /api/peer/ephemeral/tsnet → ephemeral Tailscale auth key
//  2. tsnet.Server{Ephemeral: true} joins the gateway's tailnet
//  3. Child in new user+net+mnt ns creates TUN, sends fd via SCM_RIGHTS
//  4. gVisor netstack reads from TUN, promiscuous TCP forwarder
//  5. Each TCP connection → tsnet.Dial(gwHost:gwPort) + HAProxy PROXY v1 header
//  6. Gateway recovers original dst from PROXY header, dispatches normally

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/tsnet"
)

func runRunTsnet(args []string) {
	warnIfOnGatewayHost()
	if os.Geteuid() == 0 {
		fail("run as your normal user; clawpatrol run uses unprivileged user namespaces which root cannot enter on this distro")
	}

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	noAutoExpose := fs.Bool("no-auto-expose", false, "disable the seccomp relay that mirrors TCP listeners inside the netns back to the host")
	_ = fs.Parse(args)
	cmd := fs.Args()
	if len(cmd) == 0 {
		fail("usage: clawpatrol run [--no-auto-expose] -- <cmd> [args...]")
	}
	if *noAutoExpose {
		_ = os.Setenv(runNoAutoExposeEnv, "1")
	}
	autoExpose := os.Getenv(runNoAutoExposeEnv) != "1"

	checkUserNS()

	dir := defaultClawpatrolDir()
	applyEnvPushdown(dir)

	gwURL := strings.TrimSpace(readFileSilent(filepath.Join(dir, "gateway")))
	gwHost := strings.TrimSpace(readFileSilent(filepath.Join(dir, "tailnet-gateway")))
	controlURL := strings.TrimSpace(readFileSilent(filepath.Join(dir, "control-url")))
	token := strings.TrimSpace(readFileSilent(filepath.Join(dir, "api-token")))
	if gwHost == "" {
		gwHost = "clawpatrol-gateway"
	}
	if gwURL == "" || token == "" {
		fail("tsnet run: missing gateway url or api-token in %s", dir)
	}

	// 1. Mint ephemeral tsnet auth key.
	authKey, gwPort, err := fetchEphemeralTsnetKey(gwURL, token, filepath.Join(dir, "ca.crt"))
	if err != nil {
		fail("mint tsnet key: %v", err)
	}

	// 2. Spin up ephemeral tsnet.Server.
	stateDir, err := os.MkdirTemp("", "clawpatrol-tsnet-*")
	if err != nil {
		fail("tsnet state dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(stateDir) }()

	tsServer := &tsnet.Server{
		Hostname:   fmt.Sprintf("clawpatrol-run-%d", os.Getpid()),
		AuthKey:    authKey,
		ControlURL: controlURL,
		Dir:        stateDir,
		Ephemeral:  true,
		Logf:       func(string, ...any) {},
	}
	defer func() { _ = tsServer.Close() }()

	// Wait for tsnet Running — get our 100.x.x.x address.
	fmt.Fprintln(os.Stderr, "clawpatrol: joining tailnet...")
	tsIP, err := waitTsnetUp(tsServer)
	if err != nil {
		fail("tsnet join: %v", err)
	}
	_ = os.Setenv("CLAWPATROL_TS_ADDR", tsIP.String())

	// Register ephemeral tsnet IP with gateway so profile dispatch uses
	// the right credentials (same as ephemeral WG peer registration).
	if rerr := registerEphemeralTsnetIP(gwURL, token, filepath.Join(dir, "ca.crt"), tsIP.String()); rerr != nil {
		fmt.Fprintf(os.Stderr, "warning: tsnet profile registration: %v (will use default profile)\n", rerr)
	}

	// 3. IPC channels: TUN fd handoff + wg-up pipe (same plumbing as WG mode).
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fail("socketpair: %v", err)
	}
	pSock := os.NewFile(uintptr(sp[0]), "parent-sock")
	cSock := os.NewFile(uintptr(sp[1]), "child-sock")
	defer func() { _ = pSock.Close() }()
	wgUpR, wgUpW, err := os.Pipe()
	if err != nil {
		fail("pipe: %v", err)
	}

	// 4. Spawn child in new user+net+mnt namespace.
	self, err := os.Executable()
	if err != nil {
		fail("self path: %v", err)
	}
	child := exec.Command(self, append([]string{"run"}, cmd...)...)
	child.Env = append(os.Environ(), runTsnetChildEnv+"=1")
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{cSock, wgUpR}
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		AmbientCaps:                []uintptr{capNetAdmin, capSysAdmin},
	}
	if err := child.Start(); err != nil {
		if os.Geteuid() == 0 {
			fail("clone: %v\n  hint: run as your normal user", err)
		}
		fail("clone: %v\n  hint: this distro may have unprivileged user namespaces disabled.\n  enable: sudo sysctl -w kernel.unprivileged_userns_clone=1", err)
	}
	_ = cSock.Close()
	_ = wgUpR.Close()

	// 5. Receive TUN fd from child.
	tunFd, err := recvFD(pSock)
	if err != nil {
		_ = child.Process.Kill()
		fail("recv tun fd: %v", err)
	}
	tunFile := os.NewFile(uintptr(tunFd), tunIfName)

	// 6. Build gVisor stack on the TUN fd.
	gvStack, gvEp, err := newTsnetRunStack(tsIP)
	if err != nil {
		_ = child.Process.Kill()
		fail("gvisor stack: %v", err)
	}
	defer gvStack.Close()
	startTunBridge(tunFile, gvEp, tsServer)

	// 7. TCP forwarder: every connection → tsnet → gateway.
	// We forward to gwHost:originalPort so the gateway can route by port
	// (port 443 → HTTPS MITM; other ports forwarded if gateway listens).
	enableTsnetTCPForwarder(gvStack, tsServer, gwHost, gwPort)

	// 8. Signal child: bridge is up.
	_, _ = wgUpW.Write([]byte{1})
	_ = wgUpW.Close()

	// 9. Auto-expose relay (same as WG mode).
	var relaySup *exec.Cmd
	if autoExpose {
		if relayFDs, err := recvFDs(pSock, 2); err == nil {
			notifyFile := os.NewFile(uintptr(relayFDs[0]), "seccomp-notify")
			supSock := os.NewFile(uintptr(relayFDs[1]), "relay-sup-sock")
			if c, serr := spawnRelaySupervisor(notifyFile, supSock); serr != nil {
				fmt.Fprintf(os.Stderr, "warning: auto-expose relay: %v (webhooks won't be reachable from host)\n", serr)
			} else {
				relaySup = c
			}
			_ = notifyFile.Close()
			_ = supSock.Close()
		} else {
			fmt.Fprintf(os.Stderr, "warning: auto-expose relay: no fds from child: %v\n", err)
		}
	}

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigCh {
			_ = child.Process.Signal(s)
		}
	}()

	waitErr := child.Wait()

	if relaySup != nil && relaySup.Process != nil {
		_ = relaySup.Process.Signal(syscall.SIGTERM)
		_, _ = relaySup.Process.Wait()
	}

	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			os.Exit(ee.ExitCode())
		}
		fail("wait: %v", waitErr)
	}
}

// runRunTsnetChild runs inside the new user+net+mnt namespace.
// Receives TUN fd on fd 3, wg-up pipe on fd 4.
// Sets up TUN with the tsnet 100.x.x.x IP and default route.
func runRunTsnetChild() {
	cSock := os.NewFile(3, "parent-sock")
	wgUpR := os.NewFile(4, "wg-up")

	argv := os.Args[2:]
	if len(argv) == 0 {
		fail("internal: tsnet child got empty argv")
	}

	tunFd, err := openTUN(tunIfName)
	if err != nil {
		fail("open tun: %v", err)
	}
	if err := sendFD(cSock, tunFd); err != nil {
		fail("send tun fd: %v", err)
	}
	_ = unix.Close(tunFd)

	one := make([]byte, 1)
	if _, err := io.ReadFull(wgUpR, one); err != nil {
		fail("wait wg-up: %v", err)
	}
	_ = wgUpR.Close()

	tsAddr := os.Getenv("CLAWPATROL_TS_ADDR")
	if tsAddr == "" {
		fail("CLAWPATROL_TS_ADDR not set")
	}

	steps := [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "set", tunIfName, "mtu", fmt.Sprintf("%d", tunMTU), "up"},
		{"ip", "addr", "add", tsAddr + "/32", "dev", tunIfName},
		{"ip", "route", "add", "default", "dev", tunIfName},
	}
	for _, a := range steps {
		c := exec.Command(a[0], a[1:]...)
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			fail("%s: %v", strings.Join(a, " "), err)
		}
	}

	if os.Getenv("CLAWPATROL_RUN_KEEP_RESOLV") != "1" {
		_ = bindResolv("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
	}

	autoExpose := os.Getenv(runNoAutoExposeEnv) != "1"
	if autoExpose {
		setupRelayInChild(cSock)
	}
	_ = cSock.Close()

	if autoExpose {
		_, _, _ = unix.RawSyscall6(unix.SYS_PRCTL,
			unix.PR_SET_PTRACER, ptraceAny, 0, 0, 0, 0)
	}

	if err := clearAmbientCaps(); err != nil {
		fail("clear ambient caps: %v", err)
	}

	bin, err := exec.LookPath(argv[0])
	if err != nil {
		fail("lookpath %s: %v", argv[0], err)
	}
	if err := syscall.Exec(bin, argv, os.Environ()); err != nil {
		fail("exec %s: %v", bin, err)
	}
}

// --- gVisor stack + TUN bridge ------------------------------------------

// newTsnetRunStack creates a gVisor TCP/IP stack bound to localIP.
// Promiscuous + spoofing enabled so it accepts connections destined
// to any IP from the child netns.
func newTsnetRunStack(localIP netip.Addr) (*stack.Stack, *channel.Endpoint, error) {
	ep := channel.New(netstackQueueSize, uint32(tunMTU), "")
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
		},
		HandleLocal: false,
	})
	sackOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)
	rackOpt := tcpip.TCPRecovery(0)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rackOpt)
	ccOpt := tcpip.CongestionControlOption("reno")
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)
	minRTOOpt := tcpip.TCPMinRTOOption(time.Second)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &minRTOOpt)
	rxBuf := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rxBuf)
	txBuf := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 6 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &txBuf)

	if e := s.CreateNIC(1, ep); e != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", e)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(localIP.AsSlice()).WithPrefix(),
	}
	if e := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); e != nil {
		return nil, nil, fmt.Errorf("AddProtocolAddress: %v", e)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	if e := s.SetPromiscuousMode(1, true); e != nil {
		return nil, nil, fmt.Errorf("SetPromiscuousMode: %v", e)
	}
	if e := s.SetSpoofing(1, true); e != nil {
		return nil, nil, fmt.Errorf("SetSpoofing: %v", e)
	}
	return s, ep, nil
}

// tsnetTunBridge pumps packets between the raw TUN fd and gVisor's
// channel endpoint. Implements channel.Notification for the outbound
// (gVisor→TUN) direction.
type tsnetTunBridge struct {
	tunFile *os.File
	ep      *channel.Endpoint
}

// WriteNotify is called by gVisor when outbound packets are ready.
// Drains ep and writes raw IP packets to the TUN fd.
func (b *tsnetTunBridge) WriteNotify() {
	for {
		pkt := b.ep.Read()
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		_, _ = b.tunFile.Write(view.AsSlice())
	}
}

// startTunBridge registers the outbound notification and starts the
// inbound read loop (TUN fd → gVisor InjectInbound).
// IPv4 UDP packets are intercepted before gVisor injection and forwarded
// directly via tsnet so the child has functional UDP without an exit node.
func startTunBridge(tunFile *os.File, ep *channel.Endpoint, ts *tsnet.Server) {
	br := &tsnetTunBridge{tunFile: tunFile, ep: ep}
	ep.AddNotify(br)
	uf := &udpForwarder{ts: ts, tunFile: tunFile, flows: map[udpFlowKey]net.Conn{}}

	go func() {
		buf := make([]byte, tunMTU)
		for {
			n, err := tunFile.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			// Intercept IPv4 UDP before injecting into gVisor TCP stack.
			if pkt[0]>>4 == 4 && n > 20 && pkt[9] == 17 {
				uf.handle(pkt)
				continue
			}
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			switch pkt[0] >> 4 {
			case 4:
				ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
			case 6:
				ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
			default:
				pkb.DecRef()
			}
		}
	}()
}

// udpForwarder maintains per-flow tsnet UDP connections for the child netns.
// Each unique (srcIP:srcPort → dstIP:dstPort) 4-tuple gets one tsnet UDP conn.
type udpForwarder struct {
	ts      *tsnet.Server
	tunFile *os.File
	mu      sync.Mutex
	flows   map[udpFlowKey]net.Conn
}

type udpFlowKey struct {
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
}

func (f *udpForwarder) handle(pkt []byte) {
	ihl := int(pkt[0]&0xf) * 4
	if len(pkt) < ihl+8 {
		return
	}
	var srcIP, dstIP [4]byte
	copy(srcIP[:], pkt[12:16])
	copy(dstIP[:], pkt[16:20])
	srcPort := uint16(pkt[ihl])<<8 | uint16(pkt[ihl+1])
	dstPort := uint16(pkt[ihl+2])<<8 | uint16(pkt[ihl+3])
	udpLen := int(pkt[ihl+4])<<8 | int(pkt[ihl+5])
	if udpLen < 8 || ihl+udpLen > len(pkt) {
		return
	}
	payload := pkt[ihl+8 : ihl+udpLen]

	key := udpFlowKey{srcIP, dstIP, srcPort, dstPort}

	f.mu.Lock()
	conn, ok := f.flows[key]
	if !ok {
		dstAddr := fmt.Sprintf("%d.%d.%d.%d:%d",
			dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort)
		var err error
		conn, err = f.ts.Dial(context.Background(), "udp", dstAddr)
		if err != nil {
			f.mu.Unlock()
			return
		}
		f.flows[key] = conn
		go func() {
			f.readResponses(conn, dstIP, srcIP, dstPort, srcPort)
			f.mu.Lock()
			delete(f.flows, key)
			f.mu.Unlock()
			_ = conn.Close()
		}()
	}
	f.mu.Unlock()

	_, _ = conn.Write(payload)
}

func (f *udpForwarder) readResponses(conn net.Conn, srcIP, dstIP [4]byte, srcPort, dstPort uint16) {
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = f.tunFile.Write(buildUDPPacket(srcIP, dstIP, srcPort, dstPort, buf[:n]))
	}
}

// buildUDPPacket constructs a raw IPv4+UDP packet. UDP checksum is zero
// (optional for IPv4; Linux accepts these from TUN devices).
func buildUDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen
	pkt := make([]byte, ipLen)
	pkt[0] = 0x45 // IPv4, IHL=5
	pkt[2] = byte(ipLen >> 8)
	pkt[3] = byte(ipLen)
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	cs := ipv4Checksum(pkt[:20])
	pkt[10] = byte(cs >> 8)
	pkt[11] = byte(cs)
	pkt[20] = byte(srcPort >> 8)
	pkt[21] = byte(srcPort)
	pkt[22] = byte(dstPort >> 8)
	pkt[23] = byte(dstPort)
	pkt[24] = byte(udpLen >> 8)
	pkt[25] = byte(udpLen)
	// pkt[26:28] = 0 (checksum omitted)
	copy(pkt[28:], payload)
	return pkt
}

func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// enableTsnetTCPForwarder installs a promiscuous TCP forwarder on s.
// Every connection is forwarded to gwHost:gwPort via tsnet. A HAProxy PROXY v1
// header is written before the payload carrying the original 4-tuple so the
// gateway can dispatch by original dst IP/port (PostgreSQL, ClickHouse, etc.)
// instead of only being able to route by SNI on port 443.
func enableTsnetTCPForwarder(s *stack.Stack, ts *tsnet.Server, gwHost, gwPort string) {
	gwAddr := net.JoinHostPort(gwHost, gwPort)
	fwd := tcp.NewForwarder(s, 1<<20, 16384, func(req *tcp.ForwarderRequest) {
		id := req.ID()
		// PROXY TCP4 srcIP dstIP srcPort dstPort
		proxyHdr := fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n",
			id.RemoteAddress, id.LocalAddress, id.RemotePort, id.LocalPort)

		var wq waiter.Queue
		ep, err := req.CreateEndpoint(&wq)
		if err != nil {
			req.Complete(true)
			return
		}
		req.Complete(false)
		local := gonet.NewTCPConn(&wq, ep)
		go func() {
			defer func() { _ = local.Close() }()
			ctx := context.Background()
			remote, err := ts.Dial(ctx, "tcp", gwAddr)
			if err != nil {
				return
			}
			defer func() { _ = remote.Close() }()
			if _, err := io.WriteString(remote, proxyHdr); err != nil {
				return
			}
			tsnetBiRelay(local, remote)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}
