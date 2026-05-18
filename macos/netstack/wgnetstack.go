// Package main builds libwgnetstack.a — a userspace WireGuard tunnel
// + gVisor netstack exposed via cgo for the macOS NETransparentProxy
// extension (see ../ClawpatrolExtension/Provider.swift).
//
// Same pattern the gateway uses (../wireguard.go): wireguard-go
// device + a netTun backed by a gVisor stack + channel.Endpoint.
// Difference is direction — gateway is the WG server, this is the WG
// client. Each dial_tcp / dial_udp call returns one end of a unix
// socketpair, with a pumping goroutine bridging the gVisor connection
// to that fd. The Swift caller reads/writes the fd as if it were a
// normal socket; bytes flow through wireguard-go to the gateway and
// back.
//
// Why not noisysockets / netstack-smoltcp:
//   - We already vendor wireguard-go + gvisor for the gateway. Same
//     code on both sides keeps the dependency surface small.
//   - We need a C ABI for cgo, which the Go libs above don't expose.
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"tailscale.com/tsnet"

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
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// netTun: copy of gateway's netTun, client-side. wireguard-go reads
// outbound IP packets from Read (we feed it via incomingPacket) and
// writes inbound IP packets to Write (we inject into the gVisor
// stack). HandleLocal=false matches the gateway choice.
type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan wgtun.Event
	incomingPacket chan []byte
	mtu            int
	closed         bool
}

type epNotify struct{ dev *netTun }

func (n *epNotify) WriteNotify() {
	for {
		pkt := n.dev.ep.Read()
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		pkt.DecRef()
		b := v.AsSlice()
		cp := make([]byte, len(b))
		copy(cp, b)
		select {
		case n.dev.incomingPacket <- cp:
		default:
		}
	}
}

// netstackQueueSize matches the gateway side. 1024 was tight under
// whole-machine bursts; 16384 absorbs realistic spikes.
const netstackQueueSize = 16384

// wgTunMTU matches wireguard.go's constant. 1220 fits Tailscale's
// 1280-byte underlay without IP fragmentation. v6 unavailable inside
// the tunnel; see the comment over there.
const wgTunMTU = 1220

func newNetTUN(addr netip.Addr, addr6 netip.Addr, mtu int) (*netTun, error) {
	t := &netTun{
		ep: channel.New(netstackQueueSize, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol, ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol, udp.NewProtocol,
				icmp.NewProtocol4, icmp.NewProtocol6,
			},
			HandleLocal: false,
		}),
		events:         make(chan wgtun.Event, 10),
		incomingPacket: make(chan []byte, netstackQueueSize),
		mtu:            mtu,
	}
	t.ep.AddNotify(&epNotify{dev: t})
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
	t.events <- wgtun.EventUp
	return t, nil
}

func (t *netTun) File() *os.File             { return nil }
func (t *netTun) Name() (string, error)      { return "clawpatrol-wg", nil }
func (t *netTun) MTU() (int, error)          { return t.mtu, nil }
func (t *netTun) Events() <-chan wgtun.Event { return t.events }
func (t *netTun) BatchSize() int             { return tunBatchSize }

const tunBatchSize = 128

func (t *netTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
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

func (t *netTun) Write(bufs [][]byte, offset int) (int, error) {
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

func (t *netTun) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	t.stack.RemoveNIC(1)
	t.stack.Close()
	close(t.events)
	close(t.incomingPacket)
	return nil
}

// Single global tunnel. Only one client tunnel makes sense per
// extension instance.
var (
	tun     *netTun
	dev     *device.Device
	mu      sync.Mutex
	started bool
)

// init parses a wg-quick string into the (PrivateKey, Address,
// PeerPublicKey, Endpoint, optional PersistentKeepalive) tuple our
// device.IpcSet expects in `WireGuard config format`.
func parseWG(conf string) (priv, addr, peerPub, ep string, ka int, err error) {
	section := ""
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		switch section + "/" + k {
		case "interface/PrivateKey":
			priv = v
		case "interface/Address":
			addr = v
		case "peer/PublicKey":
			peerPub = v
		case "peer/Endpoint":
			ep = v
		case "peer/PersistentKeepalive":
			ka, _ = strconv.Atoi(v)
		}
	}
	if priv == "" || addr == "" || peerPub == "" || ep == "" {
		err = errors.New("wg-conf missing required field (PrivateKey/Address/PublicKey/Endpoint)")
	}
	return
}

// b64ToHex: wg-quick uses base64 for keys; wireguard-go's IpcSet
// wants hex. Decode + re-encode.
func b64ToHex(b64 string) (string, error) {
	dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, len(dec)*2)
	for i, v := range dec {
		out[i*2] = hexd[v>>4]
		out[i*2+1] = hexd[v&0xf]
	}
	return string(out), nil
}

//export wg_netstack_init
func wg_netstack_init(confC *C.char, errBuf *C.char, errLen C.int) C.int {
	mu.Lock()
	defer mu.Unlock()
	if started {
		return 0
	}
	// Raise the per-process file-descriptor limit. Each flow opens a
	// unix socketpair (2 fds); macOS extensions default to
	// RLIMIT_NOFILE = 256. Whole-machine traffic blows past that
	// almost immediately — socketpair() returns EMFILE, the swift
	// pumpTCP drops the flow, the mac kernel retransmits, and the
	// browser sees long stalls with no useful error. Bump to the
	// hard limit (typically 524288 on macOS 14).
	raiseFDLimit()
	conf := C.GoString(confC)
	priv, addr, peerPub, ep, ka, perr := parseWG(conf)
	if perr != nil {
		setErr(errBuf, errLen, perr.Error())
		return -1
	}
	// Address may carry both v4 and v6 separated by ", ". Each part is
	// `addr/prefix`. wg-quick conf written by the gateway emits e.g.
	// `Address = 10.55.0.10/32, fd77::a/128`.
	var clientIP, clientIP6 netip.Addr
	for _, part := range strings.Split(addr, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
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
		setErr(errBuf, errLen, "parse client IP: no IPv4 in Address")
		return -1
	}
	t, err := newNetTUN(clientIP, clientIP6, wgTunMTU)
	if err != nil {
		setErr(errBuf, errLen, "newNetTUN: "+err.Error())
		return -1
	}
	d := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg "))

	privHex, err := b64ToHex(priv)
	if err != nil {
		setErr(errBuf, errLen, "decode privkey: "+err.Error())
		return -1
	}
	pubHex, err := b64ToHex(peerPub)
	if err != nil {
		setErr(errBuf, errLen, "decode peer pub: "+err.Error())
		return -1
	}
	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		privHex, pubHex, ep,
	)
	// Force keepalive on. wireguard-go does not initiate a handshake
	// until outbound traffic appears or keepalive timer fires. Without
	// this the first user flow's SYN triggers handshake, but the SYN
	// itself is queued behind the handshake and the TCP retransmit
	// timer (3s, then 6s, ...) ends up gating the visible latency.
	// Forcing keepalive=10s drives handshake-on-startup, so by the time
	// startProxy returns the tunnel is already up.
	if ka <= 0 {
		ka = 10
	}
	ipc += fmt.Sprintf("persistent_keepalive_interval=%d\n", ka)
	if err := d.IpcSet(ipc); err != nil {
		setErr(errBuf, errLen, "IpcSet: "+err.Error())
		return -1
	}
	if err := d.Up(); err != nil {
		setErr(errBuf, errLen, "device.Up: "+err.Error())
		return -1
	}
	tun = t
	dev = d
	started = true
	return 0
}

// wg_netstack_wait_handshake blocks until the peer completes a
// WireGuard handshake or `timeoutMs` elapses. Returns 0 on success,
// -1 on timeout. Polls device.IpcGet for `last_handshake_time_sec`
// (wireguard-go writes it on handshake completion).
//
// Caller must invoke this AFTER wg_netstack_init returns success and
// BEFORE driving any TCP/UDP flows; otherwise the first user flow
// races the handshake and TCP retransmit timers (3s, 6s...) gate the
// visible latency.
//
//export wg_netstack_wait_handshake
func wg_netstack_wait_handshake(timeoutMs C.int) C.int {
	mu.Lock()
	d := dev
	mu.Unlock()
	if d == nil {
		return -1
	}
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	for {
		if cfg, err := d.IpcGet(); err == nil {
			for _, line := range strings.Split(cfg, "\n") {
				if strings.HasPrefix(line, "last_handshake_time_sec=") {
					sec, _ := strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
					if sec > 0 {
						return 0
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return -1
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// wg_netstack_resolve runs A-record lookup through the netstack so
// names that appear directly in NEAppProxyFlow.remoteEndpoint (rare —
// macOS usually resolves before opening the flow) get answered via
// the tunnel rather than the host's system resolver. Uses Go's
// net.Resolver bound to the netstack via gonet.
//
//export wg_netstack_resolve
func wg_netstack_resolve(hostC *C.char, outBuf *C.char, outLen C.int) C.int {
	if !started {
		setErr(outBuf, outLen, "wg_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	// Cheap path — already an IP literal.
	if _, err := netip.ParseAddr(host); err == nil {
		setErr(outBuf, outLen, host)
		return 0
	}
	// Use a custom resolver whose Dial routes through the netstack.
	// Hardcoded 1.1.1.1:53; we could read DNS from the wg-conf later.
	r := &netResolver{}
	ip, err := r.lookup(host)
	if err != nil {
		setErr(outBuf, outLen, "lookup: "+err.Error())
		return -1
	}
	setErr(outBuf, outLen, ip)
	return 0
}

type netResolver struct{}

func (n *netResolver) lookup(host string) (string, error) {
	// Always dial 1.1.1.1:53 over the netstack regardless of which DNS
	// server net.Resolver would pick from the host. resolv.conf isn't
	// useful inside the sandboxed extension.
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr := tcpip.FullAddress{
				NIC:  1,
				Addr: tcpip.AddrFromSlice([]byte{1, 1, 1, 1}),
				Port: 53,
			}
			if strings.HasPrefix(network, "udp") {
				return gonet.DialUDP(tun.stack, nil, &addr, ipv4.ProtocolNumber)
			}
			return gonet.DialContextTCP(ctx, tun.stack, addr, ipv4.ProtocolNumber)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no IPv4 for %s", host)
}

//export wg_netstack_close
func wg_netstack_close() {
	mu.Lock()
	defer mu.Unlock()
	if dev != nil {
		dev.Close()
		dev = nil
	}
	if tun != nil {
		tun.Close()
		tun = nil
	}
	started = false
}

// Connection-handle API. Mirrors unclaw's NE design: instead of
// opening a unix socketpair per flow (2 fds → RLIMIT_NOFILE pressure
// + per-flow goroutines + kernel buffer copies), we expose a small
// integer connection ID. Swift drives an event loop calling
// _send/_recv/_close; Go side just stores the gVisor conn keyed by
// the ID. Zero kernel fds per flow, one goroutine when blocked on
// recv (still cheap — Go schedules onto a worker thread).
//
// Trade-off: _send and _recv are blocking. Swift must call them on
// background dispatch queues so the main pump doesn't stall. The
// extension's bridgeTCP / bridgeUDP own that pattern.

type connHandle struct {
	conn io.ReadWriteCloser
}

var (
	conns      sync.Map // int64 → *connHandle
	nextConnID atomic.Int64
)

// wg_netstack_tcp_connect dials host:port through the wg netstack and
// returns a positive connection ID on success, -1 on failure (with
// errBuf populated). The returned ID is opaque to Swift — pass back
// to _send/_recv/_close. Host must be an IP literal; DNS happens at
// the wg_netstack_resolve layer above.
//
// timeoutMs is the dial deadline in milliseconds. <=0 means no timeout
// (context.Background). Callers should always pass a finite timeout:
// if the WireGuard peer is unreachable (post-sleep, captive portal),
// DialContextTCP blocks indefinitely under context.Background while
// wireguard-go queues the TCP SYN waiting for a handshake that never
// completes — stalling whole-machine TCP flows until the user disables
// the extension.
//
//export wg_netstack_tcp_connect
func wg_netstack_tcp_connect(hostC *C.char, port C.int, timeoutMs C.int, errBuf *C.char, errLen C.int) C.int64_t {
	if !started {
		setErr(errBuf, errLen, "wg_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		setErr(errBuf, errLen, "parse host: "+err.Error())
		return -1
	}
	proto := ipv4.ProtocolNumber
	if ip.Is6() {
		proto = ipv6.ProtocolNumber
	}
	addr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(port),
	}
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutMs > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
	}
	gconn, err := gonet.DialContextTCP(ctx, tun.stack, addr, proto)
	if err != nil {
		setErr(errBuf, errLen, "DialContextTCP: "+err.Error())
		return -1
	}
	id := nextConnID.Add(1)
	conns.Store(id, &connHandle{conn: gconn})
	return C.int64_t(id)
}

// wg_netstack_udp_connect dials a UDP "connection" (gVisor UDPConn —
// fixed remote, datagram semantics). Returns positive ID on success.
//
//export wg_netstack_udp_connect
func wg_netstack_udp_connect(hostC *C.char, port C.int, errBuf *C.char, errLen C.int) C.int64_t {
	if !started {
		setErr(errBuf, errLen, "wg_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		setErr(errBuf, errLen, "parse host: "+err.Error())
		return -1
	}
	proto := ipv4.ProtocolNumber
	if ip.Is6() {
		proto = ipv6.ProtocolNumber
	}
	addr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(port),
	}
	gconn, err := gonet.DialUDP(tun.stack, nil, &addr, proto)
	if err != nil {
		setErr(errBuf, errLen, "DialUDP: "+err.Error())
		return -1
	}
	id := nextConnID.Add(1)
	conns.Store(id, &connHandle{conn: gconn})
	return C.int64_t(id)
}

// wg_netstack_send writes up to n bytes from buf to the conn. Blocks
// until the gVisor stack accepts the bytes (TCP window fills slow
// receiver). Returns bytes written or -1 on error.
//
//export wg_netstack_send
func wg_netstack_send(id C.int64_t, buf *C.char, n C.int) C.int {
	v, ok := conns.Load(int64(id))
	if !ok {
		return -1
	}
	h := v.(*connHandle)
	if n <= 0 {
		return 0
	}
	p := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))
	written, err := h.conn.Write(p)
	if err != nil {
		return -1
	}
	return C.int(written)
}

// wg_netstack_recv reads up to n bytes from the conn into buf. Blocks
// until at least one byte is available or the conn closes. Returns
// the byte count, 0 on EOF, or -1 on error.
//
//export wg_netstack_recv
func wg_netstack_recv(id C.int64_t, buf *C.char, n C.int) C.int {
	v, ok := conns.Load(int64(id))
	if !ok {
		return -1
	}
	h := v.(*connHandle)
	if n <= 0 {
		return 0
	}
	p := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))
	read, err := h.conn.Read(p)
	if err != nil {
		if read == 0 {
			if err == io.EOF {
				return 0
			}
			return -1
		}
		// Short read with error — return what we got; next call
		// surfaces the error.
	}
	return C.int(read)
}

// wg_netstack_close drops the conn and frees its slot. Idempotent.
//
//export wg_netstack_close_conn
func wg_netstack_close_conn(id C.int64_t) {
	if v, ok := conns.LoadAndDelete(int64(id)); ok {
		_ = v.(*connHandle).conn.Close()
	}
}

// _unusedSocketpair keeps these imports referenced so the cgo
// archive still resolves syscall + os without the legacy spliceFD
// path; the helpers below are the older, deprecated dial_tcp/
// dial_udp + spliceFD that the new connection-handle API replaces.
//
// dial_tcp / dial_udp / spliceFD remain exported temporarily for
// any caller still using the fd-pair flow; once macos/Provider.swift
// is fully on the connect/send/recv API we can drop them.
//
// dial_tcp opens a TCP connection to host:port via the netstack and
// returns one end of a unix socketpair. Deprecated — use
// wg_netstack_tcp_connect.
//
//export wg_netstack_dial_tcp
func wg_netstack_dial_tcp(hostC *C.char, port C.int, errBuf *C.char, errLen C.int) C.int {
	if !started {
		setErr(errBuf, errLen, "wg_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		setErr(errBuf, errLen, "parse host: "+err.Error())
		return -1
	}
	proto := ipv4.ProtocolNumber
	if ip.Is6() {
		proto = ipv6.ProtocolNumber
	}
	addr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(port),
	}
	gconn, err := gonet.DialContextTCP(context.Background(), tun.stack, addr, proto)
	if err != nil {
		setErr(errBuf, errLen, "DialContextTCP: "+err.Error())
		return -1
	}
	return spliceFD(gconn)
}

//export wg_netstack_dial_udp
func wg_netstack_dial_udp(hostC *C.char, port C.int, errBuf *C.char, errLen C.int) C.int {
	if !started {
		setErr(errBuf, errLen, "wg_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		setErr(errBuf, errLen, "parse host: "+err.Error())
		return -1
	}
	proto := ipv4.ProtocolNumber
	if ip.Is6() {
		proto = ipv6.ProtocolNumber
	}
	addr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(port),
	}
	gconn, err := gonet.DialUDP(tun.stack, nil, &addr, proto)
	if err != nil {
		setErr(errBuf, errLen, "DialUDP: "+err.Error())
		return -1
	}
	return spliceFD(gconn)
}

func spliceFD(gconn io.ReadWriteCloser) C.int {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1
	}
	swiftFD, goFD := pair[0], pair[1]
	const bufSize = 1 << 20 // 1 MiB
	for _, fd := range pair {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, bufSize)
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, bufSize)
	}
	goFile := os.NewFile(uintptr(goFD), "wgsplice")
	if goFile == nil {
		syscall.Close(swiftFD)
		syscall.Close(goFD)
		return -1
	}
	go func() {
		defer goFile.Close()
		defer gconn.Close()
		_, _ = io.Copy(gconn, goFile) // swift -> netstack
	}()
	go func() {
		defer goFile.Close()
		defer gconn.Close()
		_, _ = io.Copy(goFile, gconn) // netstack -> swift
	}()
	return C.int(swiftFD)
}

func setErr(buf *C.char, n C.int, msg string) {
	if buf == nil || n <= 0 {
		return
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))
	limit := len(dst) - 1
	if limit < 0 {
		return
	}
	if len(msg) > limit {
		msg = msg[:limit]
	}
	copy(dst, msg)
	dst[len(msg)] = 0
}

// raiseFDLimit lifts RLIMIT_NOFILE to the hard cap. Idempotent;
// failures (sandbox refuses) just log without aborting init.
func raiseFDLimit() {
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return
	}
	old := rlim.Cur
	rlim.Cur = rlim.Max
	if rlim.Cur > 1<<20 {
		rlim.Cur = 1 << 20
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim); err == nil {
		_ = old
	}
}

// --- tsnet (Tailscale mode) ----------------------------------------------
//
// ts_netstack_init / ts_netstack_tcp_connect / ts_netstack_resolve /
// ts_netstack_close mirror the wg_netstack_* surface but use a
// tsnet.Server as the transport instead of WireGuard + gVisor.
//
// Flow:
//   Provider.swift (tsnet mode)
//     bridgeTCP flow → ts_netstack_tcp_connect(ip, port)
//       → tsServer.Dial(gwAddr)
//       → write HAProxy PROXY v1 header with original dstIP:dstPort
//       → gateway dispatches to target
//
// The PROXY header carries (tsNodeIP, dstIP, 0, dstPort); srcPort is
// 0 because the NE intercept layer doesn't expose the original local
// port. Gateway routing uses dstIP:dstPort only.

var (
	tsServer  *tsnet.Server
	tsGwAddr  string
	tsNodeIP  string
	tsMu      sync.Mutex
	tsStarted bool
)

// ts_netstack_init joins the tailnet with the given ephemeral auth key
// and records the gateway address for ts_netstack_tcp_connect. Blocks
// until the tsnet node has a 100.x.x.x address (≤90s). Returns 0 on
// success, -1 on failure.
//
//export ts_netstack_init
func ts_netstack_init(authKeyC, controlURLС, gwHostC, gwPortC, errBuf *C.char, errLen C.int) C.int {
	tsMu.Lock()
	defer tsMu.Unlock()
	if tsStarted {
		return 0
	}
	raiseFDLimit()
	authKey := C.GoString(authKeyC)
	controlURL := C.GoString(controlURLС)
	gwHost := C.GoString(gwHostC)
	gwPort := C.GoString(gwPortC)

	stateDir, err := os.MkdirTemp("", "clawpatrol-tsnet-ne-*")
	if err != nil {
		setErr(errBuf, errLen, "mktemp: "+err.Error())
		return -1
	}

	s := &tsnet.Server{
		Hostname:   fmt.Sprintf("clawpatrol-ne-%d", os.Getpid()),
		AuthKey:    authKey,
		ControlURL: controlURL,
		Dir:        stateDir,
		Ephemeral:  true,
		Logf:       func(string, ...any) {},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	upSt, err := s.Up(ctx)
	if err != nil {
		_ = s.Close()
		_ = os.RemoveAll(stateDir)
		setErr(errBuf, errLen, "tsnet up: "+err.Error())
		return -1
	}

	var ip4 string
	for _, ip := range upSt.Self.TailscaleIPs {
		if ip.Is4() {
			ip4 = ip.String()
			break
		}
	}
	if ip4 == "" && len(upSt.Self.TailscaleIPs) > 0 {
		ip4 = upSt.Self.TailscaleIPs[0].String()
	}

	tsServer = s
	tsGwAddr = net.JoinHostPort(gwHost, gwPort)
	tsNodeIP = ip4
	tsStarted = true
	return 0
}

// ts_netstack_get_ip writes the tsnet node's 100.x.x.x address into
// outBuf. Returns 0 on success, -1 if not initialized.
//
//export ts_netstack_get_ip
func ts_netstack_get_ip(outBuf *C.char, outLen C.int) C.int {
	tsMu.Lock()
	ip := tsNodeIP
	tsMu.Unlock()
	if ip == "" {
		setErr(outBuf, outLen, "not initialized")
		return -1
	}
	setErr(outBuf, outLen, ip)
	return 0
}

// ts_netstack_tcp_connect dials dstHost:dstPort via the gateway over
// tsnet (PROXY v1 header carries the original destination). Returns a
// positive connection ID for use with wg_netstack_send/recv/close_conn.
//
//export ts_netstack_tcp_connect
func ts_netstack_tcp_connect(hostC *C.char, port C.int, timeoutMs C.int, errBuf *C.char, errLen C.int) C.int64_t {
	tsMu.Lock()
	s := tsServer
	gwAddr := tsGwAddr
	srcIP := tsNodeIP
	tsMu.Unlock()
	if s == nil {
		setErr(errBuf, errLen, "ts_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutMs > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
	}
	conn, err := s.Dial(ctx, "tcp", gwAddr)
	if err != nil {
		setErr(errBuf, errLen, "tsnet dial: "+err.Error())
		return -1
	}
	proxyHdr := fmt.Sprintf("PROXY TCP4 %s %s 0 %d\r\n", srcIP, host, int(port))
	if _, err := io.WriteString(conn, proxyHdr); err != nil {
		_ = conn.Close()
		setErr(errBuf, errLen, "proxy hdr: "+err.Error())
		return -1
	}
	id := nextConnID.Add(1)
	conns.Store(id, &connHandle{conn: conn})
	return C.int64_t(id)
}

// ts_netstack_resolve resolves host using the system resolver (not the
// tunnel — in tsnet mode the host has direct internet access for DNS).
//
//export ts_netstack_resolve
func ts_netstack_resolve(hostC *C.char, outBuf *C.char, outLen C.int) C.int {
	host := C.GoString(hostC)
	if _, err := netip.ParseAddr(host); err == nil {
		setErr(outBuf, outLen, host)
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		setErr(outBuf, outLen, "lookup: "+err.Error())
		return -1
	}
	for _, a := range addrs {
		if ip, perr := netip.ParseAddr(a); perr == nil && ip.Is4() {
			setErr(outBuf, outLen, a)
			return 0
		}
	}
	setErr(outBuf, outLen, "no IPv4 for "+host)
	return -1
}

// ts_netstack_udp_connect dials dstHost:dstPort for UDP directly via tsnet.
// tsnet supports UDP natively (Dial "udp"), so no framing or TCP relay needed.
// The returned conn ID works with wg_netstack_send/recv/close_conn identically
// to WireGuard UDP: each send/recv is one datagram.
//
//export ts_netstack_udp_connect
func ts_netstack_udp_connect(hostC *C.char, port C.int, errBuf *C.char, errLen C.int) C.int64_t {
	tsMu.Lock()
	s := tsServer
	tsMu.Unlock()
	if s == nil {
		setErr(errBuf, errLen, "ts_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	addr := fmt.Sprintf("%s:%d", host, int(port))
	conn, err := s.Dial(context.Background(), "udp", addr)
	if err != nil {
		setErr(errBuf, errLen, "tsnet udp dial: "+err.Error())
		return -1
	}
	id := nextConnID.Add(1)
	conns.Store(id, &connHandle{conn: conn})
	return C.int64_t(id)
}

// ts_netstack_close shuts down the tsnet server.
//
//export ts_netstack_close
func ts_netstack_close() {
	tsMu.Lock()
	defer tsMu.Unlock()
	if tsServer != nil {
		_ = tsServer.Close()
		tsServer = nil
	}
	tsStarted = false
	tsGwAddr = ""
	tsNodeIP = ""
}

func main() {} // required for c-archive build mode
