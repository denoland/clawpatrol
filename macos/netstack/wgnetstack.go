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
	"syscall"
	"time"
	"unsafe"

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

func newNetTUN(addr netip.Addr, addr6 netip.Addr, mtu int) (*netTun, error) {
	t := &netTun{
		ep: channel.New(1024, uint32(mtu), ""),
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
		incomingPacket: make(chan []byte, 1024),
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
func (t *netTun) BatchSize() int             { return 1 }

func (t *netTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-t.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n := copy(bufs[0][offset:], pkt)
	sizes[0] = n
	return 1, nil
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
	t, err := newNetTUN(clientIP, clientIP6, 1420)
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
	if ka > 0 {
		ipc += fmt.Sprintf("persistent_keepalive_interval=%d\n", ka)
	}
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

// dial_tcp opens a TCP connection to host:port via the netstack and
// returns one end of a unix socketpair. A goroutine pumps bytes
// between the gVisor conn and the fd. Caller closes the fd to tear
// down. host can be IPv4 dotted-quad — DNS handled at higher level.
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

// spliceFD: socketpair() + io.Copy in both directions.
//
// Returns the "Swift end" fd; the "Go end" fd is wrapped in os.NewFile
// and stays alive until both sides close. Uses SOCK_STREAM; UDP
// callers run datagrams over a stream pair (good enough — extension
// only sends complete datagrams at a time). Both ends close on
// pump exit.
func spliceFD(gconn io.ReadWriteCloser) C.int {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1
	}
	swiftFD, goFD := pair[0], pair[1]
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

func main() {} // required for c-archive build mode
