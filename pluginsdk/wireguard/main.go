// Standalone clawpatrol tunnel plugin: route upstream connections through
// a WireGuard tunnel. Spike — a UDP-transport plugin tunnel that supports
// `via` chaining (e.g. `via = socks`, so the WireGuard handshake's UDP
// rides over a SOCKS5 UDP relay).
//
// The plugin runs with NO network of its own (network = "none"): it opens
// its WireGuard transport through the gateway's brokered dial
// (req.DialUpstream("udp", endpoint)), which the gateway routes directly
// or through the parent tunnel. A small wireguard-go conn.Bind sends and
// receives over that brokered datagram conduit instead of a real UDP
// socket; an in-process gVisor netstack carries the tunnelled TCP.
//
// Build: go build -o wireguard-tunnel ./pluginsdk/wireguard
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/denoland/clawpatrol/pluginsdk"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	pluginsdk.Run(&pluginsdk.Plugin{
		Name:    "wireguard_tunnel",
		Version: "0.1",
		// No raw sockets: the transport is opened through the gateway's
		// brokered dial, which the gateway routes (direct or via parent).
		Capabilities: pluginsdk.Capabilities{Network: pluginsdk.NetworkNone},
		Tunnels:      []pluginsdk.TunnelDef{wireguardDef()},
	})
}

type wgConfig struct {
	Endpoint      string `json:"endpoint"`        // host:port of the WG server
	PrivateKey    string `json:"private_key"`     // base64 (wg-quick form)
	PeerPublicKey string `json:"peer_public_key"` // base64
	Address       string `json:"address"`         // this peer's IP in the WG net
	DNS           string `json:"dns"`             // optional in-tunnel resolver
}

type wgHandle struct {
	dev    *device.Device
	tnet   *netstack.Net
	cancel context.CancelFunc // cancels the brokered transport's context on Close
}

func wireguardDef() pluginsdk.TunnelDef {
	return pluginsdk.TunnelDef{
		TypeName: "wireguard",
		Schema: pluginsdk.Schema{Fields: []pluginsdk.SchemaField{
			{Name: "endpoint", TypeString: "string", Required: true},
			{Name: "private_key", TypeString: "string", Required: true},
			{Name: "peer_public_key", TypeString: "string", Required: true},
			{Name: "address", TypeString: "string", Required: true},
			{Name: "dns", TypeString: "string"},
		}},
		Open:  wireguardOpen,
		Dial:  wireguardDial,
		Close: wireguardClose,
	}
}

func wireguardOpen(_ context.Context, req pluginsdk.TunnelOpenRequest) (any, error) {
	var cfg wgConfig
	if len(req.CanonicalConfig) > 0 {
		if err := json.Unmarshal(req.CanonicalConfig, &cfg); err != nil {
			return nil, fmt.Errorf("wireguard config: %w", err)
		}
	}
	if cfg.Endpoint == "" || cfg.PrivateKey == "" || cfg.PeerPublicKey == "" || cfg.Address == "" {
		return nil, errors.New("wireguard: endpoint, private_key, peer_public_key, address are required")
	}
	if req.DialUpstream == nil {
		return nil, errors.New("wireguard: gateway provides no brokered dial (HostTunnel unavailable)")
	}
	clientAddr, err := netip.ParseAddr(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("wireguard address %q: %w", cfg.Address, err)
	}
	var dns []netip.Addr
	if cfg.DNS != "" {
		d, err := netip.ParseAddr(cfg.DNS)
		if err != nil {
			return nil, fmt.Errorf("wireguard dns %q: %w", cfg.DNS, err)
		}
		dns = append(dns, d)
	}

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{clientAddr}, dns, 1420)
	if err != nil {
		return nil, fmt.Errorf("wireguard netstack: %w", err)
	}

	// The bind opens the WireGuard transport through the gateway's brokered
	// dial. It dials inside Open (not here) because wireguard-go closes and
	// re-opens the bind on every device Up (BindUpdate) — like StdNetBind
	// re-creating its sockets — so the conduit must be (re)creatable, not a
	// single conn opened once. The context is the tunnel's lifetime: the
	// OpenTunnel ctx is cancelled when Open returns, so use a fresh one
	// cancelled on Close.
	dialCtx, cancel := context.WithCancel(context.Background())
	bind := &brokeredBind{dial: req.DialUpstream, endpoint: cfg.Endpoint, ctx: dialCtx}

	dev := device.NewDevice(tunDev, bind,
		device.NewLogger(device.LogLevelError, "[wireguard-plugin] "))
	uapi, err := buildWGIpc(cfg)
	if err != nil {
		dev.Close()
		cancel()
		return nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		cancel()
		return nil, fmt.Errorf("wireguard IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		cancel()
		return nil, fmt.Errorf("wireguard up: %w", err)
	}
	return &wgHandle{dev: dev, tnet: tnet, cancel: cancel}, nil
}

func wireguardDial(ctx context.Context, req pluginsdk.TunnelDialRequest, upstream net.Conn) error {
	h, _ := req.Handle.(*wgHandle)
	if h == nil {
		return errors.New("wireguard: missing handle")
	}
	addrPort, err := resolveInTunnel(h.tnet, req.Addr)
	if err != nil {
		return err
	}
	c, err := h.tnet.DialContextTCPAddrPort(ctx, addrPort)
	if err != nil {
		return fmt.Errorf("wireguard dial %s: %w", req.Addr, err)
	}
	defer func() { _ = c.Close() }()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	<-done
	return nil
}

func wireguardClose(_ context.Context, handle any) error {
	h, _ := handle.(*wgHandle)
	if h == nil {
		return nil
	}
	if h.dev != nil {
		h.dev.Close()
	}
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}

// ---- wireguard-go conn.Bind over a single brokered datagram conduit ----

// brokeredBind is a wireguard-go conn.Bind that sends and receives over the
// gateway's brokered UDP conduit instead of a real UDP socket. There is
// exactly one peer/endpoint — the tunnel's WG server — reached through the
// connected conduit, so addresses are immaterial. Open dials a fresh
// conduit (wireguard-go closes+reopens the bind on every device Up), Close
// tears the current one down.
type brokeredBind struct {
	dial     pluginsdk.DialUpstreamFunc
	endpoint string
	ctx      context.Context
	ep       brokeredEndpoint

	mu sync.Mutex
	pc net.PacketConn
}

func (b *brokeredBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	transport, err := b.dial(b.ctx, "udp", b.endpoint)
	if err != nil {
		return nil, 0, err
	}
	pc := pluginsdk.PacketConnOverStream(transport, endpointAddr())
	b.mu.Lock()
	b.pc = pc
	b.mu.Unlock()
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, _, err := pc.ReadFrom(packets[0])
		if err != nil {
			return 0, net.ErrClosed // the Bind contract: recv returns ErrClosed after Close
		}
		sizes[0] = n
		eps[0] = b.ep
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (b *brokeredBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc != nil {
		_ = b.pc.Close()
		b.pc = nil
	}
	return nil
}

func (b *brokeredBind) SetMark(uint32) error { return nil }
func (b *brokeredBind) BatchSize() int       { return 1 }

func (b *brokeredBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := pc.WriteTo(buf, nil); err != nil { // PacketConnOverStream ignores addr
			return err
		}
	}
	return nil
}

func (b *brokeredBind) ParseEndpoint(string) (conn.Endpoint, error) { return b.ep, nil }

// brokeredEndpoint is the single, immaterial WG endpoint — the real route
// is the connected conduit, so the address is cosmetic.
type brokeredEndpoint struct{}

func (brokeredEndpoint) ClearSrc()           {}
func (brokeredEndpoint) SrcToString() string { return "" }
func (brokeredEndpoint) DstToString() string { return "brokered" }
func (brokeredEndpoint) DstToBytes() []byte  { return []byte{0} }
func (brokeredEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (brokeredEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// endpointAddr returns a synthetic net.Addr for the conduit's remote (used
// only as PacketConnOverStream's reported address).
func endpointAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }

// ---- config ----

// buildWGIpc renders the wireguard-go IpcSet payload (keys are base64 in
// config, hex on the wire). The peer endpoint is a sentinel — the bind
// ignores it and routes through the brokered conduit. 0.0.0.0/0 allowed-ips
// + a forced keepalive so the handshake runs eagerly.
func buildWGIpc(cfg wgConfig) (string, error) {
	privHex, err := base64ToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("wireguard private_key: %w", err)
	}
	pubHex, err := base64ToHex(cfg.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("wireguard peer_public_key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pubHex)
	fmt.Fprintf(&b, "endpoint=0.0.0.0:0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=25\n")
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	return b.String(), nil
}

func base64ToHex(b64 string) (string, error) {
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(dec), nil
}

// resolveInTunnel turns "host:port" into a netip.AddrPort, resolving a
// hostname through the WG netstack's resolver when needed (spike: the
// common case is the gateway handing us an ip:port).
func resolveInTunnel(tnet *netstack.Net, addr string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap, nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard port %q: %w", portStr, err)
	}
	hosts, err := tnet.LookupHost(host)
	if err != nil || len(hosts) == 0 {
		return netip.AddrPort{}, fmt.Errorf("wireguard resolve %q: %w", host, err)
	}
	ip, err := netip.ParseAddr(hosts[0])
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}
