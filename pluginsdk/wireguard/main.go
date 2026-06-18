// Standalone clawpatrol tunnel plugin: route upstream connections
// through a WireGuard tunnel. Spike — demonstrates a UDP-transport plugin
// tunnel that also supports `via` chaining (e.g. `via = socks`, so the
// WireGuard handshake's UDP rides over a SOCKS5 UDP relay).
//
// Mechanism: an in-process wireguard-go device over a gVisor netstack
// (golang.zx2c4.com/wireguard/tun/netstack). Each Dial opens a TCP
// connection over the WG netstack. The hard part is the transport — WG is
// UDP. Direct: wireguard-go's default UDP bind dials the endpoint. Via:
// point the device at a local relay socket and bridge that socket to the
// parent tunnel's datagram conduit (req.Via.Dial(ctx, "udp", endpoint)),
// so the WG UDP packets travel through the parent.
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
		// Direct mode dials the WG endpoint over real UDP; via mode dials
		// the parent. Either way the plugin needs outbound network.
		Capabilities: pluginsdk.Capabilities{Network: pluginsdk.NetworkOutbound},
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
	dev       *device.Device
	tnet      *netstack.Net
	relay     *net.UDPConn       // non-nil in via mode (local WG<->via bridge socket)
	via       net.Conn           // non-nil in via mode (datagram conduit through parent)
	viaCancel context.CancelFunc // cancels the via conduit's context on Close
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
	h := &wgHandle{tnet: tnet}

	// Determine the UDP endpoint the wireguard-go device dials. Direct: the
	// resolved real endpoint. Via: a local relay socket we bridge to the
	// parent tunnel's datagram conduit.
	var deviceEndpoint string
	if req.Via != nil {
		// The via conduit must outlive this Open call — it carries the WG
		// transport for the tunnel's whole lifetime. The OpenTunnel request
		// ctx is cancelled the moment Open returns, which would tear the
		// DialVia stream down immediately; use a tunnel-lifetime context
		// cancelled on Close instead.
		dialCtx, cancel := context.WithCancel(context.Background())
		h.viaCancel = cancel
		via, err := req.Via.Dial(dialCtx, "udp", cfg.Endpoint)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("wireguard via dial: %w", err)
		}
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			_ = via.Close()
			return nil, fmt.Errorf("wireguard relay socket: %w", err)
		}
		h.via, h.relay = via, relay
		deviceEndpoint = relay.LocalAddr().String()
		go bridgeWGToVia(relay, via)
	} else {
		ep, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("wireguard resolve endpoint %q: %w", cfg.Endpoint, err)
		}
		deviceEndpoint = ep.String()
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "[wireguard-plugin] "))
	uapi, err := buildWGIpc(cfg, deviceEndpoint)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard up: %w", err)
	}
	h.dev = dev
	return h, nil
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
	if h.relay != nil {
		_ = h.relay.Close()
	}
	if h.viaCancel != nil {
		h.viaCancel()
	}
	if h.via != nil {
		_ = h.via.Close()
	}
	return nil
}

// bridgeWGToVia couples the wireguard-go device's local UDP socket (which
// sends to `relay`) with the parent tunnel's datagram conduit. WG packets
// arriving at the relay are framed onto the via conduit; datagrams from
// the conduit are delivered back to the device's source address.
func bridgeWGToVia(relay *net.UDPConn, via net.Conn) {
	var (
		mu    sync.Mutex
		wgSrc *net.UDPAddr
	)
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, src, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			wgSrc = src
			mu.Unlock()
			if err := pluginsdk.WriteDatagram(via, buf[:n]); err != nil {
				return
			}
		}
	}()
	for {
		d, err := pluginsdk.ReadDatagram(via)
		if err != nil {
			return
		}
		mu.Lock()
		dst := wgSrc
		mu.Unlock()
		if dst != nil {
			_, _ = relay.WriteToUDP(d, dst)
		}
	}
}

// buildWGIpc renders the wireguard-go IpcSet payload (keys are base64 in
// config, hex on the wire). 0.0.0.0/0 allowed-ips + a forced keepalive so
// the handshake runs eagerly.
func buildWGIpc(cfg wgConfig, endpoint string) (string, error) {
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
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
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
