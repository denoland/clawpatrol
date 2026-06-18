// Standalone clawpatrol tunnel plugin: route upstream connections
// through a SOCKS5 proxy. Spike — demonstrates a PARENT tunnel that can
// carry UDP (so a WireGuard tunnel can chain `via = socks`).
//
// TCP upstreams use SOCKS5 CONNECT. "udp" dials (a chained child asking
// for a datagram conduit) use SOCKS5 UDP ASSOCIATE; the child's bytes are
// length-prefixed datagrams (pluginsdk.ReadDatagram/WriteDatagram) which
// this plugin reframes onto the proxy's UDP relay.
//
// The plugin opens NO raw sockets: it reaches the SOCKS proxy and the UDP
// relay only through the gateway's brokered DialUpstream, so it runs with
// no network capability of its own (network = "none"), just like an
// endpoint plugin.
//
// Build: go build -o socks-tunnel ./pluginsdk/socks
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/denoland/clawpatrol/pluginsdk"
)

func main() {
	pluginsdk.Run(&pluginsdk.Plugin{
		Name:    "socks_tunnel",
		Version: "0.1",
		// No raw sockets: the plugin reaches the proxy and the UDP relay
		// only through the gateway's brokered DialUpstream.
		Capabilities: pluginsdk.Capabilities{Network: pluginsdk.NetworkNone},
		Tunnels:      []pluginsdk.TunnelDef{socksDef()},
	})
}

// strAddr is a synthetic net.Addr for the brokered relay conn (already
// connected, so PacketConnOverStream only reports it back, never dials it).
type strAddr string

func (a strAddr) Network() string { return "udp" }
func (a strAddr) String() string  { return string(a) }

type socksConfig struct {
	Proxy    string `json:"proxy"`    // host:port of the SOCKS5 server
	Username string `json:"username"` // optional user/pass auth
	Password string `json:"password"`
}

func socksDef() pluginsdk.TunnelDef {
	return pluginsdk.TunnelDef{
		TypeName: "socks_proxy",
		Schema: pluginsdk.Schema{Fields: []pluginsdk.SchemaField{
			{Name: "proxy", TypeString: "string", Required: true},
			{Name: "username", TypeString: "string"},
			{Name: "password", TypeString: "string"},
		}},
		Open: func(_ context.Context, req pluginsdk.TunnelOpenRequest) (any, error) {
			var cfg socksConfig
			if len(req.CanonicalConfig) > 0 {
				if err := json.Unmarshal(req.CanonicalConfig, &cfg); err != nil {
					return nil, fmt.Errorf("socks_proxy config: %w", err)
				}
			}
			if cfg.Proxy == "" {
				return nil, errors.New("socks_proxy: proxy is required")
			}
			return &cfg, nil
		},
		Dial: func(ctx context.Context, req pluginsdk.TunnelDialRequest, upstream net.Conn) error {
			cfg, _ := req.Handle.(*socksConfig)
			if cfg == nil {
				return errors.New("socks_proxy: missing handle")
			}
			if req.DialUpstream == nil {
				return errors.New("socks_proxy: gateway has no transport dial support")
			}
			switch req.Network {
			case "", "tcp":
				return socksDialTCP(ctx, req.DialUpstream, cfg, req.Addr, upstream)
			case "udp":
				return socksDialUDP(ctx, req.DialUpstream, cfg, req.Addr, upstream)
			default:
				return fmt.Errorf("socks_proxy: unsupported network %q", req.Network)
			}
		},
		Close: func(_ context.Context, _ any) error { return nil },
	}
}

// ---- TCP: SOCKS5 CONNECT, then pump bytes ----

func socksDialTCP(ctx context.Context, dial pluginsdk.DialUpstreamFunc, cfg *socksConfig, addr string, upstream net.Conn) error {
	c, err := dial(ctx, "tcp", cfg.Proxy)
	if err != nil {
		return fmt.Errorf("dial socks proxy: %w", err)
	}
	defer func() { _ = c.Close() }()
	if err := socksHandshake(c, cfg); err != nil {
		return err
	}
	if _, err := socksRequest(c, cmdConnect, addr); err != nil {
		return fmt.Errorf("socks CONNECT %s: %w", addr, err)
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	<-done
	return nil
}

// ---- UDP: SOCKS5 UDP ASSOCIATE, datagram-framed over `upstream` ----

func socksDialUDP(ctx context.Context, dial pluginsdk.DialUpstreamFunc, cfg *socksConfig, target string, upstream net.Conn) error {
	// The TCP control connection must stay open for the lifetime of the
	// association — closing it tells the proxy to drop the UDP relay.
	ctrl, err := dial(ctx, "tcp", cfg.Proxy)
	if err != nil {
		return fmt.Errorf("dial socks proxy: %w", err)
	}
	defer func() { _ = ctrl.Close() }()
	if err := socksHandshake(ctrl, cfg); err != nil {
		return err
	}
	relayStr, err := socksRequest(ctrl, cmdUDPAssociate, "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("socks UDP ASSOCIATE: %w", err)
	}
	// The reply's BND.ADDR is frequently unspecified (0.0.0.0) or an
	// internal address when the proxy sits behind NAT (e.g. a cloud VM
	// returning its private IP). The UDP relay lives on the proxy host, so
	// fall back to the proxy's host with the returned port unless the reply
	// names a concrete, routable address.
	relayHost, relayPort, _ := net.SplitHostPort(relayStr)
	if ip := net.ParseIP(relayHost); ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() {
		relayHost, _, _ = net.SplitHostPort(cfg.Proxy)
	}
	relayHostPort := net.JoinHostPort(relayHost, relayPort)

	// Open the UDP relay through the gateway's brokered dial (no raw
	// socket). The conn carries length-prefixed datagrams; treat it as a
	// connected net.PacketConn.
	relayConn, err := dial(ctx, "udp", relayHostPort)
	if err != nil {
		return fmt.Errorf("dial socks relay %q: %w", relayHostPort, err)
	}
	pc := pluginsdk.PacketConnOverStream(relayConn, strAddr(relayHostPort))
	defer func() { _ = pc.Close() }()

	hdr, err := socksUDPHeader(target)
	if err != nil {
		return err
	}

	done := make(chan struct{}, 3)
	// upstream datagrams -> SOCKS relay (prepend the UDP request header)
	go func() {
		for {
			d, rerr := pluginsdk.ReadDatagram(upstream)
			if rerr != nil {
				break
			}
			pkt := append(append([]byte(nil), hdr...), d...)
			if _, werr := pc.WriteTo(pkt, strAddr(relayHostPort)); werr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	// SOCKS relay -> upstream datagrams (strip the UDP reply header)
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, _, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				break
			}
			payload, ok := stripSocksUDPHeader(buf[:n])
			if !ok {
				continue
			}
			if werr := pluginsdk.WriteDatagram(upstream, payload); werr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	// The control conn closing (proxy dropped the association) ends it.
	go func() {
		var b [1]byte
		_, _ = ctrl.Read(b[:])
		done <- struct{}{}
	}()
	<-done
	return nil
}

// ---- SOCKS5 wire format (RFC 1928) ----

const (
	socksVer        = 0x05
	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03
	atypIPv4        = 0x01
	atypDomain      = 0x03
	atypIPv6        = 0x04
)

func socksHandshake(c net.Conn, cfg *socksConfig) error {
	useAuth := cfg.Username != ""
	methods := []byte{0x00}
	if useAuth {
		methods = []byte{0x02}
	}
	greeting := append([]byte{socksVer, byte(len(methods))}, methods...)
	if _, err := c.Write(greeting); err != nil {
		return err
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		return err
	}
	if sel[0] != socksVer {
		return fmt.Errorf("socks: bad version %d", sel[0])
	}
	switch sel[1] {
	case 0x00:
		return nil
	case 0x02:
		return socksUserPassAuth(c, cfg)
	default:
		return fmt.Errorf("socks: no acceptable auth method (got %d)", sel[1])
	}
}

func socksUserPassAuth(c net.Conn, cfg *socksConfig) error {
	msg := []byte{0x01, byte(len(cfg.Username))}
	msg = append(msg, cfg.Username...)
	msg = append(msg, byte(len(cfg.Password)))
	msg = append(msg, cfg.Password...)
	if _, err := c.Write(msg); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("socks: user/pass auth failed")
	}
	return nil
}

// socksRequest sends a CONNECT or UDP ASSOCIATE request for addr and
// returns the bound address from the reply ("host:port").
func socksRequest(c net.Conn, cmd byte, addr string) (string, error) {
	dst, err := encodeSocksAddr(addr)
	if err != nil {
		return "", err
	}
	req := append([]byte{socksVer, cmd, 0x00}, dst...)
	if _, err := c.Write(req); err != nil {
		return "", err
	}
	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", err
	}
	if head[1] != 0x00 {
		return "", fmt.Errorf("socks reply code %d", head[1])
	}
	host, err := readSocksAddr(c, head[3])
	if err != nil {
		return "", err
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

// socksUDPHeader builds the per-datagram SOCKS UDP request header for a
// fixed target: RSV(2)=0 FRAG=0 ATYP DST.ADDR DST.PORT.
func socksUDPHeader(target string) ([]byte, error) {
	dst, err := encodeSocksAddr(target)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x00, 0x00, 0x00}, dst...), nil
}

// stripSocksUDPHeader removes the SOCKS UDP reply header, returning the
// inner payload.
func stripSocksUDPHeader(b []byte) ([]byte, bool) {
	if len(b) < 4 {
		return nil, false
	}
	// b[0:2]=RSV, b[2]=FRAG, b[3]=ATYP
	off := 4
	switch b[3] {
	case atypIPv4:
		off += 4
	case atypIPv6:
		off += 16
	case atypDomain:
		if len(b) < 5 {
			return nil, false
		}
		off += 1 + int(b[4])
	default:
		return nil, false
	}
	off += 2 // port
	if off > len(b) {
		return nil, false
	}
	return b[off:], true
}

func encodeSocksAddr(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append([]byte{atypIPv4}, v4...)
		} else {
			out = append([]byte{atypIPv6}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("socks: host too long")
		}
		out = append([]byte{atypDomain, byte(len(host))}, host...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(p))
	return append(out, port[:]...), nil
}

func readSocksAddr(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		return net.IP(b[:]).String(), nil
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		return net.IP(b[:]).String(), nil
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("socks: bad atyp %d", atyp)
	}
}
