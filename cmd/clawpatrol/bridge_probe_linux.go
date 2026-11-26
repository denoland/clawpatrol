//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// wgProbeTimeout bounds one liveness probe round trip. Well under the
// keepalive-interval probe cadence, so a lost probe is a prompt failure.
const wgProbeTimeout = 3 * time.Second

// icmpProber sends ICMP echoes to the gateway's tunnel address over one
// socket that stays open for the session. A reply proves both directions of
// the tunnel in one round trip: the request advanced the gateway peer's rx,
// the reply advanced ours.
type icmpProber struct {
	conn     *icmp.PacketConn
	dst      net.Addr
	proto    int
	echoType icmp.Type
	// raw sockets see every ICMP packet in the netns, so replies are matched
	// on ID as well as sequence. Datagram sockets get only their own replies.
	raw bool
	id  int
	seq int
}

// openICMPProber opens the probe socket. It tries an unprivileged datagram
// socket first, which needs the pod's net.ipv4.ping_group_range to include
// the bridge's GID. On a permission error it tries a raw socket, which needs
// CAP_NET_RAW. When neither is allowed it returns errProbeUnavailable.
func openICMPProber(gwIP netip.Addr) (*icmpProber, error) {
	dgramNet, rawNet, listen := "udp4", "ip4:icmp", "0.0.0.0"
	p := &icmpProber{
		proto:    ipv4.ICMPTypeEcho.Protocol(),
		echoType: ipv4.ICMPTypeEcho,
		id:       os.Getpid() & 0xffff,
	}
	if gwIP.Is6() {
		dgramNet, rawNet, listen = "udp6", "ip6:ipv6-icmp", "::"
		p.proto = ipv6.ICMPTypeEchoRequest.Protocol()
		p.echoType = ipv6.ICMPTypeEchoRequest
	}
	c, err := icmp.ListenPacket(dgramNet, listen)
	if err != nil {
		if !isPermissionErr(err) {
			return nil, fmt.Errorf("open icmp socket: %w", err)
		}
		dgramErr := err
		c, err = icmp.ListenPacket(rawNet, listen)
		if err != nil {
			if isPermissionErr(err) {
				return nil, fmt.Errorf("%w: datagram socket: %w; raw socket: %w", errProbeUnavailable, dgramErr, err)
			}
			return nil, fmt.Errorf("open raw icmp socket: %w", err)
		}
		p.raw = true
		setEchoReplyFilter(c, gwIP.Is6())
	}
	p.conn = c
	if p.raw {
		p.dst = &net.IPAddr{IP: net.IP(gwIP.AsSlice())}
	} else {
		p.dst = &net.UDPAddr{IP: net.IP(gwIP.AsSlice())}
	}
	return p, nil
}

// setEchoReplyFilter limits a raw socket to echo replies, so other ICMP
// traffic in the netns does not fill its receive queue. Best effort.
func setEchoReplyFilter(c *icmp.PacketConn, is6 bool) {
	if is6 {
		var f ipv6.ICMPFilter
		f.SetAll(true)
		f.Accept(ipv6.ICMPTypeEchoReply)
		_ = c.IPv6PacketConn().SetICMPFilter(&f)
		return
	}
	var f ipv4.ICMPFilter
	f.SetAll(true)
	f.Accept(ipv4.ICMPTypeEchoReply)
	_ = c.IPv4PacketConn().SetICMPFilter(&f)
}

// Probe sends one echo and waits up to timeout for its reply. A permission
// error on send returns errProbeUnavailable.
func (p *icmpProber) Probe(timeout time.Duration) error {
	p.seq = (p.seq + 1) & 0xffff
	msg := icmp.Message{
		Type: p.echoType,
		Code: 0,
		Body: &icmp.Echo{ID: p.id, Seq: p.seq, Data: []byte("clawpatrol-bridge")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	if err := p.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := p.conn.WriteTo(b, p.dst); err != nil {
		if isPermissionErr(err) {
			return fmt.Errorf("%w: send echo: %w", errProbeUnavailable, err)
		}
		return fmt.Errorf("send echo: %w", err)
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := p.conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("await echo reply: %w", err)
		}
		rm, err := icmp.ParseMessage(p.proto, buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPTypeEchoReply && rm.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok || echo.Seq != p.seq || (p.raw && echo.ID != p.id) {
			// A late reply to an earlier probe, or another process's echo.
			continue
		}
		return nil
	}
}

func (p *icmpProber) Close() error {
	if p == nil || p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

func isPermissionErr(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}
