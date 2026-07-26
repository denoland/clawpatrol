//go:build linux

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// wgProbeTimeout bounds one liveness probe round trip. Well under the
// keepalive-interval probe cadence, so a lost probe is a prompt failure.
const wgProbeTimeout = 3 * time.Second

// pingGatewayTunnel sends one ICMP echo to the gateway's tunnel address and
// waits up to timeout for the reply. It uses an unprivileged ICMP datagram
// socket (SOCK_DGRAM / IPPROTO_ICMP), which needs no CAP_NET_RAW as long as
// the pod netns permits it (net.ipv4.ping_group_range) — the same path the
// workload's `ping` uses. A reply proves both directions of the tunnel in one
// round trip: the request advanced the gateway peer's rx, the reply advanced
// ours.
func pingGatewayTunnel(gwIP netip.Addr, timeout time.Duration) error {
	network, listen := "udp4", "0.0.0.0"
	echoType := icmp.Type(ipv4.ICMPTypeEcho)
	proto := ipv4.ICMPTypeEcho.Protocol()
	if gwIP.Is6() {
		network, listen = "udp6", "::"
		echoType = ipv6.ICMPTypeEchoRequest
		proto = ipv6.ICMPTypeEchoRequest.Protocol()
	}
	c, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return fmt.Errorf("open icmp socket: %w", err)
	}
	defer func() { _ = c.Close() }()

	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("clawpatrol-bridge")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := c.WriteTo(b, &net.UDPAddr{IP: net.IP(gwIP.AsSlice())}); err != nil {
		return fmt.Errorf("send echo: %w", err)
	}
	// The socket only receives replies to its own echoes (the kernel demuxes on
	// the ID it assigned), so any echo reply we read is ours.
	buf := make([]byte, 1500)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("await echo reply: %w", err)
		}
		rm, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			return nil
		}
	}
}
