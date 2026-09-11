package main

// udpDisposition is what the gateway does with a forwarded UDP flow.
type udpDisposition int

const (
	udpPassthrough udpDisposition = iota // leave it to the transport's default handler
	udpDNS                               // intercept via dnsvip
	udpDrop                              // refuse with ICMP port unreachable; never relayed
	udpRelay                             // transparently relay to the upstream
)

// udpPortDisposition is the destination-port half of UDP dispatch. It is
// the single place that decides what a UDP port means to clawpatrol, and
// every transport consumes it: the WireGuard promiscuous forwarder
// (udpDispatch in runGateway, gated by refuseUDPPort), the tsnet
// exit-node catch-all (tsnetUDPDisposition) and the Linux `clawpatrol
// run` daemon (newTransportUDPProtocolHandler, gated by refuseUDPPort).
//
//   - UDP/53 → dnsvip, whatever resolver IP the client aimed at.
//   - UDP/443 → drop, for every destination. That is QUIC / HTTP-3,
//     which the gateway never inspects. Plain https endpoints are
//     dispatched by SNI on TCP/443 and carry no VIP, so relaying
//     UDP/443 would let an intercepted host's HTTPS ride straight
//     past its rules (and past unknown_host = deny, which is TCP
//     only). Nothing on UDP/443 is ever relayed.
//   - anything else → relay. Whether a given source may relay is the
//     transport's call (tsnet gates on onboarding, see
//     tsnetUDPDisposition; every WireGuard peer is onboarded by
//     construction).
//
// A dropped flow is refused before a gVisor endpoint exists for it, so
// the netstack answers with ICMP port unreachable sourced from the
// original destination. A QUIC client sees ECONNREFUSED on its
// connected socket and falls back to TCP/443 at once instead of
// waiting out its own handshake timer. The Linux daemon refuses locally
// for the same reason: its relay carries datagrams, not ICMP, so an
// unreachable from the gateway would never reach the wrapped process.
func udpPortDisposition(port uint16) udpDisposition {
	switch port {
	case 53:
		return udpDNS
	case 443:
		return udpDrop
	}
	return udpRelay
}

// refuseUDPPort is the pre-endpoint gate for transports that consult the
// port decision before creating a gVisor endpoint (the WireGuard
// forwarder and the Linux run daemon): true means "answer ICMP port
// unreachable, do not service this flow".
func refuseUDPPort(port uint16) bool {
	return udpPortDisposition(port) == udpDrop
}
