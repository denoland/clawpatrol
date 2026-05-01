# Userspace WireGuard

Claw Patrol uses a userspace WireGuard implementation. The WireGuard protocol,
TCP/IP stack, and DNS interception all run inside the clawpatrol process without
requiring root, iptables, or kernel modules.

## Architecture

```
              UDP :51820
                  |
             +---------+
             | boringtun|  WireGuard protocol (Rust)
             | decrypt  |  encrypt/decrypt via Noise protocol
             +---------+
                  |
             raw IP packets
                  |
             +---------+
             | smoltcp  |  Userspace TCP/IP stack (Rust)
             | (Rust)   |  Accepts TCP on any port, UDP on port 53
             +---------+
               /     \
          TCP conns   UDP datagrams
            |              |
       +---------+    +---------+
       | napi-rs |    | napi-rs |   Node.js native addon
       | stream  |    | stream  |   ReadableStream<TcpConn>
       +---------+    +---------+   ReadableStream<UdpDatagram>
            |              |
     +-------------+  +---------+
     | main.ts     |  | main.ts |   Connection router
     | route by    |  | DNS vs  |
     | dst ip:port |  | forward |
     +-------------+  +---------+
      /    |     \          |
  proxy  dns   relay      dns
   .ts   .ts   TCP        .ts
```

## Native addon (`native/`)

The addon is a Rust crate built with napi-rs. It exposes:

- **Tunnel** class -- manages WireGuard peers and the smoltcp stack
- **TcpConn** class -- a single TCP connection from a WG client
- **UdpDatagram** object -- a single UDP packet from a WG client

Key properties:

| Property | Type | Description |
|----------|------|-------------|
| `tunnel.connections` | `ReadableStream<TcpConn>` | Accepted TCP connections |
| `tunnel.datagrams` | `ReadableStream<UdpDatagram>` | Incoming UDP datagrams |
| `tcpConn.readable` | `ReadableStream<Buffer>` | Data from the WG client |
| `tcpConn.peerPublicKey` | `string` | WG public key of the client |
| `tcpConn.peerIp` | `string` | Tunnel IP of the client |
| `tcpConn.dstIp` | `string` | Destination IP the client connected to |
| `tcpConn.dstPort` | `number` | Destination port |

### Dynamic port listening

smoltcp requires explicit TCP listen sockets. High-traffic ports (443, 8443,
80, 53) get a pre-allocated pool of 16 sockets. All other ports are handled
via SYN-peeking: when an IP packet containing a TCP SYN for an unknown port
arrives, a listener is dynamically created before smoltcp processes the packet.

### Crate stack

| Crate | Purpose |
|-------|---------|
| **boringtun** | WireGuard protocol (Noise handshake, ChaCha20-Poly1305) |
| **smoltcp** | Userspace TCP/IP (no kernel, pure Rust, polling-based) |
| **napi-rs** | Node.js native addon bindings |
| **tokio** | Async runtime (UDP socket, timers, channels) |

## Connection routing (main.ts)

All TCP connections from the tunnel are dispatched in `routeTunnelConnections()`:

| Destination | Handler |
|-------------|---------|
| Any IP, port 443 or 8443 | `proxy.ts handleConnection()` -- MitM transparent proxy |
| Any IP, port 53 | `dns.ts handleDnsTcpConnection()` -- DNS over TCP |
| VIP (10.78.x.x), any port | `dns.ts handleDnsConnection()` -- per-hostname handler |
| Everything else | `relayTcp()` -- transparent TCP forwarding |

All UDP datagrams:

| Destination | Handler |
|-------------|---------|
| Any IP, port 53 | `dns.ts handleDnsPacket()` -- DNS query/response |
| Everything else | `relayUdp()` -- transparent UDP forwarding |

## What changed from kernel WireGuard

| Before (kernel) | After (userspace) |
|------------------|-------------------|
| `wg0` kernel interface | No kernel interface |
| `sudo wg set` to add peers | `tunnel.addPeer()` in JS |
| `iptables REDIRECT` for port 443 | Route by `dstPort` in JS |
| `iptables DNAT` for VIPs | Route by `dstIp` in JS |
| `iptables MASQUERADE` for forwarding | `relayTcp()`/`relayUdp()` in JS |
| Requires root/sudo | Runs as unprivileged user |
| Linux-only | Any platform with Rust + Node.js |

## Building

```bash
cd native
npm install
npm run build        # release build
npm run build:debug  # debug build
```

Requires Rust stable toolchain and Node.js >= 22.

## Peer metadata

Every `TcpConn` and `UdpDatagram` carries:
- `peerPublicKey` -- base64 WireGuard public key of the client
- `peerIp` -- tunnel IP (e.g. `10.77.0.2`)

This allows the proxy to identify which agent is making each request
without relying on source IP alone.
