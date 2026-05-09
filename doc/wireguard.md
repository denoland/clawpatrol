# clawpatrol — WireGuard mode

WireGuard as the primary control plane. No Tailscale account, no
kernel module, no `wg-quick` lifecycle on the gateway, no systemd
unit for the WG interface, no `/etc/hosts` pinning on clients. The
clawpatrol binary IS the WG endpoint and the L3 forwarder.

## How it works

The gateway runs an embedded **wireguard-go** + a **gVisor netstack**
in promiscuous mode — same shape as unclaw's `boringtun` + `smoltcp`
(`set_any_ip`) setup, just in Go.

1. wireguard-go decrypts UDP off the wire, hands inner packets to a
   custom `netTun` (`wgnet.go:newNetTUN`).
2. `netTun` injects into a gVisor stack built with **`HandleLocal:
   false`** (the upstream `tun/netstack.CreateNetTUN` hardcodes
   `HandleLocal: true`, which combined with promiscuous mode causes
   the IP layer to drop every packet as "InvalidSource"). NIC has
   `SetPromiscuousMode + SetSpoofing`, IP layer accepts ANY dst.
3. `tcp.NewForwarder` + `udp.NewForwarder` register as the stack's
   default transport handlers. Every TCP/UDP session to ANY dst IP
   reaches `EnablePromiscuousForwarder`'s callback.
4. Callback dispatches by port:
   - `:443` → `g.handle` (SNI peek → MITM or splice)
   - `:<info_listen>` → dashboard mux
   - else → `wgRelay` / `relayUDP` to real upstream
5. Clients route `0.0.0.0/0` through the tunnel. Agents resolve real
   hostnames via public DNS (UDP/53 forwarded by the gateway), open
   real public IPs, gateway intercepts at L3.

## What works (verified end-to-end on vultr)

- `clawpatrol gateway -config gateway.hcl` boots WG endpoint on
  UDP 51820, dashboard + MITM ride the same forwarder.
- Server keypair persisted at `<oauth_dir>/wg-server.key`. Pubkey
  derived via curve25519 at boot. Peer (pubkey → IP) map persisted
  at `<oauth_dir>/wg-peers.json`, replayed on every restart so
  existing clients survive gateway redeploys.
- `clawpatrol join <gw>` runs once: prints user-code, opens
  dashboard URL, server mints a fresh keypair, allocates a /32 from
  the configured subnet, registers the peer with wireguard-go,
  hands back a `wg-quick` conf. Server **auto-claims** the peer
  IP for the approver at mint time — no client-side claim
  round-trip (which used to race against the new default route).
- `wg-quick up` writes `/etc/wireguard/clawpatrol.conf` and brings the
  tunnel up. PostUp swaps `/etc/resolv.conf` to `1.1.1.1` (no
  `resolvconf` dependency — backed up + restored on PostDown).
  Default route via wg, fwmark 51820 keeps WG handshakes themselves
  off the tunnel. SSH stays alive (fwmark 51820 + ip rule trick).
- Agents (`claude`, `gh`, `codex`) run unmodified. `eval "$(clawpatrol
  env)"` exports placeholder tokens + CA bundle. Outbound HTTPS to
  `api.anthropic.com` resolves to a real public IP, routes through
  WG to the gateway, TCP forwarder catches the SYN, port-443
  dispatch fires `g.handle`, SNI matches, MITM injects real OAuth,
  forwards to real upstream, response returns through the tunnel.

## vs Tailscale mode

- Dashboard auth in WG mode falls back to `admin_email` for every
  approval. Multi-user setups need an auth proxy
  (Cloudflare Access, basic auth, etc.) that fills
  `X-Forwarded-User` / `X-Forwarded-Email` (~10 LoC to teach
  `ownerForCaller` to read those).
- Both endpoints behind the same NAT egress IP can't establish a
  WG handshake (UDP hairpin drop). Same constraint as plain unclaw
  remote mode. Use a real public-IP VPS for the gateway.

## Operator setup

```bash
# on the gateway VM (real public IP needed)
curl -fsSL https://denoland.github.io/clawpatrol/install.sh | sh

cat > /etc/clawpatrol/gateway.hcl <<'EOF'
listen       = "0.0.0.0:8443"
info_listen  = "0.0.0.0:8080"
public_url   = "http://your-gw.example.com:8080"
admin_email  = "you@example.com"
ca_dir       = "/opt/clawpatrol/ca"
log_path     = "/opt/clawpatrol/gateway.log"
oauth_dir    = "/opt/clawpatrol/oauth"
integrations = ["claude", "codex", "github"]

tailscale {
  control        = "wireguard"
  wg_endpoint    = "your-gw.example.com:51820"
  wg_subnet_cidr = "10.55.0.0/24"
}
EOF

mkdir -p /opt/clawpatrol
clawpatrol init-ca /opt/clawpatrol/ca

iptables -I INPUT -p udp --dport 51820 -j ACCEPT
iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
clawpatrol gateway -config /etc/clawpatrol/gateway.hcl
```

Connect Claude / GitHub / Codex via the dashboard at
`http://your-gw.example.com:8080`. Per-user OAuth credentials land
in `/opt/clawpatrol/oauth/`.

## Client setup

```bash
curl -fsSL https://denoland.github.io/clawpatrol/install.sh | sh
clawpatrol join http://your-gw.example.com:8080
# approve at the displayed URL, done — claude/gh/codex just work
```

## Diagnostics

The gateway exposes a debug endpoint on `127.0.0.1:6060` (localhost only).

| Path | Description |
|------|-------------|
| `/debug/vars` | JSON: expvar counters (tcpStats, wgTxPackets, wgTxBytes) |
| `/debug/pprof/` | pprof index (goroutine, heap, CPU profile, trace) |

```bash
curl -s http://localhost:6060/debug/vars | python3 -m json.tool
```

### tcpStats fields

| Field | What it means |
|-------|---------------|
| `currentEstab` | Live TCP connections through the gVisor stack |
| `retransmits` | Total retransmitted segments (all causes) |
| `fastRetransmit` | Loss events caught by 3-dupack — normal loss recovery |
| `timeouts` | **RTO timeout events** — each resets cwnd to 10; high values kill throughput |
| `slowStartRtx` | Retransmits during slow start — usually equals `timeouts` |
| `resetsSent` | RSTs sent by the stack |
| `segSendErrors` | gVisor failed to hand a segment to WireGuard — should always be 0 |

### Reading the numbers

**Healthy:**
```
timeouts: 0
fastRetransmit: low relative to segsSent (< 0.5%)
```

**cwnd collapse (RTO-driven):**
```
timeouts: high (> 10)
slowStartRtx: matches timeouts
```
Each timeout resets the congestion window to 10 segments. Cause: peer RTT is
close to `minRTO` (1 s). Investigate path latency if a peer's RTT exceeds ~800 ms.

**Burst packet loss:**
```
timeouts: 0
fastRetransmit: high
retransmits >> fastRetransmit  (many segments lost per event)
```
SACK reports many missing segments per fast-retransmit event. Check the peer's
UDP receive buffer (`/proc/net/snmp` `RcvbufErrors`); increase
`net.core.rmem_default` on the peer if non-zero.

### Throughput counters

`wgTxPackets` / `wgTxBytes` count IP packets leaving gVisor toward WireGuard.
Poll twice and divide by interval for current throughput.

### pprof

```bash
# 30-second CPU profile
curl -s "http://localhost:6060/debug/pprof/profile?seconds=30" -o cpu.prof
go tool pprof cpu.prof

# goroutine dump
curl -s "http://localhost:6060/debug/pprof/goroutine?debug=2"
```

## wg-go heap buffer limit: PreallocatedBuffersPerPool

### What it is

wireguard-go defines a constant `PreallocatedBuffersPerPool` in
`device/queueconstants_default.go`:

```go
const (
    PreallocatedBuffersPerPool = 0 // Disable and allow for infinite memory growth
)
```

This constant controls how many packet buffers are pre-allocated in each
of wireguard-go's internal buffer pools (inbound, outbound, handshake).
`0` means pools grow without bound — no cap on heap allocation.

On mobile and embedded targets wireguard-go ships platform-specific
overrides:

| Platform | Value | Reason |
|----------|-------|--------|
| default (Linux/macOS/…) | `0` | unlimited |
| Android | `4096` | constrained RAM |
| iOS | `1024` | Network Extension API memory cap |

### The open PR

[wireguard-go PR #69](https://github.com/WireGuard/wireguard-go/pull/69)
— *"device: Allow buffer memory growth to be limited at run time"*
(opened 2023-02-26 by Seth Lankford, unmerged as of 2026-05).

The PR converts `PreallocatedBuffersPerPool` from a compile-time `const`
to a runtime `var`, so operators can tune the cap without recompiling:

```go
// PR proposes:
var PreallocatedBuffersPerPool uint32 = 0
```

**Why it hasn't merged:** the project lead prefers a dynamic heuristic
(scale the pool automatically based on available system memory, like the
kernel ratelimiter) rather than exposing a manual knob. The PR remains
stalled; the author's last comment predates the dynamic-heuristic
proposal.

### Does this affect clawpatrol?

Clawpatrol embeds wireguard-go as a gateway process (`golang.zx2c4.com/wireguard`),
not as a mobile app. The unbounded-growth default is fine under typical
loads, but can become a problem at scale:

- **High peer count** (thousands of peers, each with active tunnels)
  amplifies buffer pool pressure. One reported data point: a deployment
  with ~10 500 peers saw wireguard-go consume ~18 GB before the patch;
  ~2 GB after setting the pool cap to 4096.
- **Memory-constrained gateway hosts** (small VPS, ≤ 1–2 GB RAM) are at
  risk of OOM even at moderate peer counts during traffic bursts.

Run `curl -s http://localhost:6060/debug/vars | python3 -m json.tool` and
watch `wgTxPackets`/`wgTxBytes` while also profiling the heap
(`/debug/pprof/heap`) to decide whether this bites you.

### Should we fork wg-go?

**Recommendation: no fork right now.**

The change PR #69 proposes is a one-line diff (`const` → `var`). That
makes it feasible to apply as a `replace` directive in `go.mod` against a
minimal local or GitHub-hosted fork if memory pressure becomes a real
problem in production. A full fork of wireguard-go carries ongoing
maintenance cost (tracking upstream security patches) that is hard to
justify while the default is demonstrably fine for the typical single-
gateway deployment.

Preferred path if the memory issue materialises:

1. Open a clawpatrol issue with heap profiles to quantify the impact.
2. Apply the patch via a `go.mod` `replace` pointing at a thin fork that
   has only the one-line change, or vendor the patched file.
3. Revert to upstream once PR #69 (or its successor) lands.

The Tailscale fork (`github.com/tailscale/wireguard-go`, which clawpatrol
already pulls in transitively) also keeps `PreallocatedBuffersPerPool = 0`
on non-mobile platforms, so switching to Tailscale's fork would not help
here.
