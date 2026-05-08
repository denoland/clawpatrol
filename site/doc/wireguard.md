# WireGuard / gVisor Diagnostics

The gateway exposes a debug endpoint on `127.0.0.1:6060` (localhost only).
It publishes WireGuard throughput counters and gVisor TCP stats via expvar,
plus the full Go pprof suite.

## Endpoints

| Path | Description |
|------|-------------|
| `/debug/vars` | JSON: expvar counters (tcpStats, wgTxPackets, wgTxBytes) |
| `/debug/pprof/` | pprof index (goroutine, heap, CPU profile, trace) |

```bash
# on the gateway host
curl -s http://localhost:6060/debug/vars | python3 -m json.tool
```

## tcpStats fields

```json
{
  "tcpStats": {
    "currentEstab":    3,
    "segsSent":        44514,
    "segsReceived":    16074,
    "retransmits":     765,
    "fastRetransmit":  138,
    "fastRecovery":    0,
    "timeouts":        48,
    "slowStartRtx":    48,
    "resetsSent":      2,
    "resets":          72,
    "invalidSegments": 0,
    "segSendErrors":   0
  }
}
```

| Field | What it means |
|-------|---------------|
| `currentEstab` | Live TCP connections through the gVisor stack |
| `retransmits` | Total retransmitted segments (all causes) |
| `fastRetransmit` | Loss events caught by 3-dupack — normal loss recovery |
| `fastRecovery` | Segments retransmitted during fast recovery |
| `timeouts` | **RTO timeout events** — each resets cwnd to 10; high values kill throughput |
| `slowStartRtx` | Retransmits during slow start — usually equals `timeouts` |
| `resetsSent` | RSTs sent by the stack (connection errors, policy rejects) |
| `segSendErrors` | gVisor failed to hand a segment to WireGuard — should always be 0 |

## Throughput counters

```bash
curl -s http://localhost:6060/debug/vars | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('tx packets:', d['wgTxPackets'])
print('tx bytes:  ', d['wgTxBytes'])
"
```

`wgTxPackets` and `wgTxBytes` count IP packets leaving gVisor toward WireGuard
(outbound from the gateway's perspective). Poll twice and divide by interval for
current throughput.

## Reading the numbers

### Healthy session
```
timeouts: 0
fastRetransmit: low relative to segsSent (< 0.5%)
retransmits: low
```

### cwnd collapse (RTO-driven)
```
timeouts: high (> 10)
slowStartRtx: matches timeouts
```
Each timeout resets the congestion window to 10 segments. Cause: RTO fires
before ACKs return, usually because the peer RTT is close to or above
`minRTO` (currently 1 s). Check `minRTO` if a peer's RTT exceeds ~800 ms.

### Packet loss on the path
```
timeouts: 0
fastRetransmit: high
retransmits >> fastRetransmit  (many segments lost per event)
```
Fast retransmit fires (3 dupacks) but SACK reports many missing segments per
event. Indicates burst loss somewhere between the gateway and the peer — check
the peer's UDP receive buffer (`/proc/net/snmp` `RcvbufErrors`) and increase
`net.core.rmem_default` if non-zero.

### Normal operation with distant peers
Some `fastRetransmit` events are expected on cross-continental paths.
`timeouts: 0` is the key indicator that the stack is healthy.

## pprof

```bash
# 30-second CPU profile
curl -s "http://localhost:6060/debug/pprof/profile?seconds=30" -o cpu.prof
go tool pprof cpu.prof

# goroutine dump (check for stuck goroutines)
curl -s "http://localhost:6060/debug/pprof/goroutine?debug=2"

# heap profile
curl -s "http://localhost:6060/debug/pprof/heap" -o heap.prof
go tool pprof heap.prof
```

## Architecture note

The gVisor TCP stack runs inside the gateway process. Each WireGuard peer
gets TCP connections handled by gVisor's userspace stack (`netTun` +
`blockingChanEP`). The `blockingChanEP` link endpoint blocks `WritePackets`
instead of dropping when WireGuard's send path is busy, preventing silent
drops that would collapse the TCP congestion window.

```
gVisor TCP sender
      │ WritePackets (blocks when full)
      ▼
blockingChanEP.outbound  [256-slot channel]
      │ Read() — WireGuard RoutineReadFromTUN drains directly
      ▼
wireguard-go encrypt → UDP → peer
```
