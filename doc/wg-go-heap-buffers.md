# Limitation: wireguard-go unbounded heap growth (PreallocatedBuffersPerPool)

## The problem

wireguard-go's default build has no cap on how much heap memory its internal
packet buffer pools can consume. The constant that controls this is
`PreallocatedBuffersPerPool` in `device/queueconstants_default.go`:

```go
const (
    PreallocatedBuffersPerPool = 0 // Disable and allow for infinite memory growth
)
```

`0` means the pools (inbound, outbound, handshake) grow without bound. Under
sustained traffic or at high peer counts the Go runtime never releases the
pooled memory back to the OS, so resident heap climbs monotonically until the
process is OOM-killed.

Real-world data point: a deployment with ~10 500 active peers saw wireguard-go
consume ~18 GB of RAM. After patching `PreallocatedBuffersPerPool` to `4096`
the same load settled at ~2 GB with no observable throughput change.

wireguard-go ships hard-coded platform overrides for constrained environments:

| Platform | Value | Reason |
|----------|-------|--------|
| default (Linux/macOS/…) | `0` | unlimited |
| Android | `4096` | constrained RAM |
| iOS | `1024` | Network Extension API memory limit |

Clawpatrol uses the default build (`golang.zx2c4.com/wireguard`), so it
inherits the unbounded behaviour.

## Impact on clawpatrol today

Low-to-moderate deployments (single gateway, hundreds of peers, lightly
loaded) are generally unaffected — the pools do not grow large enough to
matter and the host has headroom.

The risk surface is:

- **High peer count** (thousands of peers with active tunnels): pool
  pressure accumulates per concurrent inbound/outbound worker; can
  exceed available RAM even on a well-sized host.
- **Memory-constrained gateways** (≤ 1–2 GB VPS): moderate traffic during
  bursts fills the pool past the available headroom.

To check whether this is biting a live gateway:

```bash
# heap profile — look for large sync.Pool or wireguard-go device slabs
curl -s "http://localhost:6060/debug/pprof/heap" -o heap.prof
go tool pprof heap.prof

# traffic counters — watch for sustained high wgTxBytes alongside memory growth
curl -s http://localhost:6060/debug/vars | python3 -m json.tool
```

## The upstream PR that fixes it

[wireguard-go PR #69](https://github.com/WireGuard/wireguard-go/pull/69)
— *"device: Allow buffer memory growth to be limited at run time"*
(opened 2023-02-26, unmerged as of 2026-05).

The change is a one-liner: convert the compile-time `const` to a runtime `var`
so operators can set it before the device is created:

```go
// upstream proposes:
var PreallocatedBuffersPerPool uint32 = 0
```

The PR has stalled because the upstream maintainer wants a dynamic heuristic
(auto-scale the cap based on available system memory) rather than a manual
knob. No progress on the dynamic heuristic has appeared since the proposal.

## How a fork fixes it

Because the change is a single-line diff, a minimal fork is low-cost to
maintain. The fix:

1. Fork `golang.zx2c4.com/wireguard` (e.g. `github.com/denoland/wireguard-go`).
2. In `device/queueconstants_default.go`, change `const` to `var`:
   ```go
   var PreallocatedBuffersPerPool uint32 = 4096
   ```
3. Point `go.mod` at the fork:
   ```
   replace golang.zx2c4.com/wireguard => github.com/denoland/wireguard-go v0.0.0-<date>-<hash>
   ```
4. Track upstream security patches by periodically merging from
   `golang.zx2c4.com/wireguard`; the diff stays a single file, one line.

The Tailscale fork (`github.com/tailscale/wireguard-go`, already a transitive
dependency) keeps `PreallocatedBuffersPerPool = 0` on non-mobile platforms, so
switching to it would not help here.

## Recommendation

Do not fork yet. The risk only materialises at scale we have not reached.

When heap pressure is observed in production (via pprof or OOM events):

1. File a clawpatrol issue with heap profiles to quantify the impact.
2. Apply the one-line patch via a `go.mod replace` pointing at a thin fork
   (steps above). The fork surface is one file; upstream security patches
   can be tracked with a periodic `git merge`.
3. Revert to upstream once PR #69 or an equivalent lands.
