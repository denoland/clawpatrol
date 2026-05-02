# `clawpatrol run`

Route a single process tree's traffic through the gateway, leave the
rest of the machine alone. Multiple concurrent invocations on the same
host share one machine identity (same WG keypair, same dashboard
device). Server-side has zero new state.

This document is the design. Implementation lands in phased PRs.

## Goals

- `clawpatrol run -- <cmd> [args...]` routes the cmd's traffic (and
  its descendants) through the clawpatrol gateway.
- Default `clawpatrol join` no longer routes the whole machine. It
  registers identity + persists keys, that's it. Operators who want
  the old behaviour pass `--whole-machine`.
- Multiple concurrent `clawpatrol run` invocations work without
  conflict. Each shares the single machine peer.
- Server has nothing to do with `run`. One peer per machine; the
  dashboard sees N AI sessions under that one device, the same way
  it does today.

Out of scope (separate efforts):
- GUI onboarding
- Same-machine sandboxing (`--fs-access`, hide data dirs, etc. — see
  `../unclaw/native/napi/src/client_linux/netns.rs` for the maximal
  version).
- Per-run policies / per-run dashboard rows. The right axis for
  policy is per-AI-session anyway, which is already tracked.

## Two install modes (split from current join)

| Command | Behaviour |
|---|---|
| `clawpatrol join --url <gw>` | Approve + persist `wg.conf`. **No** host-wide tunnel. |
| `clawpatrol join --url <gw> --whole-machine` | Same as above + `wg-quick up clawpatrol`. Today's behaviour. |

Both write `~/.config/clawpatrol/wg.conf` (per-user). The
`--whole-machine` mode also calls `wg-quick up` so all host traffic
egresses via the gateway.

## `clawpatrol run` — Linux

### Mechanism

One persistent **sidecar network namespace** per machine. All `run`
invocations drop into it. The sidecar netns holds one WireGuard
interface (`wg0`) driven by an embedded `wireguard-go` device. The
WG userspace UDP socket lives in the **init netns** so it egresses
the host's normal default route to reach the gateway endpoint.

```
init netns (host)                 sidecar netns ($USER)
─────────────────                 ──────────────────────
                                                                                     ┌──────────────────┐
wireguard-go ←──── TUN fd ──────  wg0  10.55.0.X/32
device       (passed via             │
             SCM_RIGHTS)             ├── default route via wg0
                                     │
UDP socket   ───────────────────→ gateway:51820
(init netns)                      (real internet)
```

### First-run bring-up

```
1. flock /run/user/$UID/clawpatrol.lock
2. if /run/user/$UID/clawpatrol/netns is unpinned or its supervisor pid is dead:
   a. fork:
      - parent stays in init netns
      - child unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)
      - parent writes /proc/<child>/uid_map = "0 <real_uid> 1"
      - parent writes /proc/<child>/setgroups = "deny"
      - parent writes /proc/<child>/gid_map = "0 <real_gid> 1"
   b. child opens /dev/net/tun, builds wg0 ifreq with IFF_TUN|IFF_NO_PI
   c. child sends TUN fd back via SCM_RIGHTS over a socketpair
   d. parent runs embedded wireguard-go device on that TUN fd
      (golang.zx2c4.com/wireguard/device — already linked for the
      gateway side, reuse for the client)
   e. parent bind-mounts /proc/<child>/ns/net → /run/user/$UID/clawpatrol/netns
      so the netns survives even after the supervisor restarts.
   f. child:
      - sets address on wg0 via netlink
      - adds default route via wg0
      - bind-mounts a tmpfile `nameserver 10.55.0.1` over /etc/resolv.conf
      - pauses in pause(2) — anchors the netns as long as supervisor lives
3. spawn cmd:
   - setns(/run/user/$UID/clawpatrol/netns)
   - execve(cmd, argv, environ)
4. parent of cmd: waitpid + exit with cmd's status
```

### Concurrent runs

The lock + pinned netns design means only the *first* `run` does the
WG bring-up. Subsequent runs check the lock, find a live supervisor
+ pinned netns, and skip directly to step 3 (`setns` + `execve`).
All cmds share the same wg0, the same /32, the same machine peer.

Multiple `cmd` processes inside the netns work because the netns
itself permits arbitrary fork/exec — the WG plumbing just provides
their default route.

### Cleanup

- The supervisor process holds the wireguard-go device + the paused
  netns-anchor child. It runs in a tight loop counting active setns'd
  descendants (via `inotify` on `/run/user/$UID/clawpatrol/runs/`).
  When the last run exits, supervisor optionally tears down WG and
  unpins the netns.
- Or simpler: leave the netns idle forever, reuse on next `run`.
  Costs ~few-MB RAM. Probably the right default.
- Crash recovery: on `clawpatrol run` start, if the lock is held by a
  dead pid, take it over and either reuse the pinned netns (if WG
  still alive) or rebuild.

### Privileges

Unprivileged. The `unshare(CLONE_NEWUSER)` gives the namespaced
child CAP_NET_ADMIN inside its own netns + uid 0 mapping (with the
caller's real uid mapped to namespaced root). No `sudo`, no
`newuidmap`, no setuid binary. Caller's own uid mapped 1:1 is enough
for v1.

### Failure surface

- `unshare(CLONE_NEWUSER)` denied: distros with restricted user
  namespaces (Debian 11 by default has `kernel.unprivileged_userns_clone=1`,
  but RHEL/CentOS may disable). Fail with a friendly message.
- `/dev/net/tun` not present: tell user to `modprobe tun` or run
  inside a container that exposes it.
- Conf missing: tell user to run `clawpatrol join` first.

## `clawpatrol run` — macOS

Reuse the persistent NE tunnel approach from
`../unclaw/macos/UnclawExtension/`. One `NETransparentProxyProvider`
per machine, registered + signed at install time. It carries one
WireGuard tunnel (the machine peer). NE filter selects flows by
ppid:

```
clawpatrol run on macOS:
  1. ensures the NE provider is active
  2. fork() the user's cmd
  3. IPC (XPC) the child pid + ephemeral run_id to the NE provider
  4. provider's filter: "outbound TCP and pid descends from a registered run pid"
       → relay through tunnel
       else passthrough
  5. wait + on exit IPC pid removal
```

`--whole-machine` mode: provider's filter degenerates to "match
everything" (one global registered pid = init).

This requires:
- Xcode project (`macos/Clawpatrol.app` + bundled
  `ClawpatrolExtension.systemExtension`)
- NE entitlements + Developer ID signing + notarization
- `clawpatrol install` to enable the system extension on first run

Heavy lift. Lift directly from unclaw's
`TransparentProxyProvider.swift`, `ProcessTree.swift`,
`SessionRegistry.swift`, and the IPC server. Strip the parts we
don't need (no per-pid proxy port routing — we have a single
tunnel; no fwmark; no FUSE).

## CLI shape

```
clawpatrol join --url <gw> [--whole-machine]
clawpatrol run [--conf <path>] -- <cmd> [args...]
```

`run` exits with the cmd's exit code. SIGINT/SIGTERM forwarded to
the cmd. `-h` prints platform notes.

## Phasing

| PR | Change | LoC |
|---|---|---|
| 1 | `join --whole-machine` flag; default no longer brings up wg-quick. Conf path moves to `~/.config/clawpatrol/wg.conf` (per-user). | ~80 |
| 2 | `clawpatrol run` Linux MVP: unshare + wg-go on TUN fd + setns + exec. Single-run only (no sharing). | ~500 |
| 3 | Netns sharing: flock + pinned ns + supervisor lifecycle. Concurrent runs work. | ~150 |
| 4 | Polish: signal forwarding, exit-code propagation, friendly errors, idle netns reaper. | ~100 |
| 5+ | macOS NE: lift from `../unclaw/macos/UnclawExtension/`, strip to our needs. Separate effort. | ~2k Swift + Xcode project |

Server has no changes for any of the Linux phases.

## Open design calls

1. **Conf path**. `~/.config/clawpatrol/wg.conf` (per-user) feels
   right — `run` is per-user. `--whole-machine` could also drop a
   copy at `/etc/wireguard/clawpatrol.conf` for `wg-quick`. Or just
   feed wg-quick a tempfile rendered from the per-user conf.
2. **`--whole-machine` default**. Pre-1.0; flip default immediately
   to "no host tunnel"? Or one release with a deprecation warning?
3. **netlink dep** (`vishvananda/netlink`). ~200 KB pure Go,
   well-maintained. Avoids shelling to `ip(8)`. Default yes.
4. **Restricted-userns distros**. Detect + tell user to either run
   under sudo or `sysctl kernel.unprivileged_userns_clone=1`. Don't
   silently fall back to a worse mode.
5. **Sidecar netns lifetime**. Default to "keep idle indefinitely"
   (cheap). Add `clawpatrol run --teardown-on-exit` if someone wants
   the opposite.

## Reference

- `../unclaw/native/napi/src/client_linux/netns.rs` — Rust impl of
  the Linux side. We deliberately ship a smaller subset.
- `../unclaw/macos/UnclawExtension/{TransparentProxyProvider,
  ProcessTree,SessionRegistry,IPCServer}.swift` — macOS NE.
- `golang.zx2c4.com/wireguard/device` — userspace WG, already linked
  for the gateway.
- `vishvananda/netlink` — pure-Go netlink.
- WireGuard wiki, "Routing & Network Namespace Integration" —
  describes the canonical pattern of WG-in-namespace with UDP
  egressing init netns.

## Research notes (May 2026)

The proposed design is well-trodden ground. Closest prior art:

### `wireguard4netns` (cmusatyalab)

Direct match for our Linux mechanism. Creates a TUN inside an
unprivileged user+net namespace, ships the fd back to the init
namespace via SCM_RIGHTS, and runs `wireguard-go` against that fd
in init netns so the UDP socket egresses through the host's normal
default route. No setuid binary, no `sudo`, no kernel WG required.

Footgun documented in their README: stock `wireguard-go` fails when
the TUN fd lives in a different netns from the running process —
specifically the MTU getter/setter ioctls fail because the netlink
socket has no view into the TUN's namespace. They ship a patched
wireguard-go that ignores those errors. We'll either patch our
linked copy similarly, or set MTU from inside the child before
shipping the fd (cleaner, doesn't require a fork). Default to the
latter.

### `slirp4netns` (rootless-containers)

The pattern we're using for the namespace handshake — fork +
unshare + socketpair + SCM_RIGHTS — is exactly slirp4netns'
production-proven design. Used by podman / Buildah for rootless
container networking. Battle-tested across distros. We're
substituting WireGuard for slirp's usermode TCP/IP stack but the
plumbing is identical.

### Pinned netns survival

Canonical pattern for keeping a netns alive after its creating
process dies: bind-mount `/proc/<pid>/ns/net` over a file. Confirmed
by namespaces(7), setns(2). This is exactly what `ip netns add`
does — `ip netns add foo` creates `/var/run/netns/foo` as a bind
mount of a fresh netns.

For multi-user use we'll mount under `/run/user/$UID/clawpatrol/netns`
(per-user XDG_RUNTIME_DIR style), so two users on the same machine
get separate sidecar netns'es. Single-user case uses the same path.

### WireGuard canonical netns pattern

Already documented on wireguard.com/netns/. The interface lives in
one netns; the UDP socket in another. Standard wg-quick supports
this directly: `ip link add wg0 type wireguard; ip link set wg0
netns <ns>`. We replicate the same topology in userspace.

### macOS — NETransparentProxyProvider per-pid filtering

NETransparentProxyProvider gives per-flow `sourceAppAuditToken`
which `audit_token_to_pid` resolves to a pid. `proc_pidinfo` walks
ppid. This is the path unclaw uses, mirrored from Apple's own
SimpleTunnel sample. Stable since macOS 11. iOS/macOS 26 adds full
URL-level filtering (vs hostname-only) which we don't need yet —
HTTPS-MITM happens at the gateway anyway.

Practical constraint: NETransparentProxyProvider runs as a system
extension (`*.systemextension` bundled inside the parent `.app`).
Requires Developer ID signing + notarization for distribution.
Self-signed builds work for local dev only. This is the bulk of
the macOS work — ~80% of the LoC is Xcode + Swift glue, not policy.

### Stable choices

Based on the above, the design holds. Concrete picks:

1. **TUN-fd handoff via SCM_RIGHTS** (slirp4netns / wireguard4netns
   pattern) over alternatives like `/proc/<pid>/fd/N`. Stable since
   the early 2000s, every distro supports it.
2. **Set MTU on the TUN inside the child netns** before shipping
   the fd. Avoids the wireguard-go MTU footgun without patching the
   library.
3. **Bind-mount-pin the netns at `/run/user/$UID/clawpatrol/netns`.**
   Standard XDG path. Auto-cleaned on logout (tmpfs is volatile).
4. **`vishvananda/netlink` for in-process addr/route config.**
   Avoids shelling to `iproute2`. Pure Go, ~200 KB, last release
   stable.
5. **macOS: lift unclaw's NE verbatim, strip per-pid-port routing
   (we have one shared tunnel, not N proxy ports). One PID
   registration set, one filter, single `ClientTunnel` instance.**

### Search results consulted

- WireGuard, "Routing & Network Namespace Integration" —
  https://www.wireguard.com/netns/
- cmusatyalab/wireguard4netns —
  https://github.com/cmusatyalab/wireguard4netns
- rootless-containers/slirp4netns —
  https://github.com/rootless-containers/slirp4netns
- Apple, NETransparentProxyProvider —
  https://developer.apple.com/documentation/NetworkExtension/NETransparentProxyProvider
- Apple WWDC25, "Filter and tunnel network traffic with
  NetworkExtension" —
  https://developer.apple.com/videos/play/wwdc2025/234/
- mitmproxy, Intercepting macOS Applications —
  https://www.mitmproxy.org/posts/local-capture/macos/
- LWN, "Namespaces in operation, part 2" —
  https://lwn.net/Articles/531381/
