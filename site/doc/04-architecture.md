# Architecture

## Overview — actors

Five actors take part in a clawpatrol deployment:

- **Agent.** The AI client the operator wants to gate (Claude,
  Codex, …). The agent runs as an ordinary process on the
  operator's workstation and dials upstream hostnames directly; it
  has no awareness that clawpatrol is in the path. clawpatrol also
  covers the non-AI CLIs the agent shells out to (the GitHub CLI,
  kubectl, psql, ssh, …): those aren't agents themselves but tools
  the agent uses, and the gateway applies the same policy gates to
  whichever flows the agent kicks off through them.
- **Device.** The machine the agent runs on. The device hosts a
  small clawpatrol client (CLI binary on Linux; system extension
  inside `Clawpatrol.app` on macOS) that captures the agent's
  outbound flows and feeds them into the tunnel.
- **Tunnel.** A WireGuard underlay between the device and the
  gateway. The tunnel carries L3 packets — every byte the agent
  emits travels inside it. The agent never sees a proxy URL or a
  CA bundle.
- **Gateway.** The clawpatrol process. A single Go binary that
  terminates the tunnel, decides per flow whether to intercept or
  pass through, and runs the policy plugins that inject real
  credentials, gate requests, and emit events. The diagram below
  draws the gateway on its own machine — typically a small VM the
  operator controls — to keep the picture clean, but the deployment
  shape is independent of the binary: the same gateway also runs on
  `localhost` next to the agent for single-machine setups, or
  anywhere reachable by the device's WireGuard config.
- **Upstream.** The API or service the agent is calling
  (api.anthropic.com, api.github.com, an internal Kubernetes API
  server, a Postgres database, a ClickHouse cluster, an SSH
  bastion, …). The upstream sees a connection from the gateway,
  not from the device.

## Process diagram

The gateway is drawn on a separate machine; the device runs only
the client — it does not run policy logic, does not hold
credentials, and does not know upstream secrets.

<svg viewBox="0 0 920 360" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="clawpatrol process diagram: device captures agent flows, tunnels them via WireGuard to the gateway, which either runs them through endpoint, rule, and credential plugins or splices them transparently to the upstream">
  <defs>
    <marker id="ar-proc" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">
      <path d="M0,0 L10,5 L0,10 z" fill="#2a342f"/>
    </marker>
  </defs>
  <style>
    svg text { font-family: ui-monospace, "JetBrains Mono", monospace; fill: #2a342f; }
    .b-proc { fill: #fbf7ee; stroke: #2a342f; stroke-width: 1.5; }
    .f-proc { fill: none; stroke: #6b7770; stroke-width: 1.2; stroke-dasharray: 5 4; }
    .lbl-proc { font-size: 12px; text-anchor: middle; }
    .sm-proc { font-size: 10px; text-anchor: middle; fill: #6b7770; }
    .ttl-proc { font-size: 11px; font-weight: 700; fill: #2a342f; }
    .arr-proc { fill: none; stroke: #2a342f; stroke-width: 1.5; }
  </style>
  <rect class="f-proc" x="20" y="20" width="220" height="160" rx="6"/>
  <text class="ttl-proc" x="30" y="14">device</text>
  <rect class="b-proc" x="40" y="70" width="80" height="40" rx="4"/>
  <text class="lbl-proc" x="80" y="92">agent</text>
  <text class="sm-proc" x="80" y="106">claude/codex</text>
  <rect class="b-proc" x="140" y="70" width="80" height="40" rx="4"/>
  <text class="lbl-proc" x="180" y="92">client</text>
  <text class="sm-proc" x="180" y="106">capture</text>
  <line class="arr-proc" x1="120" y1="90" x2="140" y2="90" marker-end="url(#ar-proc)"/>
  <line class="arr-proc" x1="240" y1="90" x2="335" y2="90" marker-end="url(#ar-proc)"/>
  <text class="sm-proc" x="287" y="82">tunnel (WireGuard)</text>
  <rect class="f-proc" x="335" y="20" width="565" height="320" rx="6"/>
  <text class="ttl-proc" x="345" y="14">gateway</text>
  <rect class="b-proc" x="345" y="70" width="100" height="40" rx="4"/>
  <text class="lbl-proc" x="395" y="94">intercept?</text>
  <text class="sm-proc" x="475" y="64">yes</text>
  <line class="arr-proc" x1="445" y1="90" x2="490" y2="90" marker-end="url(#ar-proc)"/>
  <rect class="b-proc" x="490" y="70" width="115" height="40" rx="4"/>
  <text class="lbl-proc" x="547" y="90">endpoint plugin</text>
  <text class="sm-proc" x="547" y="104">https/k8s/sql/ssh</text>
  <line class="arr-proc" x1="605" y1="90" x2="630" y2="90" marker-end="url(#ar-proc)"/>
  <rect class="b-proc" x="630" y="70" width="100" height="40" rx="4"/>
  <text class="lbl-proc" x="680" y="90">rule plugin</text>
  <text class="sm-proc" x="680" y="104">match facets</text>
  <line class="arr-proc" x1="730" y1="90" x2="760" y2="90" marker-end="url(#ar-proc)"/>
  <rect class="b-proc" x="760" y="50" width="130" height="84" rx="4"/>
  <text class="lbl-proc" x="825" y="68">verdict</text>
  <text class="sm-proc" x="825" y="84">allow</text>
  <text class="sm-proc" x="825" y="98">deny</text>
  <text class="sm-proc" x="825" y="112">HITL approver</text>
  <text class="sm-proc" x="825" y="126">LLM proctor</text>
  <line class="arr-proc" x1="825" y1="134" x2="825" y2="170" marker-end="url(#ar-proc)"/>
  <text class="sm-proc" x="864" y="155" style="text-anchor:start">on allow</text>
  <rect class="b-proc" x="760" y="170" width="130" height="40" rx="4"/>
  <text class="lbl-proc" x="825" y="190">credential plugin</text>
  <text class="sm-proc" x="825" y="204">inject real secret</text>
  <line class="arr-proc" x1="825" y1="210" x2="825" y2="246" marker-end="url(#ar-proc)"/>
  <rect class="b-proc" x="760" y="246" width="130" height="40" rx="4"/>
  <text class="lbl-proc" x="825" y="270">upstream</text>
  <text class="sm-proc" x="365" y="128" style="text-anchor:start">no</text>
  <polyline class="arr-proc" points="395,110 395,316 825,316 825,288" marker-end="url(#ar-proc)"/>
  <text class="sm-proc" x="610" y="308">transparent relay</text>
</svg>

The gateway pulls in three plugin families:

- **Endpoint plugins** define an upstream binding and the wire
  protocol to terminate (`https`, `kubernetes`, `postgres`,
  `clickhouse_native`, `clickhouse_https`, `ssh`). Each plugin owns
  the per-protocol decode: an `https` endpoint sees parsed
  `http.Request` objects; a `postgres` endpoint sees `Query` /
  `Parse` messages; a `clickhouse_native` endpoint sees Hello
  packets; an `ssh` endpoint sees channels and global requests.
- **Credential plugins** own one secret shape each (bearer token,
  OAuth flow, mTLS bundle, postgres user/password, ClickHouse
  user/password, SSH key, cookie, header token, …). Each plugin
  writes to one well-defined slot on the matched flow — header,
  startup message, hello packet, auth replay — and nothing else
  rewrites that slot. The agent never holds the real secret; the
  device only sees a placeholder.
- **Approver plugins** arbitrate human-in-the-loop and
  LLM-in-the-loop verdicts on rules that opt in (`dashboard`,
  `human_approver` over Slack/Discord/Telegram, `llm_approver` for
  synchronous LLM proctoring against a `policy "<name>" { text =
  "..." }` prompt — see `config/README.md`). The dashboard's
  built-in approver pushes pending entries to a queue the operator
  drains in the SPA.

## Connection modes

There are three ways to connect a device to the gateway. Onboarding
runs through `clawpatrol join --url <gateway>`: the dashboard mints
a WireGuard keypair, allocates a `/32` from the configured subnet,
registers the peer with the running wireguard-go device, and the
device persists the resulting `wg-quick`-style config at
`~/.config/clawpatrol/wg.conf`. Each connection mode is what
happens after that.

### `clawpatrol join --whole-machine` (Linux)

Routes every byte the host emits through the gateway. The CLI
calls `wg-quick up` against `/etc/wireguard/clawpatrol.conf` (the
config has `AllowedIPs = 0.0.0.0/0, ::/0`), which uses the kernel
WireGuard module to add the route and replace the default gateway.
Reference: `login.go:wgQuickUp`, `wireguard.go`.

- **Tunnel mechanism.** Kernel WireGuard via `wg-quick`. The kernel
  driver owns the tunnel lifetime; clawpatrol does not run a
  userspace WG on the device.
- **What's installed on the device.** `/etc/wireguard/clawpatrol.conf`
  (root-owned, mode `0o600`); `wg-quick` activates the `clawpatrol`
  network interface and adds default routes through it.
- **Scope.** Whole host. Every process on the device, including the
  operator's shell, browser, and unrelated daemons, dials through
  the gateway.

### `clawpatrol run -- <cmd>` (Linux)

Routes one process tree through the gateway, leaves the rest of
the device alone. The CLI re-execs itself in fresh user, network,
and mount namespaces with `CAP_NET_ADMIN` in the ambient set,
opens a TUN inside the new netns, runs userspace wireguard-go
against it, configures `default dev wg0`, drops the ambient cap,
and execs the wrapped command. Reference: `run_linux.go:runRun` /
`runRunChild`.

- **Tunnel mechanism.** Userspace wireguard-go embedded in the
  `clawpatrol` binary; the TUN lives only inside the unshared
  netns.
- **What's installed on the device.** Nothing persistent — no
  kernel module, no `/etc/wireguard/`, no system service. Just the
  `clawpatrol` binary and `~/.config/clawpatrol/wg.conf` from
  onboarding.
- **Scope.** The wrapped process and all its descendants. The host
  default route is untouched. Other shells and processes on the
  device keep their original network.

### `clawpatrol run -- <cmd>` (macOS)

Routes the wrapped process tree through the gateway via a Network
Extension. The CLI hands the command off to
`/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol`, which
forks the agent as a child of the `.app` and ensures the
`NETransparentProxyProvider` system extension is loaded.
Reference: `run_darwin.go`,
`macos/ClawpatrolExtension/Provider.swift`.

The extension intercepts every outbound TCP and UDP flow on the
host and filters in `handleNewFlow`: it walks each flow's
originating PPID chain and tunnels only those flows whose ancestor
is the wrapped `.app` process. Matched flows are bridged into a
userspace wireguard-go tunnel + gVisor netstack inside the
extension; non-matched flows return `false` and proceed via the
host's normal network. A `--whole-machine` mode skips the PPID
filter and tunnels every flow.

- **Tunnel mechanism.** Userspace wireguard-go + gVisor netstack
  inside the system extension (`macos/netstack/`). Apple's per-app
  `NEPacketTunnel` routing is gated behind MDM, so the extension
  uses `NETransparentProxyProvider` and applies the per-process
  scope itself.
- **What's installed on the device.** `Clawpatrol.app` in
  `/Applications/`, plus its system extension (one-time approval
  prompt at first install). The first `clawpatrol run` activates
  the extension; subsequent runs are no-ops.
- **Scope.** The wrapped process and its descendants, identified
  by PPID walk against the parent app's signing identifier.

## Network traffic processing

Once a flow reaches the gateway over the tunnel, the gateway
inspects the destination port (and, for some families, the SNI or
the resolved hostname) to pick a handler. A **family** is the
protocol class an endpoint plugin advertises so rule plugins can
target it: today the gateway ships `https` (the `https` endpoint),
`sql` (postgres, clickhouse_native, clickhouse_https), and `k8s`
(kubernetes). Rule kinds bind to families, not to individual
endpoint types — `http_rule` matches anything in `https`,
`sql_rule` anything in `sql`, `k8s_rule` anything in `k8s`. New
protocols (e.g. `ssh`) carry their own family identifier when
their rule kind ships. Anything the gateway has no opinion on
splices to the real upstream byte-for-byte. There is no
`HTTPS_PROXY` env var, no per-tool CA configuration, and no
`iptables` rule on the gateway host: the WG netstack accepts SYNs
to any destination IP/port and hands the dispatcher the original
4-tuple intact.

### Dispatch decision

The promiscuous WG forwarder picks one branch per inbound flow
based on the destination port and IP:

<svg viewBox="0 0 980 470" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="gateway dispatch decision flow: incoming flows are routed by destination port and IP into MitM HTTPS, postgres MitM, DNS-VIP, VIP-bound endpoint runtime, direct-IP endpoint runtime, or transparent relay">
  <defs>
    <marker id="ar-disp" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">
      <path d="M0,0 L10,5 L0,10 z" fill="#2a342f"/>
    </marker>
  </defs>
  <style>
    svg text { font-family: ui-monospace, "JetBrains Mono", monospace; fill: #2a342f; }
    .b-disp { fill: #fbf7ee; stroke: #2a342f; stroke-width: 1.5; }
    .lbl-disp { font-size: 12px; text-anchor: middle; }
    .row-disp { font-size: 12px; }
    .cond-disp { font-size: 11px; fill: #2a342f; font-weight: 600; }
    .arr-disp { fill: none; stroke: #2a342f; stroke-width: 1.5; }
  </style>
  <rect class="b-disp" x="20" y="20" width="200" height="36" rx="4"/>
  <text class="lbl-disp" x="120" y="42">agent flow arrives</text>
  <line class="arr-disp" x1="120" y1="56" x2="120" y2="80" marker-end="url(#ar-disp)"/>
  <rect class="b-disp" x="20" y="80" width="200" height="36" rx="4"/>
  <text class="lbl-disp" x="120" y="102">dispatch on dst port / IP</text>
  <line class="arr-disp" x1="120" y1="116" x2="120" y2="430"/>
  <line class="arr-disp" x1="120" y1="160" x2="240" y2="160" marker-end="url(#ar-disp)"/>
  <text class="cond-disp" x="125" y="155">TCP :443</text>
  <rect class="b-disp" x="240" y="142" width="720" height="36" rx="4"/>
  <text class="row-disp" x="250" y="164">SNI peek; matched endpoint ⇒ MitM TLS (https / k8s family); no match ⇒ unknown_host policy (passthrough or close)</text>
  <line class="arr-disp" x1="120" y1="210" x2="240" y2="210" marker-end="url(#ar-disp)"/>
  <text class="cond-disp" x="125" y="205">TCP :5432</text>
  <rect class="b-disp" x="240" y="192" width="720" height="36" rx="4"/>
  <text class="row-disp" x="250" y="214">ConnIndex (DNS-resolved IP) → device profile picks one postgres endpoint ⇒ MitM (sql_rule); no match ⇒ relay</text>
  <line class="arr-disp" x1="120" y1="260" x2="240" y2="260" marker-end="url(#ar-disp)"/>
  <text class="cond-disp" x="125" y="255">UDP/TCP :53</text>
  <rect class="b-disp" x="240" y="242" width="720" height="36" rx="4"/>
  <text class="row-disp" x="250" y="264">DNS-VIP responder: known VIP-bound host returns its allocated VIP; everything else is forwarded to the upstream resolver</text>
  <line class="arr-disp" x1="120" y1="310" x2="240" y2="310" marker-end="url(#ar-disp)"/>
  <text class="cond-disp" x="125" y="305">dst is allocated VIP</text>
  <rect class="b-disp" x="240" y="292" width="720" height="36" rx="4"/>
  <text class="row-disp" x="250" y="314">VIP table → endpoint runtime owning the VIP (today: ssh, clickhouse_native reached by hostname)</text>
  <line class="arr-disp" x1="120" y1="360" x2="240" y2="360" marker-end="url(#ar-disp)"/>
  <text class="cond-disp" x="125" y="355">dst IP in ConnIndex</text>
  <rect class="b-disp" x="240" y="342" width="720" height="36" rx="4"/>
  <text class="row-disp" x="250" y="364">direct-IP endpoint runtime (e.g. clickhouse_native bound to a literal cluster IP)</text>
  <line class="arr-disp" x1="120" y1="410" x2="240" y2="410" marker-end="url(#ar-disp)"/>
  <text class="cond-disp" x="125" y="405">otherwise</text>
  <rect class="b-disp" x="240" y="392" width="720" height="36" rx="4"/>
  <text class="row-disp" x="250" y="414">transparent relay (defaults.unknown_host = passthrough by default)</text>
</svg>

The branches are described below, with the summary table at the
end of the section.

### TLS SNI

For TCP flows on `:443`, the gateway peeks the TLS `ClientHello`
to recover the SNI hostname, then looks up the endpoint claiming
that host within the device's profile. If the endpoint is `https`
or `k8s`, the gateway terminates TLS with a leaf cert minted on
the fly (P-256, 30-day validity, in-memory cache, signed by the
gateway's CA), parses the request, runs it through the rule
matcher and approve chain, asks the credential plugin to inject
the real secret, and round-trips upstream. Endpoints whose family
isn't HTTPS-shaped (e.g. `clickhouse_https`, schema-only today)
fall through to passthrough.

The CA cert is provisioned on the device during onboarding so the
agent's TLS clients trust the minted leaves; the agent never sees
the upstream's real cert.

### Postgres claiming

Postgres endpoints don't have an SNI to peek, so the gateway
claims them by destination IP. The mechanism is the `ConnRouter`
interface in `config/runtime/conn_route.go`: an endpoint plugin's
body satisfies `ConnRouter` when it exposes
`ConnRouteHosts() []string`, returning the `host:port` tuples it
claims (`db.example.com:5432`, …). At policy load the gateway
resolves each host via DNS and folds the answers into a
`ConnIndex` keyed `dstIP → endpoint(s)`.

When a TCP connection lands on `:5432`, the WG forwarder routes it
into `handlePostgresConn`, which consults the index by the
connection's destination IP to pick the matching endpoint. When
several endpoints share an IP (writer + readonly aimed at the same
RDS instance) the lookup filters by the device's profile so the
right one wins; single-database profiles fall back to "first
postgres in profile" without needing DNS at all. The postgres
endpoint runtime then performs auth offload and runs the flow
through `sql_rule` matching with the right credential.

The same `ConnRouter` mechanism powers `clickhouse_native` (claimed
by direct IP) and `ssh` (claimed by DNS-VIP); the plugin only has
to declare its host tuples and the dispatcher does the rest
without `main.go` having to learn about new families.

### DNS interception → VIP

Some families (`ssh`, `clickhouse_native`) have no SNI and no
`Host` header, so the gateway can't recover the agent-dialed
hostname from the wire bytes alone. Their endpoint plugins flag
`RequiresVIP`, and the dnsvip allocator assigns each hostname a
stable virtual IP at policy build, persisted to disk so VIPs
survive restart.

The gateway runs an in-process DNS responder on UDP/TCP `:53`. The
WG netstack delivers all DNS queries here regardless of the
agent's resolver setting (any port-53 datagram reaches the
gateway). For VIP-bound hostnames it returns the allocated VIP;
for everything else it forwards the query to the upstream resolver
and returns the real A/AAAA verbatim, so unrelated traffic flows
unchanged.

When the agent dials the VIP, the WG forwarder routes any port on
that IP into the matching endpoint runtime, which recovers the
hostname from the VIP table and dispatches into the right plugin
(SSH server-toward-agent / SSH client-toward-upstream with auth
replay; ClickHouse Hello-packet placeholder swap; …).

### Direct IP

Endpoint plugins can also bind to literal IPs (`hosts =
["172.17.0.1"]` for an in-cluster ClickHouse). Those skip dnsvip
entirely — the agent dials the IP without ever issuing a DNS
query. The gateway maintains an index of IP-literal bindings and
consults it in the catch-all branch of the dispatcher: if the
destination IP claims an endpoint, the flow goes to that
endpoint's runtime; otherwise it falls through to transparent
relay.

### Intercept-or-passthrough summary

With the branches explained, the dispatch table reads as a
summary:

| dst port             | handler                                                                                  |
|----------------------|------------------------------------------------------------------------------------------|
| `:443`               | SNI peek, then HTTPS family dispatch (`https` / `k8s`) or passthrough                    |
| `:5432`              | postgres wire-protocol gateway (auth offload + `sql_rule` matching)                      |
| `:53`                | DNS-VIP responder (UDP and TCP fallback)                                                 |
| any port, dst is VIP | VIP-bound endpoint runtime (today: `ssh`, `clickhouse_native` reached by hostname)       |
| `else`               | direct-IP endpoint lookup; falls through to transparent TCP relay when no plugin claims  |

If no endpoint plugin claims the destination, the gateway falls
back to a transparent relay: it dials the real destination IP and
pipes bytes both ways. The `defaults.unknown_host` knob in
`gateway.hcl` (`passthrough` by default) decides what to do when an
HTTPS SNI doesn't match any configured endpoint — splice it
unchanged or close it.

UDP dispatch is narrower: only `:53` is handled today (DNS-VIP);
other UDP datagrams are dropped.
