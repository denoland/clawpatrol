# Architecture

## Overview

Clawpatrol is a single Go binary (`go 1.26.1`, no external runtime) that
sits between agents and the upstream APIs they call. It does three jobs:

1. Terminates a userspace WireGuard tunnel and accepts traffic from
   onboarded peers at L3.
2. Intercepts each agent flow at the wire — HTTPS via SNI peek and
   MITM, postgres / clickhouse-native / SSH via per-protocol
   gateways — dispatches it through a typed policy compiled from
   HCL, and lets credential plugins stamp real secrets onto matched
   requests so the agent never holds them.
3. Serves a dashboard for onboarding devices, approving/denying
   pending requests, and pasting credential material into per-profile
   slots.

The same binary is the WG endpoint, the wire-protocol gateway
(HTTPS / postgres / clickhouse / SSH), the dashboard server, and
the CLI used on agent machines (`clawpatrol join`,
`clawpatrol run …`, `clawpatrol login`, etc.).

## Process layout

```
                        agents
                          │
                          │  WireGuard (UDP :51820)
                          ▼
         ┌────────────────────────────────────┐
         │ clawpatrol gateway (single Go bin) │
         │                                    │
         │  ┌──────────────────────────────┐  │
         │  │ wireguard-go device          │  │
         │  │  + gVisor netstack TUN       │  │  promiscuous L3:
         │  │  + promiscuous forwarder     │  │  any dst IP/port
         │  └──────────────┬───────────────┘  │
         │                 │                  │
         │  dispatch by dst port + VIP:       │
         │   :443  → HTTPS MITM (SNI peek)    │
         │   :5432 → postgres wire gateway    │
         │   :53   → DNS-VIP responder        │
         │   VIP   → SSH / clickhouse_native  │
         │   :dash → dashboard mux            │
         │   else  → ConnIndex direct-IP /    │
         │           transparent relay        │
         │                                    │
         │  policy: HCL → CompiledPolicy      │
         │  state:  SQLite (clawpatrol.db)    │
         │  CA:     ca.crt / ca.key (P-256)   │
         └────────────────────────────────────┘
                          │
                          ▼
                       upstream
```

The Go binary is the only moving part on the gateway host. The
WireGuard endpoint is userspace (no kernel module, `wg-quick`, or
`/etc/wireguard/` config), L3 dispatch happens in-process via the
gVisor netstack (no `iptables` rules), the in-process DNS-VIP
responder handles virtual-IP synthesis without a separate
Bind/Unbound sidecar (and only for the SSH and `clickhouse_native`
endpoint families that can't be dispatched on dst port alone —
every other DNS query is forwarded verbatim and the agent dials the
real upstream IP), and TLS termination runs against stdlib
`crypto/tls` directly (no separate Caddy/TLS frontend).

## Connecting an agent

The dashboard's onboarding flow mints a WireGuard keypair, allocates a
`/32` from the configured subnet (`gateway.wg_subnet_cidr`, default
`10.55.0.0/24`), and registers the peer with the running
wireguard-go device. The agent gets back a `wg-quick`-style config
with `AllowedIPs = 0.0.0.0/0, ::/0` — every byte the agent emits goes
into the tunnel.

There is no `HTTPS_PROXY` env var, no per-tool CA configuration, and
no `iptables` rule on the gateway host. The promiscuous netstack
forwarder accepts a SYN to any dst IP:port and hands it to the
gateway's dispatcher with the original 4-tuple intact, so the agent
just resolves the upstream hostname (the gateway's in-process DNS
responder forwards real upstreams unchanged and substitutes a
virtual IP only for endpoints flagged `RequiresVIP`) and dials it.

### macOS network extension

`clawpatrol run -- <cmd>` on macOS routes one process tree through
the gateway without a system-wide tunnel. The CLI registers the
child PID with an `NETransparentProxyProvider` system extension over
XPC; the extension walks each outbound flow's PPID chain to decide
whether the flow belongs to the wrapped tree, then relays matched
flows over a userspace WireGuard tunnel to the same `:51820` endpoint.

See [Userspace WireGuard](10-userspace-wireguard.md) for the netstack
internals.

## Promiscuous WG forwarder

The gateway boots a `wireguard-go` device backed by a custom gVisor
`netstack` TUN. The stack runs with `HandleLocal=false` so inbound
flows aren't dropped as "local source". A custom `NIC` route
matching `0.0.0.0/0` and `::/0` makes the netstack accept connections
to any destination IP, not just its own.

`Gateway.EnablePromiscuousForwarder` registers two callbacks: one
fires per inbound TCP flow with the original `(c, dstIP, dstPort)`,
the other per UDP datagram. TCP dispatch:

| dst tuple              | handler                                                                                                                                                                    |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `:443`                 | `Gateway.handle` — SNI peek, then `mitmHTTPS` for `https` / `k8s` family endpoints; passthrough for SQL-family hosts that arrive on `:443` (e.g. `clickhouse_https`)        |
| `:5432`                | `Gateway.handlePostgresConn` — postgres wire-protocol gateway (auth offload + `sql_rule` matching)                                                                         |
| `:53`                  | `Gateway.handleDNSTCPConn` — TCP fallback for the DNS-VIP responder                                                                                                        |
| any port, dst IP ∈ VIP | `Gateway.handleVIPConn` — recovers the agent-dialed hostname from the dnsvip table, picks the endpoint per profile, dispatches to its `ConnEndpointRuntime` (currently SSH; clickhouse_native when bound by hostname) |
| dashboard port         | `http.Serve` against the dashboard mux on a one-shot listener                                                                                                              |
| else                   | `Gateway.tryDirectIPConn` — `ConnIndex.Lookup(dstIP)` to dispatch direct-IP `ConnEndpointRuntime` bindings (e.g. `clickhouse_native` with `hosts = ["172.17.0.1"]`); falls through to `wgRelay` (transparent TCP relay) when no endpoint claims the dst |

UDP dispatch is narrower: `:53` lands on the DNS-VIP responder
(`g.dnsvip.ServeUDP`); other UDP datagrams are dropped today.

Plain HTTP, arbitrary outbound TCP, and any wire protocol whose
plugin hasn't shipped a `ConnEndpointRuntime` yet fall through to
`wgRelay` — transparent TCP relay to the real upstream IP.

## HTTPS MITM

`Gateway.handle` runs once per TCP flow on `:443`:

1. **SNI peek.** `peekSNI` reads up to one TLS record (5-byte header +
   record body), validates the `0x16` content type and `ClientHello`
   handshake type, walks extensions, returns the SNI server name plus
   the buffered prefix. The connection is wrapped with a `peekConn`
   that replays the prefix on the next `Read`.

2. **Endpoint lookup.** `runtime.HostEndpoint(policy, profile, host)`
   maps SNI to a `CompiledEndpoint` if the device's profile has an
   endpoint claiming this host. If not, `defaults.unknown_host` (the
   default is `passthrough`) decides whether to splice or close.

3. **Family dispatch.** `https` and `k8s` endpoints go to
   `mitmHTTPS`. SQL-family endpoints that happen to surface on
   `:443` (today: `clickhouse_https`, schema only) fall through to
   passthrough — the postgres / clickhouse_native / SSH families
   have their own dispatch paths (`:5432`, dnsvip, direct-IP) and
   never reach this branch in the first place.

4. **TLS termination.** Stdlib `crypto/tls.Server` wraps the duplex
   `net.Conn` directly. The leaf cert is minted by `CertCache.mint`
   (P-256, 30-day validity, in-memory cache, signed by the gateway
   CA).

5. **Request loop.** For each `http.Request`, the gateway:
   - Buffers the body (up to 1 MiB) so rules with `body_json` /
     `body_contains` facets can match.
   - Builds a `match.Request` and runs `runtime.MatchRequest` to find
     the rule. For `k8s` endpoints, `runtime.ParseK8sPath` populates
     `K8s` with `verb / namespace / resource`.
   - Runs the rule's `approve = […]` chain (if any) through
     `runApproveChain` — every stage must allow, first deny
     short-circuits to a 403.
   - Honors the rule's verdict (`allow` / `deny` / `…`), strips
     hop-by-hop and proxy-leak headers, asks the credential plugin
     to inject the secret, and round-trips the request.
   - Forces `http/1.1` ALPN upstream and falls back to chunked
     framing on close-delimited responses so peers don't idle waiting
     for EOF.
   - Hands WS upgrades off to a raw byte bridge (`handleWSUpgrade`);
     the stdlib `http.Transport` mangles `101 Switching Protocols`
     enough that Cloudflare's WAF rejects it.

The dialer used for upstream sockets is `Gateway.dialUpstream`, which
runs stdlib TLS by default and lets a credential plugin satisfying
`runtime.TLSCredentialRuntime` (e.g. `mtls`) configure client certs
and a custom root CA pool before the handshake. A separate
`dialBrowserTLS` runs a uTLS Chrome fingerprint for the few endpoints
where Cloudflare WAF rejects plain-Go TLS handshakes (currently the
chatgpt.com WS upgrade).

## CA certificate management

The CA is a P-256 ECDSA self-signed cert with `CN=clawpatrol gateway
CA` and 10-year validity. Files live in `cfg.CADir`:

- `ca.crt` — PEM-encoded certificate (mode `0o644`)
- `ca.key` — PEM-encoded EC private key (mode `0o600`)

`clawpatrol init-ca DIR` writes a fresh pair. The gateway loads the
existing pair on every start; minting one when missing is the
operator's responsibility (the systemd unit and onboard wizard call
`init-ca` once on first boot).

Per-host leaf certs are P-256 ECDSA, signed by the CA, with a single
DNS SAN matching the SNI. They're cached in memory keyed by hostname;
there is no on-disk leaf cache and no LRU bound — the cache grows
unboundedly until restart. Typical agent traffic hits only a few
dozen distinct hosts, so the unbounded shape is fine in practice.

## Policy: gateway.hcl

Policy is HCL, parsed by `config/` and compiled into a
`CompiledPolicy` the request-time dispatcher reads. Operational
fields (listen ports, CA dir, dashboard secret, WG block) sit at the
top of the file; everything else is a typed top-level block:

| Block                                | Meaning                                                             |
|--------------------------------------|---------------------------------------------------------------------|
| `defaults {}`                        | Singleton: `unknown_host`, `llm_fail_mode`, `llm_cache_ttl`, `human_timeout`, `human_on_timeout` |
| `approver "<type>" "<name>"`         | Who arbitrates HITL stages (`llm_approver`, `human_approver`)       |
| `policy "<name>"`                    | Reusable LLM-proctor prompt heredoc                                 |
| `credential "<type>" "<name>"`       | Typed handle to a secret (`bearer_token`, `oauth`, `mtls`, …)       |
| `endpoint "<type>" "<name>"`         | Upstream binding (`https`, `kubernetes`, `postgres`, `clickhouse_*`, `ssh`)|
| `rule "<type>" "<name>"`             | One policy decision targeting one or more endpoints                 |
| `profile "<name>"`                   | Endpoint membership list — a device's profile gets exactly these    |

Names live in one flat namespace; references are bare names
(`endpoint = github`, not `endpoint.github`). HCL `gohcl` decodes
operational fields; everything below `gateway {}` runs through a
two-pass loader:

- **Pass 1** extracts policy blocks and builds a symbol table so
  forward references resolve cleanly.
- **Pass 2** dispatches each block to its plugin (registered via
  `config.Register` from `config/plugins/{approvers,credentials,endpoints,rules}/`),
  decodes the body against the plugin's struct, walks declared refs,
  validates, and calls `Build` to produce the canonical body the
  runtime reads.

The compiled output is a `CompiledPolicy` keyed by name plus
per-endpoint rule lists, secret-slot metadata, and a `ConnIndex` (see
below). The dashboard renders this directly; rules don't get
re-parsed at request time.

## Credential plugins

A `credential "<type>" "<name>" {}` block declares one credential
shape. The plugin's body satisfies one or more runtime interfaces in
`config/runtime/runtime.go`:

| Interface                  | Used by                                  | What it does                                                                                                |
|----------------------------|------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| `HTTPCredentialRuntime`    | `bearer_token`, `header_token`, `cookie_token`, OAuth-flow shapes | Mutate `req.Header` (and sometimes URL) before the upstream round-trip                                      |
| `TLSCredentialRuntime`     | `mtls`                                   | Add client cert / replace `RootCAs` on the upstream `tls.Config`                                            |
| `PostgresCredentialRuntime`| `postgres` credential plugin             | Rewrite the `StartupMessage` password before the upstream connect                                           |
| `PostgresAuthCredential`   | `postgres` credential plugin             | Hand `(user, password)` to the postgres endpoint runtime so the agent never sees auth                       |
| `ClickhouseAuthCredential` | `clickhouse` credential plugin           | Hand `(user, password)` to the `clickhouse_native` runtime so it can swap placeholder bytes in the Hello packet |
| `sshproto.AuthCredential`  | `ssh` credential plugin                  | Hand SSH user / private key / password / host pubkey to the SSH endpoint runtime for upstream auth replay   |

Schema-only credential types (e.g. `slack`, `telegram`, `gemini`)
declare slots and rule hooks but leave `Runtime` nil; their requests
forward verbatim and policy alone gates them.

### How injection works

Each credential plugin's `InjectHTTP` writes to one specific slot on
the request:

```go
// bearer_token
req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))

// header_token
req.Header.Set(h.Header, h.Prefix+string(sec.Bytes))

// cookie_token
// rewrites a single named cookie in the Cookie header
```

Secret bytes only flow into the exact header the plugin targets, and
no global pass scans the request for placeholders to substitute. That
makes anti-exfil a structural property rather than a blocklist
problem: there's nothing to leak through, because no code path
mutates a header the plugin didn't pick.
(`config/plugins/credentials/util.go` defines plumbing-level
placeholder strings like `phClaude`, `phOpenAI`, `phGitHub` for
agent-side env-var stand-ins; the gateway's `Authorization`-header
overwrite renders any echoed placeholder inert before the request
leaves the gateway.)

For multi-credential endpoints (e.g. an `https` endpoint binding
both a personal and a service-account token), the endpoint plugin's
`PlaceholderDetector` looks at the agent's request and picks which
credential entry applies. Singular bindings short-circuit before
that check.

## Endpoint plugins

`endpoint "<type>" "<name>" {}` declares an upstream binding. Each
plugin sits in one of four families; the family code is what the
dispatcher and the rule-type checker key off. The
[`config/README.md`](../../config/README.md) endpoint table is the
canonical HCL syntax reference; this section is the runtime-side
view.

| Family code | Plugin types                                        | Runtime contracts                                                                          | Dispatch path                                                                          |
|-------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| `https`     | [`https`][ep-https]                                 | `HTTPCredentialRuntime` (+ `TLSCredentialRuntime` for mTLS on the upstream dial)           | `:443` → SNI peek → `mitmHTTPS`                                                        |
| `k8s`       | [`kubernetes`][ep-k8s]                              | `HTTPCredentialRuntime`; URL parses to `verb / namespace / resource` for `k8s_rule`        | `:443` → SNI peek → `mitmHTTPS`                                                        |
| `sql`       | [`postgres`][ep-pg]                                 | `ConnEndpointRuntime` + `PostgresCredentialRuntime` / `PostgresAuthCredential`             | `:5432` → `handlePostgresConn`                                                         |
| `sql`       | [`clickhouse_native`][ep-chn]                       | `ConnEndpointRuntime` + `ClickhouseAuthCredential`                                         | hostname → VIP → `handleVIPConn`; IP-literal hosts → `tryDirectIPConn`                 |
| `sql`       | [`clickhouse_https`][ep-chh]                        | schema only today (no runtime); rides the HTTPS path but family-switches to passthrough    | `:443` → SNI peek → splice                                                             |
| `ssh`       | [`ssh`][ep-ssh]                                     | `ConnEndpointRuntime` + `sshproto.AuthCredential`                                          | hostname → VIP → `handleVIPConn` (any dst port)                                        |

[ep-https]: ../../config/plugins/endpoints/https.go
[ep-k8s]: ../../config/plugins/endpoints/kubernetes.go
[ep-pg]: ../../config/plugins/endpoints/postgres.go
[ep-chn]: ../../config/plugins/endpoints/clickhouse_native.go
[ep-chh]: ../../config/plugins/endpoints/clickhouse_https.go
[ep-ssh]: ../../config/plugins/endpoints/ssh.go

Rule families bind to endpoint families: `http_rule` → `https`,
`sql_rule` → `sql` (postgres + clickhouse_*), `k8s_rule` → `k8s`.
SSH endpoints have no rule type today — auth replay through the
credential plugin is the policy boundary; rule-driven matching on
SSH channels lands in a follow-up.

### ConnIndex: dstIP → endpoint

Endpoint plugins whose body satisfies `runtime.ConnRouter` declare
which `host[:port]` tuples they claim. At policy load,
`runtime.BuildConnIndex` resolves each declared host to IPs and
builds a `dstIP → []*CompiledEndpoint` map. The promiscuous
forwarder uses this index to map the WG-side dst IP back to a
candidate endpoint; when multiple endpoints claim the same IP
(writer + readonly RDS), `pickEndpointForProfile` filters by the
device's profile and falls back to `firstPostgresEndpoint` for
single-tenant configs without explicit DNS.

### ConnEndpointRuntime: postgres / clickhouse_native / ssh

The non-HTTPS families share a runtime shape. The plugin's
`Runtime` field implements `ConnEndpointRuntime`, its endpoint body
implements `ConnRouter`, and the dispatcher hands an inbound conn
to `HandleConn` after picking the right endpoint per the device's
profile. Each family's wire-protocol specifics differ, but the
secret-injection model is the same one as HTTPS: the credential
plugin owns one well-defined slot, the runtime swaps placeholder
bytes for real ones, and nothing else mutates the wire bytes.

- **postgres** terminates SCRAM/cleartext upstream using the
  credential's `(user, password)` — the agent never participates
  in the auth handshake — synthesizes `AuthenticationOk` for the
  agent, and runs each subsequent `Query` / `Parse` through the
  `sql_rule` matcher. Denied statements get an `ErrorResponse +
  ReadyForQuery` so the session continues.
- **clickhouse_native** parses the Hello packet, swaps placeholder
  bytes in the agent-supplied `(username, password)` for the real
  values via `ClickhouseAuthCredential`, emits one connection
  event, and pipes bidirectionally. TLS is terminated on both hops
  when `tls = true`. SQL-statement parsing lands in a follow-up;
  today the plugin gates on connect-time policy only.
- **ssh** acts as an SSH server toward the agent (any auth —
  WireGuard is the trust boundary) and an SSH client toward the
  upstream, replaying the credential's `user` / `key` / `password`
  and splicing channels and global requests both directions. The
  gateway-side host key is a lazy-generated ed25519 keypair under
  `<ca_dir>/ssh/<endpoint>.key`; interactive sessions, exec, port
  forwarding, and SFTP all work without per-channel logic.

### DNS-VIP for non-SNI families

SSH and `clickhouse_native` carry no SNI / Host header, so the
dispatcher can't recover the agent-dialed hostname from the dst IP
alone. Their plugins return `RequiresVIP() = true`; the `dnsvip`
allocator (in [`dnsvip/`](../../dnsvip/)) assigns a stable virtual
IP per declared hostname at policy build and persists the table to
`<state_dir>/dnsvip.json` so VIPs survive restart. The gateway's
in-process DNS responder serves UDP/TCP `:53`: queries for VIP-
bound hostnames return the allocated VIP; everything else is
forwarded to the upstream resolver verbatim, with A/AAAA responses
passed through unchanged. The WG forwarder routes any port on a
VIP through `handleVIPConn`, which recovers the hostname from the
VIP table and dispatches into the matching `ConnEndpointRuntime`.
IP-literal `hosts` entries skip dnsvip entirely (no DNS query to
intercept) and reach `HandleConn` via `tryDirectIPConn`.

## Rules and approval

`rule "<type>" "<name>" {}` is one policy decision targeting one or
more endpoints. Rule types are protocol-typed: `http_rule` for
`https` endpoints, `sql_rule` for `postgres` / `clickhouse_*`,
`k8s_rule` for `kubernetes`. The rule's body declares a `match`
(method/path/header/body facets) and an `outcome` (`verdict` plus
optional `approve = […]` chain plus `reason`).

`runtime.MatchRequest(ep, req)` walks the endpoint's compiled rules
in source order and returns the first match. The gateway then:

- runs the approve chain through `runApproveChain` if non-empty;
- short-circuits to 403 on the first non-allow verdict;
- honors the rule's verdict (`allow` continues, `deny` returns 403);
- forwards upstream after the credential plugin's injection.

Approvers live in `config/plugins/approvers/`:

- `dashboard` — built-in (no HCL block needed). Pushes a pending
  entry onto the in-memory `HITLPool`; the dashboard SPA reads via
  SSE and writes verdicts via `PUT /api/hitl/decide`.
- `human_approver` — Slack / Discord / Telegram / etc., delivered via
  whatever credential plugin satisfies `runtime.HITLNotifier`. Uses
  the same `HITLPool` so the dashboard and the side channel both
  resolve the same pending entry.
- `llm_approver` — synchronous LLM call via the configured `policy
  "<name>"` heredoc; verdict caching is bounded by
  `defaults.llm_cache_ttl` and failure semantics by
  `defaults.llm_fail_mode`.

## Profiles as the tenancy unit

`profile "<name>" { endpoints = [...] }` binds a device's identity to
an endpoint set. The profile is the credential-bucket key: when the
gateway looks up a credential, the lookup is keyed by `(credential
name, profile)`, not by user. The dashboard scopes everything to the
operator-selected profile.

`Gateway.profileFor(peerIP)` resolves a WG peer to its profile by
walking the onboard registry. Devices land in a profile at onboard
time (`apiOnboardClaim`); operators can re-assign via
`POST /api/clients/:id/profile`.

WG-mode deployments have no per-request owner identity: requests are
attributed to the device's profile, not to a user. The optional
`gateway.control = "tailscale"` mode does carry a user/owner concept
— Tailscale's whois lookup maps tunnel IPs to login names — see
`Gateway.ownerForRequest`.

## Secret store

`gatewaySecretStore` (in `secrets.go`) is the `runtime.SecretStore`
the gateway hands to credential plugins. Lookup order per
`(credential, profile)`:

1. **`credential_secrets` table.** Slot rows the operator pasted into
   the dashboard. Single-slot credentials fill `Secret.Bytes`;
   multi-slot fill `Secret.Extras`.
2. **`OAuthRegistry`.** For OAuth-flow credentials (Anthropic Claude,
   OpenAI Codex, GitHub, …): returns a refreshed access token, with
   refresh state persisted in the `credentials` table.
3. **`EnvSecretStore`.** Last-resort `CLAWPATROL_SECRET_<NAME>`
   env-var fallback for operator-managed secrets, with
   `CLAWPATROL_SECRET_<NAME>_{CERT,KEY,CA}` and `@/path/to/file`
   shorthand for mTLS bundles.

OAuth-flow registration runs at policy-load time via
`registerOAuthCredentials`: it walks every credential plugin
implementing `OAuthFlowProvider`, copies the flow shape (auth/token
URLs, scopes, client id) onto the registry, and rehydrates persisted
tokens from the `credentials` table.

## Persistence

State lives in SQLite at `<oauth_dir>/clawpatrol.db`. Migrations are
embedded SQL files in `migrations/sqlite/`, applied in numbered order.
Tables:

| Table                | Purpose                                                                              |
|----------------------|--------------------------------------------------------------------------------------|
| `devices`            | Onboarded peer identity: `id` (WG IP) → `name`, `profile`, `blocked`, `last_seen_ns` |
| `wg_peers`           | `(pubkey, ip)` registrations for the wireguard-go device, written before claim       |
| `credentials`        | Per-`(credential id, profile)` OAuth tokens (access, refresh, expiry)                |
| `credential_secrets` | Per-`(credential, profile, slot)` raw secret bytes for non-OAuth credentials         |
| `actions`            | Append-only request event log: mode, agent IP, host, method, path, status, bytes, action, reason, sample SHAs |

HCL is the source of truth for *policy*. SQLite persists *state* —
device identities, peer key allocations, credential material, and
request history. The dashboard never edits HCL; it edits SQLite.

## Hot reload

`Gateway.watchConfig` polls the config file's mtime every 3 seconds.
On change it re-decodes the HCL, atomically swaps in the new
`CompiledPolicy` (via `g.policy.Store`), rebuilds the `ConnIndex`,
re-registers OAuth credentials, and hot-swaps the operational
`*config.Gateway` so `admin_email` / `public_url` /
`dashboard_secret` reads pick up immediately.

Listen ports, `ca_dir`, `oauth_dir`, and the `gateway {}` block
(WireGuard / Tailscale wiring) are *not* hot-applied — changes to
those fields are logged but require a restart.

The gateway has no `SIGHUP` handler; mtime polling drives reload.
(The child-process supervisor inside `clawpatrol run` does forward
`SIGHUP` to the wrapped agent, but that's on the agent host, not the
gateway.)

## Dashboard and API

The dashboard is a React SPA served by `newWebMux` on
`info_listen` (default `0.0.0.0:8080`). The same mux is also wired
into the WG forwarder for in-tunnel access on the dashboard port —
operators on the WG network reach the dashboard at the gateway's WG
IP without leaving the tunnel.

Dashboard auth requires exactly one of:

- `dashboard_secret = "<long random string>"` — production. The
  dashboard issues a session cookie after the operator presents the
  secret.
- `insecure_no_dashboard_secret = true` — testing only. Anyone who
  can reach the dashboard URL gets in. Logged loudly on every
  config (re)load.

If neither is set, the dashboard refuses to serve anything and
returns a misconfiguration page on every request.

The on-the-wire API is stable enough to survive operator scripts but
isn't versioned for external consumers; consult `web.go`,
`onboard.go`, and `oauth.go` for the current routes (onboard
start/lookup/approve/claim/poll, HITL pending/decide, profiles,
endpoints, credentials, request log).

## Observability

Every terminal request emits an `Event` to:

- the SSE sink (`g.sink`), consumed by the dashboard's "live" tab and
  written to `actions` for the request log;
- the OpenTelemetry recorder (`otelRecordVerdict`,
  `otelRecordRequest`), feeding a Prometheus-style histogram of
  request duration tagged by action / status.

There is no built-in retention sweep on the `actions` table — it
grows indefinitely until the operator truncates it. The dashboard's
"backlog replay" reads the most recent ~500 rows on connect.
