# clawpatrol — `dry-run` design proposal

> **Status:** design / discussion. No implementation yet. Open
> questions in §3 must be resolved before code lands.

## Goal

Add a CLI subcommand that lets an operator try a candidate HCL
policy against the **live production gateway**, scoped to a single
session, with no upstream traffic actually forwarded:

```
clawpatrol dry-run --config ./candidate.hcl <cmd> [args...]
```

Same shape as `clawpatrol run`, but every action the wrapped agent
generates is matched against the candidate config rather than the
gateway's global config, and the gateway returns synthesised
responses instead of proxying. When the session ends, the candidate
config is dropped.

The point is iteration speed: operators currently have to push a
full config reload to test a rule change, which affects every
device. Dry-run lets one operator probe a candidate config from
their own machine without touching anybody else's traffic.

## 1. What I read

Citations are file:line in `denoland/clawpatrol@main`.

### 1.1 Single policy-dispatch point exists (HTTPS path)

`runtime.MatchRequest(ep, req)` at `config/runtime/dispatch.go:45`
walks an endpoint's priority-sorted rule list and returns the first
match. The HTTPS / K8s path calls this exactly once per request at
`main.go:1632` after building a `match.Request` containing
`Family`, `Method`, `URL`, `Headers`, `Body`, `PeerIP` and (for
k8s) the parsed path.

The compiled policy is held atomically on the `Gateway` struct and
read via `g.Policy()` (atomic load of `*config.CompiledPolicy`).
SIGHUP / mtime-based reload swaps it in via `g.policy.Store(cp)`,
so request handlers always see a consistent snapshot for the
lifetime of one request.

### 1.2 SQL plugins do their own matching

postgres / clickhouse_native do **not** route through
`MatchRequest`. They walk rules themselves inside their per-conn
handlers (`main.go:1169` for postgres). This is relevant for
acceptance criteria — the first iteration probably can't cover
every endpoint family with one shim; HTTPS is the cheapest
beachhead.

### 1.3 Session identity at the gateway is `PeerIP`

`peerIP(c net.Conn)` at `main.go:2026` extracts the canonical IPv4
form of the WG remote address and is the universal session key.
`g.profileFor(pip)` (`main.go:319`) and the onboard registry
(`onboard.go:121`) are both keyed by it. Every per-request lookup
flows through this.

### 1.4 But "session" and "PeerIP" are not 1:1 — see §3.A

This is the central design problem. It deserves its own section
below. The short version: **one Linux host, one PeerIP, even when
the operator runs N concurrent `clawpatrol run`s.**

### 1.5 Config compile is reusable from a request handler

`loadConfig(path)` at `main.go:92` is `config.Load() +
config.Compile()`. `Compile()` (`config/compile.go:194`) returns a
fresh `*CompiledPolicy` with no global mutation. It's safe and
cheap enough to call on demand for a candidate-config upload (mtime
poller currently runs it every 3s anyway).

A `*CompiledPolicy` is on the order of 10–100 KB for a real
config. Holding one extra per active dry-run session is fine.

### 1.6 Existing CLI ↔ gateway control channel

The dashboard's API listener (routes registered at `web.go:208+`)
already speaks JSON over the same listener as the proxy and gates
mutating routes on `dashboard_secret` (cookie or
`X-Clawpatrol-Secret` header — see `checkDashboardSecret`).
Existing precedent for "client uploads HCL, gateway compiles":
`POST /api/config/preview` and `POST /api/config/save` already do
this for the global config (with revision tokens to prevent
clobbering).

There is no per-device API token usable from the CLI today —
`api-token` files exist on devices but are scoped to env-pushdown
flows, not generic API auth.

### 1.7 Subcommand wiring

CLI subcommands live as a flat `switch os.Args[1]` in `main.go`
(around line 2000), each delegating to a `runFoo(args)` in a
sibling file (`run_linux.go`, `onboard.go`, etc.). Adding
`dry-run` is a one-line switch case + a new `dry_run.go`.

## 2. Proposed architecture

```
┌──────────────────────────────┐         ┌─────────────────────────────────┐
│  operator's host             │         │  gateway                        │
│                              │         │                                 │
│  clawpatrol dry-run          │         │  POST /api/dry-run/sessions     │
│   --config candidate.hcl     │ ──HCL──▶│   { hcl, ttl }                  │
│   <cmd> [args...]            │         │   → compile via                 │
│                              │ ◀─token─│     config.Load()+Compile()     │
│  ┌────────────────────────┐  │         │   → mint session key            │
│  │ tunnel established     │  │         │   → store {key→CompiledPolicy}  │
│  │ with session key       │──tunnel──▶│   → return session token        │
│  │ (see §3.A)             │  │         │                                 │
│  └────────────────────────┘  │         │  per-request dispatch:          │
│                              │         │   if session has dry-run        │
│  exec <cmd>                  │         │     policy attached:            │
│   └─ generates requests      │         │     match against candidate,    │
│                              │         │     synthesise response,        │
│                              │         │     tag event { dryRun: true }  │
└──────────────────────────────┘         │   else: normal path             │
                                         │                                 │
                                         │  session-end:                   │
                                         │   drop {key→CompiledPolicy}     │
                                         └─────────────────────────────────┘
```

Concrete plumbing:

- **CLI** (`dry_run.go`, new file): `flag.FlagSet` parses
  `--config`; reads HCL bytes; POSTs them to the gateway's API;
  receives a session token; establishes the tunnel (delegating to
  the same code path as `clawpatrol run`) wired with the session
  token; execs the wrapped command. Whole-machine devices are
  rejected up front (see §3.B).
- **Gateway API**: `POST /api/dry-run/sessions` handler in
  `web.go` accepting `{hcl, ttl}` and returning
  `{sessionToken, expiresAt}`. Auth: §3.E.
- **Gateway state**: a new field on `Gateway`, e.g.
  `dryRun *dryRunRegistry`, mapping session-key →
  `*config.CompiledPolicy` plus expiry. Single mutex, copy-out
  semantics (caller gets a pointer to an immutable
  `CompiledPolicy`).
- **Dispatch hook**: at `main.go:1632`, before
  `runtime.MatchRequest(ep, mreq)`, do
  `if dr := g.dryRun.Lookup(sessionKey); dr != nil { ep =
  dr.EndpointFor(host, profile); mreq.DryRun = true }`. The
  request continues through `MatchRequest` against the candidate
  endpoint definition.
- **Response synthesis**: when `mreq.DryRun` is true, replace the
  upstream dial with a synthesiser per verdict (§3.C).
- **Event tagging**: stamp `Event.DryRun = true` so the dashboard
  and event sink can filter / badge dry-run actions.
- **Cleanup**: TTL sweep (e.g. 5 min idle) plus an explicit
  `DELETE /api/dry-run/sessions/{token}` the CLI calls on clean
  exit.

## 3. Open questions (please answer before code)

### A. How does the gateway distinguish concurrent sessions on one host?

This is the biggest one and the bead's framing ("session keys off
WG peer ID") is incomplete. On Linux, `clawpatrol run`
(`run_linux.go:68`) reads `~/.config/clawpatrol/wg.conf` written
by `join` — the same WG private key for every invocation. Two
concurrent `run`s from the same host therefore share one PeerIP at
the gateway. macOS is even more collapsed: all wrapped processes
funnel through the macOS extension's single shared WG tunnel and
appear under one peer.

PeerIP alone cannot tell us whether a request came from a dry-run
session or from a regular one running in parallel.

Three plausible directions:

1. **Mint an ephemeral WG peer per dry-run session.** The new
   `POST /api/dry-run/sessions` issues a fresh WG keypair + IP;
   the CLI brings up its own short-lived tunnel scoped to just
   the wrapped command's namespace (Linux) or hands the helper a
   one-off conf (macOS). Each dry-run gets a unique PeerIP, the
   gateway's existing PeerIP-keyed dispatch needs no schema
   change, and dropping the peer at session end is a clean teardown
   signal.
   Cost: a new gateway code path that mints+revokes ephemeral peers
   without going through the `join` approval flow.
2. **In-band session token in request metadata.** CLI injects e.g.
   an `X-Clawpatrol-DryRun: <token>` header. Works for HTTPS,
   doesn't work for postgres / clickhouse / non-HTTP without a
   per-protocol shim. We'd ship HTTPS dry-run first.
3. **Per-session src-port marking.** CLI's namespace SO_MARKs its
   sockets / picks a known src-port range; gateway derives session
   from `(PeerIP, src_port_range)`. Brittle — kernels reuse ports
   freely.

**Recommendation: (1).** It is the only option that keeps PeerIP
the universal session key, doesn't require per-plugin protocol
knowledge, and gives us a clean disconnect signal. Worth the new
ephemeral-peer endpoint.

**Decision needed:** is (1) acceptable, or do you want (2) and
explicit "HTTPS-only first" scoping?

### B. Whole-machine mode

`--whole-machine` joins (`login.go:573+`) install a persistent
`wg-quick` interface routing all host traffic through one peer.
There is no per-process boundary. Dry-run on whole-machine would
mean "every packet on this host gets matched against the candidate
config," which is more like a global config swap than a session
test.

**Recommendation:** reject `clawpatrol dry-run` on a whole-machine
device at CLI-time with a clear message ("this host joined in
whole-machine mode; dry-run is per-process only — re-join without
`--whole-machine` to use it"). Out of scope for this iteration.

**Decision needed:** confirm reject, or do we want a degraded
"applies to all host traffic" mode for whole-machine?

### C. Response synthesis per verdict

For the four verdict types:

- **deny** — gateway returns the same shape it would in prod
  (HTTP 4xx, postgres `ErrorResponse`, etc.). No question.
- **allow** — must return *something* so the wrapped agent can
  keep running. Options:
  - HTTP 200 + empty body + a `X-Clawpatrol-DryRun: allowed`
    marker header. Cheapest, but the agent may break on missing
    expected fields.
  - Per-protocol minimal "OK" (HTTP: 200/empty; postgres: a
    `ReadyForQuery` after no-op; clickhouse_native: empty `EndOfStream`).
    Slightly more work, much friendlier to real agents.
  - Forward to an operator-configured mock upstream.
    Powerful, much bigger scope.
- **approve** (HITL) — running approver chains under dry-run is
  wrong (would page humans). Three options: auto-deny, auto-allow
  + tag `would-have-required-approval`, or run only the LLM
  pre-stage and skip the human stage.
- **passthrough** (`unknown_host`) — same shape as allow.

**Recommendation:** per-protocol minimal OK for `allow` /
`passthrough`, and **auto-allow + `wouldRequireApproval: true` tag
on the event** for `approve`. That gives operators "would this
config let the agent get further than the prod config does" as
useful signal without paging anyone. Mock upstream is a follow-up
feature.

**Decision needed:** confirm `approve → auto-allow + tag`.

### D. Server-side state divergence

A would-have-run `INSERT` doesn't actually run, so a follow-up
`SELECT` won't see the row. The agent's behaviour during dry-run
diverges from real prod. This is fundamental to the contract — I'll
document it explicitly in the help text and the design comment so
operators don't misread dry-run as a faithful end-to-end replay.

**Decision needed:** none, just confirming we accept the
divergence.

### E. Auth on the upload endpoint

Two reasonable choices:

- **`dashboard_secret`** — reuses existing auth, identical to
  `/api/config/preview`. But that secret is admin-scoped; an
  operator who doesn't have the dashboard secret today can't run
  dry-run, which feels backwards (any device user should be able
  to test policies for their own session).
- **Same auth as the device's normal traffic.** The CLI is
  already running under a joined identity (the WG peer
  authenticates by key); we'd let any onboarded peer upload a
  candidate config for its own session.

**Recommendation:** the second. Dry-run is a "test policy for
*me*" operation; gating it behind the admin secret is too strict.

**Decision needed:** confirm device-scoped auth, or do we want
admin-only?

### F. Config-discard timing

- Linux ephemeral peer: drop on WG handshake timeout (~3 min idle)
  or explicit CLI cleanup call.
- macOS: NE process termination → CLI cleanup call.
- TTL sweep as a fallback in case both signals are missed.

**Decision needed:** is a 5-minute idle TTL the right fallback?
Could be longer (15 min) for slow agents.

### G. Logging / metrics contamination

Dry-run actions should land in the same event sink/store so the
dashboard can render them, but tagged `dryRun: true` so they don't
contaminate real-traffic metrics (allow rate, deny rate, latency
SLOs). The dashboard rendering is a follow-up; the tag itself
lands here.

**Decision needed:** confirm tag-but-store.

## 4. Proposed scope for the first PR

After the above questions are answered, the implementation PR should:

- Add `clawpatrol dry-run` subcommand (Linux per-process + macOS
  per-process; reject whole-machine).
- Add the chosen session-keying mechanism from §3.A.
- Add `POST /api/dry-run/sessions` (and `DELETE /sessions/{id}`)
  with the chosen auth from §3.E.
- Hook dispatch at `main.go:1632` to consult the dry-run registry
  before falling through to the global `MatchRequest` path.
- HTTPS path only for verdict synthesis in v1.
- Event tagging (`Event.DryRun bool`).
- Tests: per-session config attachment & TTL drop; HTTPS dry-run
  end-to-end with a fixture candidate config asserting (a) no
  upstream dial happened, (b) verdict came from candidate config,
  (c) registry empty after teardown.

Out of scope for v1: postgres / clickhouse_native dispatch
(separate beads), dashboard UI for dry-run sessions, mock upstream,
config-vs-config diffing, time-travel replay.

## 5. References

- Bead: `cl-d9d`
- Central dispatch: `config/runtime/dispatch.go:45`,
  `main.go:1632`
- Session keying: `main.go:319`, `main.go:2026`,
  `onboard.go:121`
- Config load/compile: `main.go:92`, `config/compile.go:194`
- Existing config-upload precedent: `web.go:222`
  (`/api/config/preview`, `/api/config/save`)
- Linux per-process: `run_linux.go:52`
- macOS per-process: `run_darwin.go:43`
- Whole-machine join: `login.go:573`
