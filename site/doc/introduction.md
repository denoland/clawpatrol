# Introduction

Claw Patrol is the firewall for AI agents. It sits between your
agents and the internet, decides what each request is allowed to
do, and stamps real credentials onto the wire so the agent never
holds them.

## The problem

Your AI agent has every API key in plaintext. It talks to GitHub,
Slack, Anthropic, Postgres, Kubernetes, and a dozen other services.
You can't see what it's doing, what it's spending, or where your
credentials end up. One prompt injection — or one model that
hallucinates a `DELETE` — and your secrets exfiltrate, or a
production table gets wiped and the rows aren't coming back.

## What Claw Patrol gives you

- **Allow / deny rules** on every outbound request, written in a
  small expression language (CEL). The variables you can reference
  are typed and protocol-specific — see the per-protocol fields
  below.

- **Protocol-aware.** Rules see what the agent is doing, not just
  where it's pointed. Claw Patrol terminates the full wire protocol
  and exposes the parsed action to your rules:

  - **HTTPS** — `http.method`, `http.path`, `http.headers`,
    `http.body_json` for any REST API (GitHub, Slack, Anthropic, …).
    The JSON body is parsed once so you can match on payload fields,
    not just URL shape.
  - **Kubernetes** — API URLs decompose into `k8s.verb`,
    `k8s.resource`, `k8s.namespace`, `k8s.name`. Deny
    `delete secrets` cluster-wide, allow `get pods` only in `dev`,
    route any write to `kube-system` through a human approval.
  - **Postgres** — the gateway parses the SQL out of the wire
    protocol. Rules see `sql.verb`, `sql.tables`, `sql.statement`.
    Deny `DROP TABLE`, gate `SELECT * FROM api_keys`, restrict an
    agent to read-only verbs.
  - **ClickHouse** — same `sql.*` surface as Postgres, both the
    native and HTTPS wire protocols.

  A plugin API covers everything else: add an endpoint plugin for a
  new wire protocol, a credential plugin for a new secret shape, an
  approver plugin for a new approval channel.

- **Human-in-the-loop approvals** for risky actions. Approvers can
  be a Slack channel, the gateway's own web dashboard, email, or
  any webhook you point it at. Gate `kubectl apply -f production`
  behind a Slack ack, or pause a `DROP TABLE users` until a human
  signs off in the dashboard — the request only leaves once a
  person says yes.

- **LLM-in-the-loop approvals.** Put a model in front of a rule and
  let it judge each request against a prompt you write. Verdicts
  are cached so the same request doesn't re-bill.

- **Secret injection at the wire.** The agent never has the real
  credential; Claw Patrol stamps it on at request time. Depending
  on the protocol the agent sends a placeholder shape, or nothing
  at all — either way the secret stays on the gateway.

- **Full audit log** — every request, verdict, and latency,
  searchable in the dashboard, exportable as fixtures for the
  `clawpatrol test` regression runner so a policy change can't
  silently flip a verdict in CI.

## How it fits

Claw Patrol has two pieces:

- A **gateway** — a single Go binary running on a host you control.
  It holds the policy, the credentials, the audit log, and the
  dashboard. All state lives in one SQLite file; no cloud required.
- One or more **devices** — the machines where the agents run,
  whether a developer workstation or a dedicated host running
  agents 24/7. Claw Patrol runs on each device, captures the
  agent's outbound flows, and tunnels them to the gateway.

A device joins the gateway first — `clawpatrol join` over
WireGuard, or `clawpatrol login` if Tailscale is already your
fabric. From there, two ways to scope what gets captured:

- `clawpatrol run -- <cmd>` wraps a single command (and its
  subprocesses) in a network namespace that captures only its
  traffic; everything else on the device is untouched.
- `clawpatrol join --whole-machine` skips the per-command wrap
  and tunnels every outbound packet on the device through the
  gateway.

<svg viewBox="0 0 940 380" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="clawpatrol request flow: a device tunnels agent traffic to the gateway, the gateway matches a rule, may defer the verdict to an LLM proctor or a human approver (via Slack, the dashboard, email, or a webhook), and on allow injects the real credential before forwarding to the upstream">
  <defs>
    <marker id="ar-intro" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">
      <path d="M0,0 L10,5 L0,10 z" fill="#2a342f"/>
    </marker>
  </defs>
  <style>
    svg text { font-family: ui-monospace, "JetBrains Mono", monospace; fill: #2a342f; }
    .b-intro { fill: #fbf7ee; stroke: #2a342f; stroke-width: 1.5; }
    .f-intro { fill: none; stroke: #6b7770; stroke-width: 1.2; stroke-dasharray: 5 4; }
    .lbl-intro { font-size: 12px; text-anchor: middle; }
    .sm-intro { font-size: 10px; text-anchor: middle; fill: #6b7770; }
    .ttl-intro { font-size: 11px; font-weight: 700; fill: #2a342f; }
    .arr-intro { fill: none; stroke: #2a342f; stroke-width: 1.5; }
  </style>

  <rect class="f-intro" x="20" y="40" width="220" height="160" rx="6"/>
  <text class="ttl-intro" x="30" y="34">device</text>
  <rect class="b-intro" x="40" y="100" width="80" height="40" rx="4"/>
  <text class="lbl-intro" x="80" y="122">agent</text>
  <rect class="b-intro" x="140" y="100" width="80" height="40" rx="4"/>
  <text class="lbl-intro" x="180" y="122">client</text>
  <line class="arr-intro" x1="120" y1="120" x2="140" y2="120" marker-end="url(#ar-intro)"/>
  <line class="arr-intro" x1="240" y1="120" x2="335" y2="120" marker-end="url(#ar-intro)"/>
  <text class="sm-intro" x="287" y="114">tunnel</text>

  <rect class="f-intro" x="335" y="20" width="585" height="340" rx="6"/>
  <text class="ttl-intro" x="345" y="14">gateway</text>

  <rect class="b-intro" x="355" y="100" width="120" height="40" rx="4"/>
  <text class="lbl-intro" x="415" y="118">match rule</text>
  <text class="sm-intro" x="415" y="132">CEL on protocol fields</text>

  <line class="arr-intro" x1="475" y1="120" x2="520" y2="120" marker-end="url(#ar-intro)"/>

  <rect class="b-intro" x="520" y="85" width="120" height="70" rx="4"/>
  <text class="lbl-intro" x="580" y="103">verdict</text>
  <text class="sm-intro" x="580" y="120">allow</text>
  <text class="sm-intro" x="580" y="134">deny</text>
  <text class="sm-intro" x="580" y="148">defer</text>

  <line class="arr-intro" x1="640" y1="100" x2="700" y2="100" marker-end="url(#ar-intro)"/>
  <text class="sm-intro" x="670" y="92">defer</text>

  <rect class="b-intro" x="700" y="60" width="220" height="110" rx="4"/>
  <text class="lbl-intro" x="810" y="80">approver</text>
  <text class="sm-intro" x="810" y="100">
    <tspan x="810" dy="0">LLM proctor (custom prompt; cached)</tspan>
    <tspan x="810" dy="1.5em">human via Slack / dashboard /</tspan>
    <tspan x="810" dy="1.3em">email / webhook</tspan>
  </text>

  <line class="arr-intro" x1="700" y1="140" x2="640" y2="140" marker-end="url(#ar-intro)"/>
  <text class="sm-intro" x="670" y="158">verdict back</text>

  <line class="arr-intro" x1="580" y1="155" x2="580" y2="220" marker-end="url(#ar-intro)"/>
  <text class="sm-intro" x="630" y="190" style="text-anchor:start">on allow</text>

  <rect class="b-intro" x="520" y="220" width="120" height="40" rx="4"/>
  <text class="lbl-intro" x="580" y="240">inject credential</text>
  <text class="sm-intro" x="580" y="254">(real secret)</text>

  <line class="arr-intro" x1="580" y1="260" x2="580" y2="305" marker-end="url(#ar-intro)"/>

  <rect class="b-intro" x="520" y="305" width="120" height="40" rx="4"/>
  <text class="lbl-intro" x="580" y="328">upstream</text>
</svg>

The agent never sees the real credential. The gateway never trusts
the agent.

## Open source

MIT. The gateway, the dashboard, and the plugins are all in one
repo. All state lives in a single SQLite file on the gateway host —
no cloud required. The binary phones home for an update check;
disable with `CLAWPATROL_TELEMETRY=0` or `DO_NOT_TRACK=1`.

## Next

- [Getting Started](/docs/getting-started/) — stand up a gateway
  and join a device in 5 minutes.
- [Architecture](/docs/architecture/) — how interception works.
- [Approval rules](/docs/approval-rules/) — gating writes behind
  a human or an LLM judge.
- [Security model](/docs/security-model/) — what Claw Patrol does
  and doesn't protect against.
