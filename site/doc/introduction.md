# Introduction

Claw Patrol is a firewall for AI agents. It sits between your
agents and the internet, decides what each request is allowed to
do, and stamps real credentials onto the wire so the agent never
holds them.

## The problem

Your AI agent has every API key in plaintext. It talks to GitHub,
Slack, Anthropic, Postgres, Kubernetes, and a dozen other services.
You can’t see what it’s doing, what it’s spending, or where your
credentials end up. One prompt injection — or one model that
hallucinates a `DELETE` — and your secrets exfiltrate or your
production gets touched.

## What Claw Patrol gives you

- **Allow / deny rules** on every outbound request, written in CEL
  against typed variables for the protocol.

- **Protocol-aware, not just HTTP.** Claw Patrol terminates the
  full wire protocol for the systems agents actually touch, so
  rules see what the agent is doing — not just where it’s
  pointed:

  - **Postgres / ClickHouse** — the gateway parses the SQL out of
    the wire protocol. Rules see `sql.verb`, `sql.tables`,
    `sql.statement`. Deny `DROP TABLE`, gate
    `SELECT * FROM api_keys`, restrict an agent to read-only
    verbs.
  - **Kubernetes** — API URLs decompose into `k8s.verb`,
    `k8s.resource`, `k8s.namespace`, `k8s.name`. Deny
    `delete secrets` cluster-wide, allow `get pods` only in
    `dev`, route any write to `kube-system` through a human
    approval.
  - **HTTPS** — `http.method`, `http.path`, `http.headers`,
    `http.body_json` for the REST APIs (GitHub, Slack,
    Anthropic, …). The body is parsed once for JSON endpoints
    so you can match on payload fields, not just shape.

- **Human-in-the-loop approvals** for risky actions — defer
  `kubectl apply -f production` to a Slack approval before the
  request leaves. If the reviewer denies or the approval times out,
  Claw Patrol does not call the upstream service.

- **[Secret injection](/docs/credentials/)** at the wire. The agent
  process holds a token-shaped placeholder
  (`GITHUB_TOKEN=ghp_clawpatrol_placeholder_do_not_use`); the gateway
  swaps it for the real PAT in transit. SDKs read the env var
  normally and never see the real credential.

- **Full audit log** — every request, verdict, and latency,
  searchable in the dashboard, exportable as fixtures for
  regression tests.

## How it fits

Claw Patrol has two pieces:

- A **gateway** — a single Go binary running on a host you control.
  It holds the policy, the credentials, the audit log, and the
  dashboard.
- One or more **devices** — your laptop, a CI runner, a teammate’s
  workstation — that join the gateway over WireGuard. The device
  captures the agent’s outbound flows and tunnels them to the
  gateway, which decides per request what to allow, what to deny,
  what to gate behind a human, and what credential to stamp on.

```
Agent ─→ Device ──WireGuard──→ Gateway ──→ Upstream
                                  │
                                  ├ matches rule
                                  ├ injects credential
                                  └ logs the action
```

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
- [Rules](/docs/rules/) — gating writes behind
  a human or an LLM judge.
- [Security model](/docs/security-model/) — what Claw Patrol does
  and doesn’t protect against.
