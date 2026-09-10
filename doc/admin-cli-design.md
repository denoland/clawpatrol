# Design: `clawpatrol admin`, configuring a gateway from the CLI

Status: proposal for #811. Nothing here is built.

## Problem

Everything that is not in `gateway.hcl` is done through the
dashboard: pasting credential secrets, connecting OAuth
credentials, approving a joining device, assigning a profile. That
does not fit scripted or fleet setups, and it does not fit an agent
provisioning another agent. #482 prototyped `approve`,
`oauth-start` and `oauth-exchange` subcommands and was closed to
rethink the shape.

## Principles

- **Nothing is stored on the client.** No admin key, no token file,
  no cookie jar. The operator authenticates per invocation.
- **Reuse the dashboard's authentication and API.** The gateway
  already gates every mutation behind the root password (and, on
  the tailnet, the operator allowlist). The CLI is a thin client of
  those endpoints, so it cannot do anything the dashboard cannot.
- **Rules, endpoints and profile definitions stay in HCL.** The CLI
  manages the mutable state the dashboard already owns: secrets,
  OAuth connections, device approval and profile assignment. It is
  not a second config format.
- **Generic over credential types.** One verb sets slots for any
  credential; one verb runs the OAuth connect flow for any OAuth
  credential. No per-provider commands.
- **Small.** Six verbs in v1. Everything else waits for a demand.

## CLI shape

The existing commands are not renamed; the `--help` text is regrouped
so a reader can tell what runs where:

```
gateway   run on the gateway host
  clawpatrol gateway <config.hcl>        run the proxy
  clawpatrol validate <config.hcl>       parse + compile a config
  clawpatrol test <config> <fixtures>    replay action fixtures
  clawpatrol plugins ...                 manage plugins for a config

agent     run on a machine that joins a gateway
  clawpatrol join <gateway-url>
  clawpatrol run -- <cmd> [args...]
  clawpatrol env | status | uninstall

admin     talk to a gateway's API from anywhere but an agent context
  clawpatrol admin [--server URL] [--json] <verb> ...
```

### Verbs (v1)

Each verb maps onto an endpoint that exists today.

| Verb | Endpoint |
| --- | --- |
| `admin approve <code> [--profile NAME]` | `POST /api/onboard/approve?code&profile` |
| `admin devices` | `GET /api/state` (agents) |
| `admin set-profile <device> <profile>` | `POST /api/agents/profile?ip&profile` |
| `admin delete-device <device>` | `POST /api/agents/delete?ip` |
| `admin credentials` | `GET /api/status` (integrations: id, type, slots, connected) |
| `admin credential set <id> --slot NAME=VALUE ...` | `POST /api/credentials/set {id, slots}` |
| `admin credential clear <id>` | `POST /api/credentials/clear {id}` |
| `admin credential connect <id> [--extra-scopes a,b]` | `POST /api/oauth/start?id` then `exchange` or `device-poll` |
| `admin credential disconnect <id>` | `POST /api/oauth/revoke {id}` |

Details:

- `<device>` is a tunnel IP or the hostname shown on the dashboard;
  hostnames are resolved client-side from `/api/state` and must be
  unique, otherwise the CLI asks for the IP.
- `<id>` is the credential's HCL name (`bearer_token.github` is
  `github`; the API is keyed by name today). `admin credentials`
  lists ids with their slot names, so the operator does not have to
  read HCL to know what to set.
- `--slot NAME=VALUE` is repeatable. `NAME=@path` reads a file,
  `NAME=-` reads stdin (one slot only), so a secret need not appear
  in shell history or `ps`. A single-slot credential accepts
  `--slot VALUE` with the name omitted. An empty value clears that
  slot, matching the API.
- `credential connect` drives the OAuth flow the dashboard drives:
  it calls start, prints the authorization URL (or the device code
  and verification URL), and then either waits for the operator to
  paste the redirect URL or code and calls exchange, or polls the
  device flow. It never opens a browser by itself (#545).
- `--json` switches every verb to machine-readable output; without
  it, output is one line per item. Exit code 0 on success, 1 on a
  gateway error (message from the API is printed verbatim), 2 on
  usage errors.

### Server address

`--server URL` or `CLAWPATROL_SERVER`. When neither is given and the
machine has joined a gateway, the URL `join` saved next to the CA
(`~/.clawpatrol/gateway`, or the tailnet-direct URL when present) is
the default, so an operator on their laptop can type `clawpatrol
admin devices` with no flags. Configuring a gateway does not
require being joined to it.

## Authentication

v1 uses the dashboard root password everywhere.

1. The CLI prompts for the password on a TTY (hidden input). In a
   script, `CLAWPATROL_PASSWORD` or `--password-file PATH` supply
   it. There is no `--password VALUE`; secrets on the command line
   end up in shell history.
2. It posts to `/__login` exactly as the browser does and keeps the
   returned `cp_session` cookie in memory for the life of the
   process. Before exiting it calls `/__logout`, so nothing outlives
   the invocation; a crash leaves at most a session that expires on
   its own (`dashboard_session_ttl`, 24 h default).
3. TLS follows WebPKI. A gateway behind Funnel has a public
   certificate; a gateway on the tailnet or on loopback is plain
   HTTP. There is no `--insecure` flag in v1; an operator who
   terminates TLS with a private CA adds it to the system trust.

Why not the tailnet operator identity? In Tailscale mode the
dashboard already recognises tailnet operators for
`/api/onboard/approve`, but every other mutation route is
`authDashboard`, which requires the password regardless. Extending
tailnet-operator identity to the admin routes is a server-side
change with its own review (it widens what a tailnet login can do
without a password); it is listed under later work rather than
assumed by v1. The password path works identically in WireGuard and
Tailscale mode, which is what a first version should do.

Why not a stored token? A long-lived admin token on a laptop is the
thing the principles rule out: it turns any file read on that
machine into gateway control. The per-device `api-token` written by
`join` is scoped to `/api/env-pushdown` and stays that way.

### Agent context

`clawpatrol run` marks its child environment. `admin` refuses to run
when that marker is present, with a message saying why. This is a
guard against an agent being handed operator power by accident (an
operator running an agent from a shell that has `CLAWPATROL_PASSWORD`
set), not a security boundary: an agent that clears its environment
can call the API like anyone else, and the password is what stands
in the way.

## Server-side work

Small. The endpoints exist; the changes are:

- `/api/status` already lists every credential with its type, slot
  metadata and a per-credential "connected" flag, which is what
  `admin credentials` prints. If per-slot presence turns out to be
  needed (which of three slots is still empty), that is one boolean
  per slot added to the existing row.
- `/__login` returns a redirect for browsers; the CLI reads the
  `Set-Cookie` from the redirect response, no change needed. A
  JSON-friendly `401` on bad password already exists for API
  callers.
- Audit: the event log records the dashboard principal (`root`) for
  every mutation. The CLI sends `User-Agent: clawpatrol-admin/<ver>`
  so the log can tell CLI actions from browser actions. Per-operator
  identity in WireGuard mode is the RBAC question (#624), not this
  design.

## Later

- `admin hitl pending | approve <id> | deny <id>` on
  `/api/hitl/*`: easy to add, but the dashboard and Slack cover it,
  and nobody has asked.
- `admin config apply <file>` on `/api/config/apply`: only meaningful
  with `dashboard_config_writes = true`, and it overlaps with the
  config-versioning ideas in #625. Decide together.
- Tailnet-operator identity for admin routes, so operators on the
  tailnet skip the password.
- A local-socket admin path on the gateway host for scripts that run
  there, which would sidestep dashboard auth entirely. Not needed
  while the password path exists.

## Alternatives considered

- **A stored admin API key** (like most CLIs): rejected, see above.
- **Making the `join` api-token an admin credential**: rejected; it
  lives on agent machines by design.
- **A separate binary** (`clawpatrolctl`): rejected; one binary is
  the product and the `admin` group is a few hundred lines.
- **Per-provider verbs** (`oauth-start`, `oauth-exchange`, #482):
  rejected in favour of `credential connect`, which reads the
  credential's declared flow and does the right thing for
  authorization-code and device-code providers alike.

## Open questions

1. Device addressing: is hostname-or-IP enough, or should devices
   get a stable id the CLI can use?
2. Should `CLAWPATROL_PASSWORD` exist in v1 at all, or should scripts
   be pushed to `--password-file`? Env vars leak into child
   processes; files leak into backups. Both are acceptable; picking
   one keeps the surface small.
3. Should `admin approve` accept the device *hostname* shown on the
   dashboard instead of the code, for the case where the operator is
   approving from a different machine than the one that ran `join`?
