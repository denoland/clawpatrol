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

## CLI shape and command grouping

Today every command is flat: `gateway`, `join`, `run`, `validate`,
`test`, `plugins`, `env`, `status`, `uninstall`, plus internal
entry points the daemon re-execs. Adding `admin` raised the question
of grouping everything by where it runs. The layout below is the
outcome of a two-round design debate with a second reviewer; the
alternative of grouping every command, including the pre-existing
ones, is under consideration and shown afterwards.

### Recommended: flat fast paths, grouped toolboxes

```
clawpatrol
  gateway <config.hcl>                              canonical
  join [flags] <gateway-url>                        canonical
  run [--no-auto-expose] -- <cmd> [args...]         canonical
  config                                            group
    validate <config.hcl>
    test <config.hcl> <fixture-or-dir>
    plugins install|update|lock|info|approve ...
  agent                                             group
    join ...                                        documented alias of join
    run ...                                         documented alias of run
    env | status | uninstall
  admin [--server URL] [--json] [--password-file P] group
    join approve <code> [--profile NAME]
    device list | set-profile <dev> <profile> | delete <dev>
    credential list | set | clear | connect | disconnect
    config apply <file>                             later
  version | help
  internal daemon|relay-supervisor|relay-worker|run-privileged   hidden
hidden permanent aliases: validate, test, plugins, env, status, uninstall
hidden transitional aliases: daemon-internal, relay-supervisor,
  relay-worker, __run-privileged (kept for one upgrade window so an
  old daemon can re-exec a newly replaced binary)
```

Why this shape:

- The three commands that carry the product's identity stay flat
  and canonical. `clawpatrol gateway <file>` is in users' systemd
  units, `clawpatrol join <url>` is what install.sh prints, and
  `clawpatrol run -- claude` is the one-line pitch. Nesting them
  would tax the most-typed path for taxonomy's sake.
- `validate`, `test` and `plugins` operate on a config artifact, not
  on a running gateway, and run in CI or on a laptop; `config` says
  that. Putting them under `gateway` would also make `gateway` both
  a verb and a namespace, so `gateway validate` would collide with a
  config file named `validate`.
- `agent` shows the complete agent-side surface in one place;
  `agent join` and `agent run` exist so `clawpatrol agent --help` is
  a full map, while docs keep using the short forms.
- `admin` names an authorization boundary, not a location: it runs
  from anywhere except an agent context and needs the root
  password. Reusing `gateway` for remote control would leave the
  word meaning both "start this process" and "control that one".
- `admin config apply` (later) sits under `admin` on purpose: local
  artifact operations and remote authenticated mutation are
  different security boundaries and should not share a prefix.
- Aliases kept forever are not deprecations. They are hidden from
  primary help and completion and never warn.
- `internal` gives the re-exec entry points one visibly unstable
  home instead of the current mix of `-internal` and `__` prefixes.

### Under consideration: full grouping

The fully grouped layout, with the flat forms as hidden aliases for
two releases and then removed:

```
clawpatrol
  gateway                                           group
    serve <config.hcl>
  agent                                             group
    join [flags] <gateway-url>
    run [--no-auto-expose] -- <cmd> [args...]
    env | status | uninstall
  config
    validate | test | plugins ...
  admin [server/auth flags]
    join approve | device ... | credential ... | config apply (later)
  version | help
  internal ...                                      hidden
two-release hidden aliases: gateway <file>, join, run, validate, test,
  plugins, env, status, uninstall, old internal spellings
```

Strongest argument for it: the root becomes a stable product map
(gateway, agent, config, admin) with a uniform `<domain> <action>`
grammar, and every namespace can grow without ever consuming a
top-level name again. Strongest argument against: a permanent
ergonomic tax on the most important path, since `clawpatrol agent
run -- claude` is longer and less distinctive than `clawpatrol run
-- claude`, and a real migration cost for every systemd unit, script
and document that invokes `clawpatrol gateway <file>` or `clawpatrol
join`. Whether that trade is worth it is a product decision; the
rest of this note is the same under either layout.

### Verbs (v1)

Each verb maps onto an endpoint that exists today. Verbs are grouped
by resource, so the namespace has room to grow (`admin join list`,
`admin hitl ...`) without renaming anything.

| Verb | Endpoint |
| --- | --- |
| `admin join approve <code> [--profile NAME]` | `POST /api/onboard/approve?code&profile` |
| `admin device list` | `GET /api/state` (agents) |
| `admin device set-profile <device> <profile>` | `POST /api/agents/profile?ip&profile` |
| `admin device delete <device>` | `POST /api/agents/delete?ip` |
| `admin credential list` | `GET /api/status` (integrations: id, type, slots, connected) |
| `admin credential set <id> --slot NAME=VALUE ...` | `POST /api/credentials/set {id, slots}` |
| `admin credential clear <id>` | `POST /api/credentials/clear {id}` |
| `admin credential connect <id> [--extra-scopes a,b]` | `POST /api/oauth/start?id` then `exchange` or `device-poll` |
| `admin credential disconnect <id>` | `POST /api/oauth/revoke {id}` |

`join approve` acts on a pending join request, which is not a device
yet; `device list` shows approved devices only. If listing pending
requests is ever needed it becomes `admin join list`.

Details:

- `<device>` is a tunnel IP or the hostname shown on the dashboard;
  hostnames are resolved client-side from `/api/state` and must be
  unique, otherwise the CLI asks for the IP.
- `<id>` is the credential's HCL name (`bearer_token.github` is
  `github`; the API is keyed by name today). `admin credential list`
  shows ids with their slot names, so the operator does not have to
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
admin device list` with no flags. Configuring a gateway does not
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
  `admin credential list` prints. If per-slot presence turns out to be
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
3. Should `admin join approve` accept the device *hostname* shown on the
   dashboard instead of the code, for the case where the operator is
   approving from a different machine than the one that ran `join`?
