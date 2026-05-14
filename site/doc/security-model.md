# Security model

Claw Patrol is a forward proxy that intercepts outbound traffic
(HTTPS, SSH, Postgres, …), injects credentials on behalf of the
agent, and enforces policy. The agent — an AI tool, a script, a
batch job, anything we won't hand raw secrets to — sees the result
of the authenticated operation but never the credential.

This page describes how Claw Patrol stops a hostile agent from
reading injected credentials, using another agent's credentials, or
reaching Claw Patrol's own administrative surfaces.

The agent must not be able to:

- read any injected credential,
- use credentials assigned to a different agent,
- read Claw Patrol's state files (SQLite DB, policy, registrations),
- modify the Claw Patrol binary,
- call Claw Patrol's HTTP API or reach its dashboard.

Two deployment modes: **remote** (agent and Claw Patrol on
separate hosts, isolated by a network) and **local** (same host,
isolated by UNIX users). Remote is strictly stronger.

## Remote mode

Agent host and Claw Patrol host are separate. The agent host
initiates a WireGuard tunnel during onboarding; the tunnel stays
up for the life of the registration.

### Registration

Starts on the agent host, finishes with a human approving in the
Claw Patrol dashboard:

1. Agent host calls Claw Patrol with its public IPv4 + IPv6
   addresses.
2. Claw Patrol records them and issues a **join credential** —
   the only Claw-Patrol-issued secret the agent host ever holds.
3. Agent host brings up the WireGuard tunnel. Tunnel up,
   registration *unapproved*: zero traffic forwarded.
4. Operator approves in the dashboard and assigns one or more
   profiles. Traffic begins flowing.

A leaked registration endpoint is worthless on its own: no human
approval, no credentials, no traffic.

### What lives where

| Host | Holds |
|---|---|
| Agent host | The join credential. Nothing else of value to Claw Patrol. |
| Claw Patrol host | All injected credentials, the state DB, the policy, the dashboard, the HTTP API. |

Because injected credentials never reach the agent host, **the
agent can have root on its own host and still not compromise Claw
Patrol.** This is the strongest property remote mode buys you.

### Traffic flow

Per protocol:

- **HTTPS** — Claw Patrol terminates TLS with a local CA whose
  root was installed in the agent's trust store at onboarding.
  Decrypted, the request is inspected, the credential injected,
  the request re-encrypted with the destination's real cert, then
  forwarded.
- **SSH / Postgres / other authenticated protocols** — Claw Patrol
  completes the upstream authentication handshake with the real
  credential, then proxies the authenticated session back to the
  agent. The agent never participates in auth and never sees the
  credential.
- **Non-credentialled traffic** (public web, DNS) — forwarded
  unchanged.

Non-credentialled traffic is outside the security surface. If the
agent bypasses the tunnel, it gets the same internet it would have
without Claw Patrol — no credential leaks, just no protection.

### Leaked join credential

The join credential can leak: from a backup, shell history, a
compromised process on the agent host. To bound the damage, Claw
Patrol pins each join credential to the **exact** IPv4/IPv6 pair
the agent host presented at registration. A request from a
deviating pair — different v4, different v6, or v6 on a host that
registered with v4 only — blocks the credential in the state DB
and tears down the tunnel. Restoring access takes explicit
re-approval.

Two caveats: IPv6 privacy extensions rotate the source address —
disable them or deploy a stable prefix scheme. And an attacker on
the same NAT shares the public v4, so pinning isn't a standalone
defence; it's a blast-radius limiter for credentials that have
already escaped.

## Local mode

Agent and Claw Patrol on the same host. No network between them,
so the boundary moves into the OS.

**Local mode is strictly weaker than remote.** In remote mode,
nothing on the agent host can hurt Claw Patrol. In local mode,
injected credentials sit on the same physical machine as the
agent, separated only by UNIX permissions.

### UNIX user separation

Two accounts:

- The **agent user** — the agent runs here, normally the primary
  interactive user on a desktop install.
- The **Claw Patrol user** — an unprivileged service account
  created at onboarding; the Claw Patrol process runs here.

The agent user can't read the state DB (owned by the Claw Patrol
user), can't replace the binary (owned by root or the Claw Patrol
user), and can't read the dashboard's access token. Recovering the
token uses `sudo clawpatrol get-token`, which requires a password
the agent can't supply.

### Host preconditions

Two properties must hold; Claw Patrol can't enforce them itself:

- The agent user is not root-equivalent.
- The agent user cannot use `sudo` without a password.

Passwordless `sudo` for the agent user defeats the entire model.

### Defense in depth

Claw Patrol's proxy listener, HTTP API, and dashboard all bind to
loopback only in local mode. UNIX user separation is doing the
real work; loopback bind closes accidental network exposure.

### Pre-existing secrets on the host

A local install lands on a host that likely already contains
credentials the agent user can read — shell dotfiles, credential
helpers, cloud CLI configs, SSH keys. These are outside Claw
Patrol's control. Onboarding offers to import recognised
credentials and delete the originals; anything not recognised or
not migrated stays readable to the agent.

## Isolation between agents

One Claw Patrol instance can serve many agents, each with its own
credentials. A hostile agent must not be able to make Claw Patrol
inject credentials assigned to a different agent.

Claw Patrol enforces this by scoping injection to the originating
registration. Each registration is assigned one or more
**profiles**; each profile names a set of credentials. The
originating registration is identified from the channel the request
arrived on — the WireGuard peer (remote) or the authenticated local
channel (local) — not from anything the agent can claim. From there:

- Only credentials from the originating registration's profiles can
  be injected.
- A request for a service whose credentials live only in another
  registration's profile is treated like a request for a service
  Claw Patrol has no credentials for — forwarded without injection
  or rejected by policy, never signed with the wrong agent's key.

Default-profile auto-assignment is a UX convenience for fresh
registrations; the security-relevant property is the scoping rule
above.

## Out of scope

Claw Patrol does not defend against:

- physical access to the Claw Patrol host;
- compromise of the Claw Patrol host or user — any attacker with
  those privileges holds every injected credential;
- a kernel or hypervisor compromise that bypasses UNIX user
  separation;
- supply-chain compromise of the binary or its build toolchain;
- cross-user side channels (shared-CPU timing, etc.).

## Production hardening

The defaults are tuned for first-boot ergonomics. For production —
in particular limiting the blast radius of a `dashboard_secret`
leak — see [Security hardening](./security-hardening.md):
`--allow-tunnels`, the high-risk confirm gate on `local_command`
additions, `--read-only-config`, and recommended systemd
sandboxing.
