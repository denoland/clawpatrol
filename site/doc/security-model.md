# Security Model

Claw Patrol is a forward proxy that intercepts outbound traffic
(HTTPS, SSH, Postgres, …), injects credentials on behalf of the
agent, and enforces policy. The agent — an AI tool, a script, a
batch job, anything we won’t hand raw secrets to — sees the result
of the authenticated operation but never the credential.

This page describes how Claw Patrol stops a hostile agent from
reading injected credentials, using another agent’s credentials, or
reaching Claw Patrol’s own administrative surfaces.

The agent must not be able to:

- read any injected credential,
- use credentials assigned to a different agent,
- read Claw Patrol’s state files (SQLite DB, policy, registrations),
- modify the Claw Patrol binary,
- call Claw Patrol’s HTTP API or reach its dashboard.

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
  root was installed in the agent’s trust store at onboarding.
  Decrypted, the request is inspected, the credential injected,
  the request re-encrypted with the destination’s real cert, then
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
the same NAT shares the public v4, so pinning isn’t a standalone
defence; it’s a blast-radius limiter for credentials that have
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

The agent user can’t read the state DB (owned by the Claw Patrol
user), can’t replace the binary (owned by root or the Claw Patrol
user), and can’t read the dashboard’s access token. Recovering the
token uses `sudo clawpatrol get-token`, which requires a password
the agent can’t supply.

### Host preconditions

Two properties must hold; Claw Patrol can’t enforce them itself:

- The agent user is not root-equivalent.
- The agent user cannot use `sudo` without a password.

Passwordless `sudo` for the agent user defeats the entire model.

### Defense in depth

Claw Patrol’s proxy listener, HTTP API, and dashboard all bind to
loopback only in local mode. UNIX user separation is doing the
real work; loopback bind closes accidental network exposure.

### Pre-existing secrets on the host

A local install lands on a host that likely already contains
credentials the agent user can read — shell dotfiles, credential
helpers, cloud CLI configs, SSH keys. These are outside Claw
Patrol’s control. Onboarding offers to import recognised
credentials and delete the originals; anything not recognised or
not migrated stays readable to the agent.

## Dashboard and management API

Everything the agent must not reach — credential storage, profile
assignment, human-in-the-loop decisions, registration approval —
sits behind the dashboard’s HTTP API. Network reachability alone
must never grant access to it.

### App-layer auth, on every bind

The dashboard refuses to serve any management endpoint until an
operator credential has been established at the app layer. Network-
layer reachability is treated as cheap defense in depth, never as
the trust boundary. This is non-negotiable: an agent that finds
its way onto the same network as the gateway — including the
tailnet that the gateway joined — must still be denied.

Why we cannot rely on network reachability:

- `clawpatrol join` persists a Tailscale node identity (machine key
  + node key) under `~/.config/clawpatrol/tsnet-client/`. Anyone
  who can read that directory can stand up a tsnet server and
  rejoin the tailnet as the same peer, indefinitely.
- That tailnet peer can route to the gateway’s tailnet IP. Without
  app-layer auth, "I’m on the tailnet" would silently equal "I am
  an operator." It must not.

### First-run root password

On a fresh install the dashboard has no operator yet. The first
request — from anywhere — is redirected to a "set password" form;
the chosen password becomes the bcrypt-hashed `root` row in
`clawpatrol.db`. Subsequent requests must present that password
(via the `cp_dash` cookie or the `X-Clawpatrol-Secret` header).

The first-run window is benign by construction: the dashboard is
the only path that creates credentials / profile assignments /
HITL decisions, and all of those endpoints sit behind the same gate
the first-run flow protects. So no sensitive state can predate the
root password — losing the first-run race to an attacker means
they hold an empty dashboard. Recover with
`clawpatrol gateway --reset-dashboard-password`.

To skip the web first-run entirely, set the password from the CLI
before the dashboard ever serves a request:

```
clawpatrol gateway --set-dashboard-password '<pw>' gateway.hcl
```

### Tailnet operator allowlist (tailscale block)

When the `tailscale {}` block is declared the gateway can additionally
accept requests on the strength of a Tailscale whois identity, gated
by an explicit allowlist inside the same block:

```hcl
tailscale {
  authkey   = "{{secret:TS_AUTHKEY}}"
  operators = ["alice@example.com", "*@example.com"]
}
```

The gateway pulls the whois login directly off the tsnet socket
(`LocalClient.WhoIs`), so this is a kernel-attested per-peer
identity, not a forgeable header. Tagged devices — the shape
operators use for agent service accounts (`tag:cp-agent`) — return
their tag name from whois, not a user login, so a `*@example.com`
wildcard never matches an agent.

Allowlist auth composes with password auth: either gets a request
in. The first-run password is still mandatory, so an operator can
always fall back to it (and tests / break-glass paths don’t depend
on a working tailnet).

### Untagged-key prohibition

A subtle failure mode worth calling out: if the gateway ever minted
a Tailscale auth key with an empty `tags` list, the resulting node
would be "owner-associated" — whois on its requests would return
the OAuth client owner’s user login, not a tag. With
`tailscale { operators = ["*@example.com"] }` configured, that node
would silently match the allowlist and inherit operator powers.

The auth-key minting path
(`onboard.go` → `mintTailscaleAuthKey`) refuses to call Tailscale’s
create-key API with an empty tag list — it both defaults to
`tag:client` and errors out if the default is somehow stripped.
Treat the comment block at that call site as load-bearing.

### Out of band

`/api/onboard/{start,poll,claim}`, `/info`, `/ca.crt`, and the
plugin webhook prefix (`/api/cred/...`) are intentionally
reachable without the dashboard password — they carry their own
auth (signed onboarding handshake; webhook signature header) or
need to be reachable before any credential exists (CA fingerprint
fetch, fresh client onboarding). The full route table lives in
`web.go:routes()`; every other path is gated.

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

- Only credentials from the originating registration’s profiles can
  be injected.
- A request for a service whose credentials live only in another
  registration’s profile is treated like a request for a service
  Claw Patrol has no credentials for — forwarded without injection
  or rejected by policy, never signed with the wrong agent’s key.

Default-profile auto-assignment is a UX convenience for fresh
registrations; the security-relevant property is the scoping rule
above.

## Plugins are untrusted

External plugins (`plugin "<name>" { source = "..." }`) extend the
gateway with new credential, endpoint, and tunnel types. They run as
subprocesses inside the gateway's process tree, and the gateway holds
the secrets a plugin must never reach: the state database (CA private
key, stored credential material), the WireGuard / Tailscale keys, and
the `CLAWPATROL_SECRET_*` environment variables. A planned
Terraform-style distribution mechanism would let operators fetch
plugins they did not write — so plugins are treated as a supply-chain
attack surface, not trusted gateway code.

Two mechanisms contain a malicious or compromised plugin:

- **Scrubbed environment.** A plugin inherits **none** of the
  gateway's environment — only `PATH`, `HOME` and `TMPDIR` (a private
  scratch dir) and its gateway socket path. This holds even with
  `sandbox = "off"`.
- **OS sandbox, on by default.** Every plugin runs inside an OS
  sandbox: Linux user/mount/pid (and, with `network = "none"`,
  network) namespaces over a deny-by-default mount tree; Landlock
  where unprivileged user namespaces are blocked; macOS seatbelt. The
  sandbox hides the filesystem (the plugin sees only its own binary,
  system libraries, and explicitly granted paths) and, by default,
  the network. If no sandbox can be established the plugin **fails to
  load** unless the operator explicitly sets `sandbox = "off"`.

Because the default `network = "none"` cuts a plugin off from the
network entirely, an endpoint plugin that receives credential secrets
(to inject them into an upstream request) cannot exfiltrate them: its
only channel is the gateway socket, and its upstream connections are
opened *by the gateway* through the [brokered
dial](plugins.md#brokered-upstream-dial), restricted to targets the
operator's HCL sanctions and audited on every attempt. Tunnel plugins
are the upstream transport themselves and need outbound network; that
grant is per-plugin, so it does not loosen the endpoint plugins beside
it.

Network is **declared by the plugin** in its manifest and recorded,
trust-on-first-use, in a committed lockfile (`clawpatrol.lock.hcl`).
The threat this addresses is the supply-chain one: a benign plugin's
next version silently gaining a network leak path. An upgrade (a
changed binary hash) that requests more than the lockfile recorded
**fails config load** until an operator re-approves it — the loud,
reviewable moment a malicious update would otherwise slip through.
Because the lockfile is committed, the approval is also a diff in code
review. Filesystem and `sandbox = "off"` grants are never
plugin-declarable; they are operator-only and explicit (below).

For a GitHub-distributed plugin the declared capability comes from the
release's **signed static manifest** — verified (checksum + provenance)
before the binary is downloaded — so the gateway never runs the
unapproved binary to discover what it wants. When the binary then runs,
its manifest is cross-checked against that signed declaration and the
load **fails closed** if they disagree: the binary must do what its
published manifest claims. A local plugin, or a release that ships no
static manifest, falls back to reading the manifest from a throwaway,
network-denied probe spawn.

When a plugin's `source` is a GitHub repo, the same lockfile pins the
resolved release version and the binary's hash, and distribution is
gated three ways: the download must match the release's `SHA256SUMS`;
the binary's hash is trusted-on-first-use and re-checked (fail-closed)
on every later load; and, when the release carries a [GitHub
build-provenance attestation](plugins.md#verification-and-trust),
clawpatrol verifies through Sigstore that the binary was built by *that
repo's* Actions workflow — the `github.com/owner/repo` named in the
config is the trust anchor, closing the first-download gap. The
attestation also binds the binary to the source commit it was built
from, which the lockfile pins (`commit`) as an immutable reference; a
re-pointed tag whose attestation names a different commit is rejected.
Provenance is tracked trust-on-first-use like the network grant: the
lockfile records whether the pinned version was attested, and a binary
that loses provenance across a re-download or upgrade fails closed until
the operator re-approves it — the loud, reviewable moment a malicious
update that strips its attestation would otherwise slip through. The
per-plugin `provenance` field (`warn` default, `require`, `off`) sets
how a *first*, never-attested release is treated.
The gateway loads only the locked version and never upgrades on its own;
moving to a newer release is the operator's explicit `clawpatrol plugins
update`.

The sandbox is defense-in-depth, not a capability wall around the
gateway as a whole. The grants form a deliberate risk ladder:

- `network = "outbound"` is a bounded *leak path* — a network-enabled
  plugin can exfiltrate only the secrets it is actually handed,
  because the sandbox still confines its filesystem.
- `read_paths` is a *host read hole* — fine for inert files, but
  catastrophic when pointed at credential-bearing paths, so the
  gateway refuses any that overlaps the state dir (the secret store).
- There is **no host-write grant**. Host write is a
  code-execution-as-the-gateway-user primitive (plant a payload in
  `~/.bashrc`, cron, a `$PATH` dir; it runs later as the user, reads
  the state DB, and exfiltrates over the user's own network), and no
  denylist of active locations can be complete — so the only way to
  get host write is `sandbox = "off"`.
- `sandbox = "off"` is the single **full-trust** knob: full host read,
  write, and exec (the environment scrub still applies). A plugin run
  this way can read every credential in the state DB; use it only for
  plugins you fully trust.

Grant the minimum a plugin needs, and prefer the brokered dial over
`network = "outbound"` for anything that handles secrets.

## Egress interception is best-effort

Routing the agent’s traffic through the gateway is what lets Claw
Patrol inject credentials and apply policy — it is **not** a
containment wall, and intercepting every packet the agent emits is not
part of the guarantee. Per-process `clawpatrol run` confines the
wrapped process as well as the platform allows (a kernel network
namespace on Linux; a PPID-chain match in the macOS Network
Extension), but neither is airtight: on macOS an agent that detaches
from its session — double-fork + `setsid` to reparent under launchd —
no longer matches and egresses untunneled, and even the Linux
namespace can be left by an agent with enough privilege (passwordless
`sudo`). Whole-machine mode routes at the host level and sidesteps the
question.

This does not weaken the guarantee, because credentials and policy
share one chokepoint: traversing the gateway is what earns a request a
real credential *and* what subjects it to policy. A flow that escapes
interception is therefore *uncredentialed* — an anonymous client
holding only placeholders, with no access to any privileged system,
not a credentialed-but-unpoliced path. What this does **not** prevent
is a hostile process exfiltrating data it can already read locally,
over a side channel it opens outside the tunnel; if that is in your
threat model, use whole-machine mode or an external network egress
control.

## Out of scope

Claw Patrol does not defend against:

- physical access to the Claw Patrol host;
- compromise of the Claw Patrol host or user — any attacker with
  those privileges holds every injected credential;
- a kernel or hypervisor compromise that bypasses UNIX user
  separation;
- supply-chain compromise of the binary or its build toolchain;
- cross-user side channels (shared-CPU timing, etc.);
- exfiltration of locally-readable data by a process that bypasses
  per-process egress interception (see [Egress interception is
  best-effort](#egress-interception-is-best-effort)).
