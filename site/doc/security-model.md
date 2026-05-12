# Security model

## Threat model

Claw Patrol is a forward proxy that intercepts outbound network connections
-- HTTPS, SSH, Postgres, and other protocols -- and injects the
appropriate credential on behalf of **the agent**, the untrusted
program being wrapped. The agent may be an AI coding tool, a
browser-automation job, a batch script: any program we do not want to
hand raw secrets to. A single Claw Patrol instance may serve one agent or
many, each with its own set of assigned credentials. The agent sees
the result of the authenticated operation but never the credential
itself.

This document describes how Claw Patrol prevents the agent from reading the
credentials it injects, and -- in multi-agent deployments -- from
using credentials that belong to another agent.

The agent must not be able to:

- read any injected credential,
- use credentials assigned to another agent,
- read Claw Patrol's state files (the SQLite database of registrations,
  credentials, and policy),
- modify the Claw Patrol binary,
- call Claw Patrol's HTTP API directly, or
- reach Claw Patrol's dashboard.

The first two properties are about credential confidentiality and
credential scoping; the rest reduce to the same underlying requirement:
the agent must sit outside Claw Patrol's trust boundary, unable to reach
its process, its state, or its administrative interfaces.

Claw Patrol supports two deployment modes. **Remote mode** puts a network
between the agent and Claw Patrol. **Local mode** keeps them on a single
host and substitutes UNIX user separation for the network boundary.
Remote mode offers a strictly stronger property set; the local-mode
asymmetry is called out explicitly below.

## Remote mode

The agent runs on one host; Claw Patrol runs on another. The agent host
initiates a WireGuard tunnel to Claw Patrol during onboarding, and the
tunnel remains up for the life of the registration.

### Registration and approval

Registration starts on the agent host and always finishes with a human
on the Claw Patrol side:

1. The agent host contacts Claw Patrol and sends the public IPv4 and IPv6
   addresses from which it will subsequently connect.
2. Claw Patrol records those addresses and issues a **join credential** --
   the only Claw Patrol-issued secret the agent host ever holds.
3. The agent host brings up a WireGuard tunnel using the join
   credential. The tunnel comes up, but the registration is
   **unapproved**: Claw Patrol forwards none of the agent's outbound traffic
   to the internet.
4. An operator opens the Claw Patrol dashboard, approves the new
   registration, and assigns it one or more profiles (see
   "Isolation between agents" below). Traffic begins flowing at that
   moment.

A leaked registration endpoint is worthless on its own: until a human
approves the registration and assigns it credentials, the newly joined
agent host gets nothing.

### What lives on each host

The agent host holds the join credential and nothing else of value to
Claw Patrol's security model. None of the injected credentials -- API keys,
OAuth tokens, session cookies, SSH keys, database passwords -- ever
reach it.

The Claw Patrol host holds the injected credentials, the state database,
policy, the dashboard, and the HTTP API.

Because the injected credentials are never on the agent host, **the
agent can have root on its own host and still not compromise Claw Patrol.**
This is the single strongest property remote mode provides.

### How traffic moves

The agent routes some or all of its outbound traffic through the
WireGuard tunnel into the Claw Patrol process. Claw Patrol terminates each
connection on its side of the tunnel using machinery appropriate to
the protocol:

- **HTTPS.** Claw Patrol terminates TLS using a local certificate authority
  whose root was installed into the agent's trust store during
  onboarding. With the connection decrypted, Claw Patrol inspects the
  plaintext request, optionally rewrites it to include the real
  credential, enforces policy on what requests are allowed, then
  re-encrypts the request using the destination's real certificate
  and forwards it.
- **Protocols with their own authentication handshake** (SSH, Postgres,
  and others). Claw Patrol accepts the agent's connection, completes the
  protocol's authentication against the real destination using the
  real credential, and proxies the authenticated session back to the
  agent. The agent never participates in the authentication handshake
  and never sees the credential.
- **Non-credentialled traffic** -- public web pages, ordinary internet
  traffic, DNS. Claw Patrol forwards the connection without modification.

The security guarantee covers credentialled traffic: no injected
credential ever reaches the agent, and no agent request reaches a
credentialled service without Claw Patrol's policy check in between.

Non-credentialled traffic sits outside the security surface. If the
agent bypasses the tunnel for public requests, it gets the public
internet -- what it would have had without Claw Patrol. If the agent
bypasses the tunnel for credentialled requests, no credential is
injected and the request either fails or reaches the destination
unauthenticated. In both cases no credential leaks. Data that the
agent sends or receives over an unauthenticated channel is the
agent's own traffic, not Claw Patrol's to protect.

### Mitigating a leaked join credential

The join credential can leak: off a backup, out of shell history, out
of a compromised process on the agent host. To bound the damage,
Claw Patrol pins each join credential to the exact IPv4/IPv6 pair the
agent host presented at registration. If Claw Patrol observes a request
arriving from a deviating pair -- a different v4, a different v6, or
a v6 on a host that registered with v4 only -- it marks the
credential blocked in the state database and tears down the tunnel.
Restoring access requires explicit re-approval in the dashboard.

Two caveats. First, IPv6 privacy extensions rotate a host's source
address over time; operators deploying Claw Patrol should disable privacy
extensions on agent hosts or deploy a stable prefix scheme. Second,
an attacker on the same NAT as the legitimate agent host shares the
same public v4, so IP pinning is not a standalone defence -- it is a
blast-radius limiter for a credential that has already escaped.

## Local mode

In local mode, the agent and the Claw Patrol process run on the same host.
There is no network to separate them, so the isolation boundary moves
into the operating system.

**Local mode is strictly weaker than remote mode.** In remote mode,
the agent host contains nothing an attacker can use against Claw Patrol.
In local mode, the injected credentials sit on the same physical
machine as the agent, separated from the agent by UNIX permissions
alone. The mechanisms below make that boundary hard to cross, but
they do not provide the "root-on-your-own-host-is-fine" guarantee
that remote mode does.

### UNIX user separation

The host is configured with two user accounts:

- **The agent user**, under which the agent runs. On a desktop install
  this is normally the primary interactive user.
- **The Claw Patrol user**, an unprivileged service account created during
  onboarding. The Claw Patrol process runs under this account and owns
  Claw Patrol's installation and state directories.

The boundary between these two accounts replaces the network boundary
from remote mode:

- Claw Patrol's state directory -- the SQLite database of credentials,
  registrations, and policy -- is owned by the Claw Patrol user and is
  not readable by the agent user.
- The Claw Patrol binary -- a single statically linked Go executable --
  is owned by root (or by the Claw Patrol user) and installed with
  permissions that deny write access to the agent user. The agent
  cannot replace the binary, drop in a shared library it would load,
  or otherwise substitute the code that Claw Patrol is about to execute.
- Claw Patrol's HTTP API and dashboard require an access token. The token
  is stored where only the Claw Patrol user can read it. If the operator
  loses the token, they recover it with `sudo clawpatrol get-token`,
  which requires a password a human can supply and the agent cannot.

### Host prerequisites

Two properties must hold for local mode to be safe, and Claw Patrol cannot
enforce them itself:

- The agent user is not a root-equivalent account.
- The agent user cannot use `sudo` without a password.

Passwordless `sudo` for the agent user defeats the entire model.
There is no userspace mitigation for an agent that can become root.

### Defense in depth: loopback-only bind

Local-mode onboarding configures Claw Patrol's proxy listener, HTTP API,
and dashboard to bind only to the loopback interface. Nothing on the
local network, and nothing on the internet, can reach them even if
the host firewall is misconfigured or missing. UNIX user separation
is still doing the real work; the loopback bind closes off accidental
network exposure.

### Pre-existing secrets on the host

A local install lands on a host that likely already contains
credentials the agent user can read: shell dotfiles, credential
helpers, cloud-CLI configuration, SSH keys. These are outside
Claw Patrol's control. Onboarding offers to import recognised credentials
into Claw Patrol and delete the originals from the agent user's home
directory; anything Claw Patrol does not recognise, or that the user
declines to migrate, remains readable by the agent exactly as before.

## Isolation between agents

A single Claw Patrol instance can serve many agents, each with its own
credentials. The security model also protects each agent from every
other agent: a compromised or malicious agent must not be able to
cause Claw Patrol to inject credentials belonging to another agent.

Claw Patrol enforces this by scoping credential injection to the
originating registration. Each registration is assigned one or more
**profiles** by an operator; each profile is a named set of
credentials. When Claw Patrol receives a request, it identifies the
originating registration from the channel the request arrived on --
the WireGuard peer in remote mode, the authenticated local channel
in local mode -- not from anything the agent can claim or forge.
From there:

- Claw Patrol will only inject credentials drawn from profiles assigned
  to the identified registration.
- A request targeting a service whose credentials live only in
  another registration's profiles is handled the same as a request
  for a service Claw Patrol has no credentials for: forwarded without
  injection, or rejected by policy, but never signed with a credential
  the originating registration was not granted.

Profile assignment itself is a dashboard action, not a security
property. Operators can configure a default profile that is
auto-assigned to every newly approved registration, so that approval
and initial credential grant happen in a single gesture; this is a UX
convenience. The security-relevant property is the scoping rule
above: injection is bounded by whatever profiles the originating
registration actually has -- whether those were granted manually or
through the default-profile mechanism.

The single-agent case is the degenerate version of this: one
registration, one profile, one agent.

## Out of scope

The model does not defend against:

- physical access to the host Claw Patrol runs on,
- compromise of the Claw Patrol host itself: any attacker who obtains the
  Claw Patrol user's privileges or direct access to the state database
  also obtains every injected credential,
- a kernel or hypervisor compromise that bypasses UNIX user
  separation,
- supply-chain compromise of the Claw Patrol Go binary or its build
  toolchain,
- cross-user side channels such as shared-CPU timing attacks.
