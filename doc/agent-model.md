# Agent Model Design

## Status: Implemented (Option A)

## Problem

The current server data model centers on "clients" — a
concept tied to the WireGuard connection method. The CLI
introduces a second connection method (gateway proxy via
HTTPS) that doesn't fit cleanly into the client model:

- **IP binding** makes sense for a VM with a stable IP.
  A developer's laptop changes IPs constantly.
- **Profile assignment** requires visiting the dashboard
  after every `unclaw login`. Bad UX for CLI users.
- **Client names** are auto-generated from hostnames
  (`agent-Ryans-MacBook.local`). The CLI has its own
  naming via `--name`.
- **The gateway** (`/gw/`) authenticates by token lookup
  into the clients table, but the CLI's notion of "agent"
  (a named subprocess tree) doesn't map to a "client"
  (a registered connection endpoint).

## Two Connection Methods

### 1. VM join (`bash <(curl https://unclaw.dev/join)`)

Configures a whole VM to route traffic through unclaw.dev
via WireGuard. The VM typically runs OpenClaw or similar.
Traffic is transparently intercepted — no per-process
setup. The VM is the agent.

**Characteristics:**
- Stable IP (VMs don't move)
- Long-lived (days/weeks)
- One agent per VM
- Registered once, runs continuously
- WireGuard provides identity (tunnel IP)
- IP binding is useful (detects compromised keys)

### 2. CLI wrap (`unclaw <command>`)

Wraps a command in a network sandbox (sandbox-exec on
macOS, unshare on Linux). The subprocess tree is the
agent. On macOS, the Network Extension intercepts traffic
from the process tree via XPC-registered PIDs and routes
it through a WireGuard tunnel to the gateway. On Linux,
traffic is routed through a network namespace with a
userspace WireGuard tunnel.

**Characteristics:**
- Changing IPs (laptops, home networks)
- Short-lived (minutes to hours per session)
- Multiple agents on one machine (different --name)
- Re-created on every invocation
- Token-based identity
- IP binding is harmful (breaks on network change)

## What is an "Agent"?

An agent is anything that makes requests through unclaw.
It has:

- **Name**: human-chosen identifier (`avocet`, `kaju`,
  `mira`). Stable across sessions and restarts.
- **Profile**: which plugins/configs apply (secret
  injection, endpoint handlers).
- **Sessions**: individual invocations. A VM join is one
  long session. `unclaw curl ...` is a short one. Many
  sessions accumulate under one agent name.

The connection method (WireGuard vs CLI gateway) is an
implementation detail, not part of the agent's identity.

## Design Options

### Option A: Rename "clients" to "agents", accommodate both

Minimal schema change. Rename the table and UI. Add a
`connection_type` column (`wireguard` | `gateway`).
Disable IP binding for gateway agents. Auto-assign a
default profile for CLI-created agents.

**Pros:** Small diff. Doesn't break WG clients.
**Cons:** Still one table doing double duty. The
approval/IP-binding logic gets more conditional.

### Option B: Separate agent identity from connection

Split into two tables:

```
agents:
  name (PK)        -- "avocet", "mira"
  profile_id       -- which plugins apply
  created_at
  last_seen

connections:
  id (PK)
  agent_name (FK)  -- which agent this connects as
  type             -- "wireguard" | "gateway"
  token            -- auth secret
  wg_ip            -- for WG connections
  approved_ip      -- IP binding (WG only)
  created_at
```

An agent can have multiple connections (WG from a VM +
gateway from a laptop). The profile lives on the agent,
not the connection.

**Pros:** Clean separation. Agent name is the primary
key everywhere (ClickHouse, dashboard, CLI).
**Cons:** Migration required. More joins.

### Option C: Keep clients for WG, add separate agent auth for CLI

The gateway gets a new auth path: instead of looking up
a client by token, it accepts a user-level token + agent
name header. The server creates ClickHouse records with
the agent name. No client record needed for CLI usage.

```
X-Unclaw-Token: <user token from login>
X-Unclaw-Agent: avocet
```

The user token authenticates the request. The agent name
is just a label for attribution. No profile/plugin
processing for CLI agents (the CLI does its own secret
injection locally).

**Pros:** Zero changes to the WG client system. CLI
just needs a user token and a name.
**Cons:** CLI agents don't get server-side secret
injection. Two parallel auth systems.

## CLI UX Considerations

### Current: `unclaw --name avocet openclaw`

Simple. One command, one process tree, one agent name.
`--name` is optional — unnamed sessions get a hex ID.

### Alternative: `unclaw login avocet` + subshell

```
$ unclaw login avocet
Unclaw avocet>
Unclaw avocet> openclaw &
Unclaw avocet> curl https://api.anthropic.com/...
Unclaw avocet> exit
```

Login starts a sandboxed subshell. Everything inside it
is agent `avocet`. No `--name` needed — the shell IS
the agent boundary.

**Pros:** Natural for interactive use. Run multiple
commands under one agent. Background processes work.
**Cons:** Changes the mental model from "wrap a command"
to "enter an environment". Can't `unclaw cmd` one-shot
without entering a shell first (or keep both modes).

### Hybrid: both work

```
# One-shot (current)
$ unclaw --name avocet openclaw

# Interactive
$ unclaw attach avocet
avocet> openclaw &
avocet> exit

# Login stores credentials, name is per-invocation
$ unclaw login
$ unclaw --name avocet openclaw
$ unclaw --name kaju openclaw
```

The `--name` flag stays. `attach` is sugar for
`unclaw --name X $SHELL`. Login is just auth, separate
from naming.

## Key Constraint: Plugins Must Work Everywhere

CLI agents need server-side plugin execution (secret
injection, endpoint handlers) just like WG agents. If
you configure an Anthropic plugin with your API key on
a profile, `unclaw --name avocet claude` should get that
key injected — whether traffic arrives via WG or the
gateway.

This rules out Option C. The gateway already runs plugin
handlers for clients with profiles. CLI agents need to
be registered entities with profiles too.

## Recommendation

**Option A** now. Rename "clients" to "agents" in the UI
and mental model, but keep the same table with minimal
schema changes:

1. Rename dashboard tab from "Clients" to "Agents"
2. Add `connection_type` column (`wireguard` | `gateway`)
3. For gateway agents: skip IP binding (IPs change)
4. `unclaw login` creates an agent via device auth
5. The `--name` flag maps to the agent name
6. Auto-assign a default profile for new CLI agents

The gateway auth stays the same — token lookup into the
agents (née clients) table. The profile determines which
plugins run. WG and CLI agents are rows in the same
table, same profiles, same integrations.

**Path to Option B later** if we need multiple
connections per agent (e.g., same agent name used from
WG VM and CLI laptop simultaneously). For now, one row
per agent is fine.

### What changes for WG clients

Nothing in the protocol. The join script still registers
a client (now called "agent") with a WG key and IP. The
approval/IP-binding flow stays. The only visible change
is the dashboard label.

### What changes for CLI

The gateway accepts the agent's token in
`X-Unclaw-Token`. The server looks up the agent, gets
its profile, runs plugin handlers (secret injection,
etc.), forwards to upstream, records to ClickHouse.

The CLI does **not** do local secret injection in remote
mode. Placeholders flow to the server, the server
replaces them using the profile's integrations. Same
as WG clients.

### CLI UX

```
# Auth (one-time)
$ unclaw login
Logged in as user@example.com

# Named agent (creates/reuses agent on server)
$ unclaw --name avocet openclaw

# Interactive shell as an agent
$ unclaw attach avocet
avocet> openclaw &
avocet> exit

# Unnamed (auto-generated agent, ephemeral)
$ unclaw curl https://example.com
```

`unclaw --name avocet` at startup: CLI calls
`POST /api/agents/ensure { name: "avocet" }` to
create or look up the agent, get its token. Or the
login flow itself takes a name.

## Implementation (2026-04-02)

Chose **Option A**: renamed "clients" to "agents" across
the entire codebase. Single table, two connection types.

### Schema

```sql
CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  profile_id TEXT,
  connection_type TEXT DEFAULT 'wireguard',
  approved_ip TEXT,
  wg_public_key TEXT,
  wg_ip TEXT,
  registration_ip TEXT,
  created_at TEXT NOT NULL,
  last_seen TEXT,
  last_ip TEXT
);
```

`connection_type` is `'wireguard'` or `'gateway'`.

### Migration

On startup, if the table is still named `clients`, it's
renamed to `agents` and the `connection_type` column is
added. Existing rows default to `'wireguard'`.

### Behavior differences by connection type

- **wireguard**: IP binding enforced (approved_ip set on
  first request, auto-revoke on IP change). WG tunnel
  provides identity.
- **gateway**: IP binding skipped (laptops change IPs).
  Token-only auth via `X-Unclaw-Token` header.

Both types use the same profile/plugin system. The
gateway runs plugin handlers (secret injection, endpoint
rewriting) identically to the MitM proxy.

### API changes

- `/api/clients` → `/api/agents`
- `/api/clients/:id/profile` → `/api/agents/:id/profile`
- `/api/clients/:id` → `/api/agents/:id`

### Dashboard changes

- "Clients" tab → "Agents"
- Route `/clients` → `/agents`
- Interface `Client` → `Agent`

### Files renamed

- `src/clients.ts` → `src/agents.ts`
- `dashboard/src/components/ClientsPage.tsx` →
  `AgentsPage.tsx`

## Open Questions

- If two people run `unclaw --name avocet` from
  different machines, do they share the agent? (Probably
  yes — the name is the identity, not the machine.)
- Should `unclaw attach` exist, or is
  `unclaw --name avocet $SHELL` good enough?
- How do unnamed CLI sessions appear on the dashboard?
  By session ID? Should they be grouped under a default
  agent per user?
- Should the CLI auto-create agents on the server, or
  require them to be pre-created via the dashboard?
- The `join` script needs updating to use `/api/agents`
  endpoints (currently references `/api/register`).
