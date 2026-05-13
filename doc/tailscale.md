# clawpatrol — Tailscale mode

Tailscale as the primary control plane. The gateway joins your existing
tailnet as an exit-node via an embedded **tsnet.Server**; devices already
on the tailnet run `clawpatrol login` to pin it as their exit-node. No
public UDP port, no WireGuard keypair management, no subnet allocation
— Tailscale's control plane handles all of that.

## How it works

1. Gateway starts a `tsnet.Server` (embedded Tailscale node, no
   `tailscaled` required) using an auth key from the top-level
   `authkey` field or `$TS_AUTHKEY`. It joins the tailnet under the configured hostname
   (default: `clawpatrol-gateway`) and binds the MITM + dashboard on
   the resulting tailnet IP.
2. When a device runs `clawpatrol login`, the dashboard mints a
   single-use Tailscale auth key by exchanging OAuth client credentials
   for a short-lived bearer token and calling the Tailscale key API
   (`reusable: false`, `preauthorized: true`, 10-minute TTL).
3. `clawpatrol login` calls `tailscale up --authkey=<key>` (installs
   Tailscale if missing), installs a fwmark policy-route to keep SSH
   alive, fetches the gateway CA, sets `--exit-node=clawpatrol-gateway`,
   and writes the CA bundle to the system trust store.
4. All outbound traffic now exits through the gateway. The gateway
   intercepts at L4 — TCP/443 → SNI peek → MITM or splice, everything
   else forwarded via `wgRelay` / `relayUDP`. Tailscale handles NAT
   traversal and relay (DERP).
5. Device identity (hostname, OS, Tailscale user) is populated via
   `tailscale whois` at first connection — richer than WireGuard mode
   which only captures hostname at join time.

## What works (verified end-to-end)

- `clawpatrol gateway gateway.hcl` boots the tsnet node, no public
  ports needed — only outbound HTTPS to the Tailscale control plane.
- `clawpatrol login` is one command on the device: join tailnet +
  install CA + set exit-node. Subsequent re-runs are idempotent.
- Agents (`claude`, `gh`, `codex`) run unmodified. `eval "$(clawpatrol
  env)"` exports placeholder tokens + CA bundle. HTTPS to
  `api.anthropic.com` routes through the exit-node, gateway intercepts,
  MITM injects real OAuth credentials.
- Multi-user: each device authenticates with its Tailscale identity.
  The dashboard shows `user@example.com` in approval requests; no
  additional auth proxy needed.
- Devices behind the same NAT work (Tailscale DERP relay handles it —
  no WireGuard UDP hairpin problem).

## vs WireGuard mode

| | Tailscale | WireGuard |
|---|---|---|
| **Prerequisites** | Tailscale account + tailnet | None — self-hosted |
| **Control plane** | Tailscale Inc (SaaS) | Embedded in gateway binary |
| **Public port** | None — tailnet IP only | UDP 51820 + TCP 8080 |
| **NAT hairpin** | Works (DERP relay) | Fails if both peers behind same NAT |
| **Device identity** | User + hostname + OS via whois | Hostname only (set at join) |
| **Auth key source** | OAuth client_credentials → Tailscale API | Self-generated keypair |
| **Device IP** | Assigned by Tailscale control plane | Allocated from `wg_subnet_cidr` |
| **Dashboard auth** | Tailscale user identity (no proxy needed) | Falls back to `admin_email`; needs auth proxy for multi-user |
| **Client command** | `clawpatrol login` | `clawpatrol join <gw-url>` |
| **State** | `state_dir` — tsnet machine key + ipn state in sqlite | `state_dir` — WG server key, peer map, sessions in sqlite |

## Operator setup

```bash
# gateway VM — no public IP required, just outbound HTTPS
curl -fsSL https://denoland.github.io/clawpatrol/install.sh | sh

cat > /etc/clawpatrol/gateway.hcl <<'EOF'
listen       = "0.0.0.0:8443"
info_listen  = "0.0.0.0:8080"
public_url   = "http://clawpatrol-gateway"    # tailnet hostname suffices
admin_email  = "you@example.com"
state_dir    = "/opt/clawpatrol/state"
integrations = ["claude", "codex", "github"]

control             = "tailscale"
oauth_client_id     = "{{secret:TS_OAUTH_CLIENT_ID}}"
oauth_client_secret = "{{secret:TS_OAUTH_CLIENT_SECRET}}"
tailscale_tags      = ["tag:client"]       # applied to minted device keys
hostname            = "clawpatrol-gateway" # gateway's name on the tailnet
state_dir           = "/opt/clawpatrol/ts-state"
EOF

mkdir -p /opt/clawpatrol
clawpatrol init-ca /opt/clawpatrol/ca

# OAuth client: create at https://login.tailscale.com/admin/settings/oauth
# Grant: write:auth_keys (to mint device keys), read:devices
export TS_OAUTH_CLIENT_ID=<id>
export TS_OAUTH_CLIENT_SECRET=<secret>

# Auth key for the gateway node itself: generate once at
# https://login.tailscale.com/admin/settings/keys
# Tag: tag:gateway (or any ACL-gated tag)
export TS_AUTHKEY=tskey-auth-...

clawpatrol gateway /etc/clawpatrol/gateway.hcl
```

Dashboard is reachable at `http://clawpatrol-gateway:8080` from any
device on the tailnet once the gateway is up.

## Client setup

Device must be on the tailnet first:

```bash
# Install Tailscale (if not already): https://tailscale.com/download
# Then:
tailscale up   # join tailnet with your normal Tailscale credentials

curl -fsSL https://denoland.github.io/clawpatrol/install.sh | sh
clawpatrol login           # finds clawpatrol-gateway on the tailnet
                            # approve at the dashboard URL it prints
# done — claude/gh/codex just work
```

Options:

```
--name string       exit-node hostname to find on the tailnet (default: clawpatrol-gateway)
--no-exit-node      skip setting exit-node (use if you only want the CA)
```

## Tunnel plugin — reach internal tailnet services

Endpoints can dial out through an embedded tsnet node to reach services
that are only on the tailnet (e.g., internal Grafana, ClickHouse).

### Credential-driven (recommended) — interactive login, no pasted key

Declare a `credential "tailscale" "..." {}` and reference it from the
tunnel. The operator never pastes an authkey — instead, the dashboard's
"Connect" button surfaces tsnet's live Tailscale login URL the first
time the gateway boots, and the resulting node identity is persisted
in SQLite (`credential_secrets`) and reused on every subsequent
restart:

```hcl
credential "tailscale" "corp-tailnet" {}

tunnel "tailscale" "corp" {
  credential = corp-tailnet
  hostname   = "clawpatrol-tunnel-corp"
  tags       = ["tag:client"]
}

endpoint "https" "grafana-internal" {
  hosts  = ["grafana.corp.example.com:443"]
  tunnel = corp
}
```

What happens on first boot:

1. Gateway starts; tunnel comes up "pending". Endpoints depending on
   it return `tailscale tunnel "corp": node not connected — visit
   dashboard to complete "corp-tailnet" sign-in` until the operator
   completes the dance.
2. tsnet contacts Tailscale and emits an interactive login URL of the
   form `https://login.tailscale.com/a/<token>`. The gateway parks
   that URL on its in-process side-channel.
3. The dashboard's integrations list shows the `corp-tailnet`
   credential (because at least one endpoint in this profile reaches
   upstream through the `corp` tunnel). The operator clicks Connect
   and is redirected to the Tailscale URL.
4. The operator approves the node in the Tailscale admin console.
   tsnet receives the node-state callback, the gateway writes the
   node identity (machine key, node key, login profile) through the
   credential's SQLite-backed `ipn.StateStore`, and the tunnel flips
   to "operational". Pending requests retry through and succeed.
5. Subsequent gateway restarts find the persisted state, join in
   seconds, and never show the URL prompt again — exactly the
   `tailscale up` cached-state behaviour.

Operator UX surface:

- Dashboard endpoints (per credential bare name `<id>`):
  - `POST /api/tailscale/connect?id=<id>` — returns
    `{status: "connected" | "pending" | "awaiting_url", auth_url, ...}`.
  - `GET  /api/tailscale/status?id=<id>` — same shape, side-effect free.
  - `POST /api/tailscale/disconnect?id=<id>` — wipes stored node
    identity; the next tunnel re-init drives the interactive login
    again.

Multiple tunnels can share one `credential "tailscale" "..."` block —
they then share a single tsnet node identity (one node per credential,
not per tunnel). Per-tailnet selection (`control_url`) lives on the
tunnel block, not the credential.

### Legacy — literal authkey / env-var fallback

Pre-credential deployments keep working unchanged. The literal
`authkey = ...` form (and its `CLAWPATROL_TUNNEL_<UPPER_NAME>_AUTHKEY`
env-var fallback) stays supported for one iteration so existing
configs don't have to migrate in a hurry:

```hcl
tunnel "tailscale" "corp" {
  authkey   = "{{secret:TS_TUNNEL_CORP_AUTHKEY}}"  # or $CLAWPATROL_TUNNEL_CORP_AUTHKEY
  hostname  = "clawpatrol-tunnel-corp"
  state_dir = "/opt/clawpatrol/ts-tunnel-corp"
}

endpoint "https" "grafana-internal" {
  hosts  = ["grafana.corp.example.com:443"]
  tunnel = corp
}
```

In this mode the tunnel node joins synchronously at gateway startup
(`tsnet.Up` blocks), reads `authkey` (literal or env fallback), and
persists tsnet state on disk under `state_dir`. If both `credential =
...` and `authkey = "..."` are set on the same tunnel, the credential
takes precedence and the literal authkey is ignored with a load-time
warning.

One node per `tunnel` block in both modes — singleton sharing; all
endpoints referencing the same tunnel share the same tsnet node.
