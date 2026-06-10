# clawpatrol — Tailscale mode

Tailscale as the primary control plane. The gateway joins your existing
tailnet as an exit-node via an embedded **tsnet.Server**; devices onboard
through the same `clawpatrol join <gateway-url>` device-flow that
WireGuard mode uses. No public UDP port, no WireGuard keypair management,
no subnet allocation — Tailscale's control plane handles all of that.

## How it works

1. Gateway starts a `tsnet.Server` (embedded Tailscale node, no
   `tailscaled` required) using an auth key from the top-level
   `authkey` field or `$TS_AUTHKEY`. It joins the tailnet under the configured hostname
   (default: `clawpatrol-gateway`) and binds the MITM + dashboard on
   the resulting tailnet IP.
2. When a device runs `clawpatrol join <gateway-url>`, the dashboard
   mints a single-use Tailscale auth key by exchanging OAuth client
   credentials for a short-lived bearer token and calling the
   Tailscale key API (`reusable: false`, `preauthorized: true`,
   10-minute TTL) and ships it back over the device-flow poll.
3. The per-process tsnet daemon picks up that auth key on first
   `clawpatrol run` and joins the tailnet under the operator-chosen
   hostname. With `--whole-machine` (Linux), the join flow also runs
   `tailscale up --authkey=<key>`, installs a fwmark policy-route to
   keep SSH alive, and sets `--exit-node=clawpatrol-gateway` on the
   system tailscaled. The CA is fetched over the tailnet and
   installed into the system trust store.
4. All outbound traffic now exits through the gateway. The gateway
   intercepts at L4 — TCP/443 → SNI peek → MITM or splice, everything
   else forwarded via `wgRelay` / `relayUDP`. Tailscale handles NAT
   traversal and relay (DERP). UDP gets the same dispatch as WireGuard
   mode even on the tsnet exit-node path: a catch-all on tsnet's netstack
   (`GetUDPHandlerForFlow`) sends UDP/53 to any resolver IP to `dnsvip`
   and relays other UDP from onboarded peers via `relayUDP` — so a
   tsnet-mode `clawpatrol run` child gets arbitrary UDP (NTP, custom
   protocols) without a UDP-over-TCP shim, since the userspace exit node
   already receives the datagrams. **QUIC / HTTP-3 (UDP/443) to an
   intercepted host is dropped** in both modes so HTTPS can't ride UDP
   past the TCP/443 SNI-peek MITM — the client falls back to
   interceptable TCP. UDP/443 to a host the gateway *passes through* (no
   VIP) is relayed normally: clawpatrol doesn't intercept that host's
   HTTPS either, so there's nothing to bypass and no reason to break its
   HTTP/3. For the hosts it does MITM, the gateway also strips the
   `Alt-Svc` response header so agents don't discover h3 in the first
   place (intercepted names already return no SVCB/HTTPS DNS record).
5. Device identity (hostname, OS, Tailscale user) is populated via
   `tailscale whois` at first connection — richer than WireGuard mode
   which only captures hostname at join time.

## What works (verified end-to-end)

- `clawpatrol gateway gateway.hcl` boots the tsnet node, no public
  ports needed — only outbound HTTPS to the Tailscale control plane.
- `clawpatrol join <gateway-url>` is one command on the device:
  device-flow approval against the dashboard, then install CA +
  (with `--whole-machine`) set the gateway as exit-node. Subsequent
  re-runs are idempotent.
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
| **Device IP** | Assigned by Tailscale control plane | Allocated from `wireguard.subnet_cidr` |
| **Dashboard auth** | Bcrypt root password + optional `tailscale.operators` allowlist | Bcrypt root password (no whois identity to allowlist against; combine with a `tailscale {}` block for that) |
| **Client command** | `clawpatrol join <gw-url>` | `clawpatrol join <gw-url>` |
| **State** | `state_dir` — tsnet machine key + ipn state in sqlite | `state_dir` — WG server key, peer map, sessions in sqlite |

## Required tailnet ACL

Client traffic flows through the gateway by treating it as the
client's tsnet **exit node**. The client side sets
`ExitNodeIP=<gateway>` automatically; for that to actually route,
the tailnet ACL must **auto-approve the gateway as an exit node
for the client tag**. Without it, the pref is accepted locally
but every outbound dial silently times out.

Besides the two `/0` exit routes, the gateway advertises the dnsvip
VIP ranges (`10.78.0.0/16` / `fd78::/64` — the per-endpoint virtual
IPs that `clawpatrol.internal`, SSH hosts, ClickHouse native, etc.
resolve to) as plain subnet routes. This is what makes the v4 VIPs
reachable at all: tailscaled derives its inbound packet filter's
accept set locally from the advertised routes, and a bare `/0`
advertisement is deliberately shrunk to public address space
("guest wifi" semantics — `10.0.0.0/8` and friends are stripped), so
without the explicit VIP-range advertisement the gateway itself
silently drops exit-node flows to v4 VIPs. The effect is node-local;
the VIP routes do **not** need to be approved in the admin console
for VIP traffic to work (clients reach VIPs through the exit-node
`/0`, not through subnet routing). Approving or auto-approving them
merely keeps the gateway's machine entry free of "pending route
approval" noise.

Add to your tailnet ACL JSON:

```jsonc
{
  "autoApprovers": {
    "exitNode": ["tag:client"],   // must match tailscale.tags below
    "routes": {
      // dnsvip VIP ranges (optional tidiness, see above); approver
      // is the GATEWAY node's tag (the tag on the authkey the
      // gateway itself joined with).
      "10.78.0.0/16": ["tag:gateway"],
      "fd78::/64":    ["tag:gateway"]
    }
  },
  "tagOwners": {
    "tag:client":  ["autogroup:admin"],
    "tag:gateway": ["autogroup:admin"]
  }
}
```

If your ACL is not the permissive default (`accept *:*`), the rules
must also allow client tags to send to the VIP ranges, e.g.
`{"action": "accept", "src": ["tag:client"], "dst":
["10.78.0.0/16:*", "fd78::/64:*"]}` — `autogroup:internet` does not
include them.

## Operator setup

```bash
# gateway VM — no public IP required, just outbound HTTPS
curl -fsSL https://clawpatrol.dev/install.sh | sh

cat > /opt/clawpatrol/gateway.hcl <<'EOF'
gateway {
  dashboard_listen = "127.0.0.1:8080"
  public_url       = "http://clawpatrol-gateway" # tailnet hostname suffices
  state_dir        = "/opt/clawpatrol/ts-state"

  tailscale {
    authkey             = "tskey-auth-xxxxx"       # gateway-node key; or set $TS_AUTHKEY and omit
    hostname            = "clawpatrol-gateway"     # gateway's name on the tailnet
    tags                = ["tag:client"]           # applied to minted client keys
    oauth_client_id     = "{{secret:TS_OAUTH_CLIENT_ID}}"
    oauth_client_secret = "{{secret:TS_OAUTH_CLIENT_SECRET}}"
  }
}
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

clawpatrol gateway /opt/clawpatrol/gateway.hcl
```

Dashboard is reachable at `http://clawpatrol-gateway:8080` from any
device on the tailnet once the gateway is up.

## Client setup

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
clawpatrol join <gateway-url>   # prints a user_code; approve on the
                                # dashboard from any trusted device
# done — clawpatrol run claude (or gh/codex) just works
```

The gateway mints a single-use Tailscale auth key as part of the
approval; the local tsnet daemon joins the tailnet on first
`clawpatrol run`. Add `--whole-machine` to additionally install
system Tailscale and pin the gateway as the host-wide exit-node.

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
credential "tailscale_auth" "corp-tailnet" {}

tunnel "tailscale" "corp" {
  credential = tailscale_auth.corp-tailnet
  hostname   = "clawpatrol-tunnel-corp"
  tags       = ["tag:client"]
}

endpoint "https" "grafana-internal" {
  hosts  = ["grafana.corp.example.com:443"]
  tunnel = tailscale.corp
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

### OAuth client — self-renewing keys, no Connect click

Set `oauth_client_secret` (a `tskey-client-...` secret from an OAuth
client with the `write:auth_keys` scope) and `tags` on the tunnel.
tsnet then mints a fresh, short-lived device key from the OAuth client
on **every** join — first boot, restart, and re-auth after node-key
expiry — so there is no long-lived auth key that can expire out from
under the tunnel. This is the recommended mode for unattended gateways:
unlike the interactive credential flow there is no Connect click, and
unlike a static `authkey` there is no key to rotate.

```hcl
credential "tailscale_auth" "corp-tailnet" {}

tunnel "tailscale" "corp" {
  credential          = tailscale_auth.corp-tailnet
  oauth_client_secret = "tskey-client-xxxxx"  # or env CLAWPATROL_TUNNEL_CORP_OAUTH_CLIENT_SECRET
  tags                = ["tag:bot"]            # required — untagged OAuth keys are rejected
  keepalive           = "always"              # keep the node joined; avoid lazy cold-starts
}
```

Notes:

- The secret comes from the HCL field or the per-tunnel env fallback
  `CLAWPATROL_TUNNEL_<UPPER_NAME>_OAUTH_CLIENT_SECRET` (hyphens folded
  to underscores), mirroring `authkey`.
- `tags` are mandatory here. Tailscale refuses to mint untagged keys,
  and an untagged node would be owner-associated (its `whois` returns
  the OAuth client owner), which could bypass an operator allowlist.
  Note the `tags` field is advertised to tsnet **only** in this OAuth
  mode — with a static `authkey` or the interactive credential login the
  node's tags come from the key itself or your tailnet's autoApprovers
  ACL, and the tunnel's `tags` field is ignored.
- clawpatrol appends `?ephemeral=false&preauthorized=true` to the secret
  so the node persists across restarts and joins without manual
  approval. Supplying your own `?...` query string replaces **both**
  defaults — tsnet falls back to `ephemeral=true`, `preauthorized=false`
  for anything you omit — so re-specify any attribute you want to keep.
- Pairs with a `credential` block: the credential's SQLite `StateStore`
  still persists node identity (so steady-state restarts rejoin from
  cached state), while the OAuth client supplies the key whenever a join
  actually needs one. The OAuth secret also takes precedence over any
  ambient `TS_AUTHKEY` in the gateway environment, so a stray static key
  in the process env can't shadow it.
- A literal `authkey` (if also set) wins over `oauth_client_secret`.

### Legacy — literal authkey / env-var fallback

Pre-credential deployments keep working unchanged. The literal
`authkey = ...` form (and its `CLAWPATROL_TUNNEL_<UPPER_NAME>_AUTHKEY`
env-var fallback) stays supported for one iteration so existing
configs don't have to migrate in a hurry:

```hcl
tunnel "tailscale" "corp" {
  authkey   = "tskey-auth-xxxxx"  # or env CLAWPATROL_TUNNEL_CORP_AUTHKEY
  hostname  = "clawpatrol-tunnel-corp"
  state_dir = "/opt/clawpatrol/ts-tunnel-corp"
}

endpoint "https" "grafana-internal" {
  hosts  = ["grafana.corp.example.com:443"]
  tunnel = tailscale.corp
}
```

`{{secret:...}}` expansion runs only on a few gateway fields — the
`tailscale` block's `oauth_client_id`/`oauth_client_secret` and
integration OAuth credentials — never on any Tailscale `authkey`
(gateway or tunnel) or a tunnel's `oauth_client_secret`. A
`{{secret:...}}` placeholder in one of those would reach tsnet
verbatim. To keep the value out of the HCL, use the env fallback
instead: `CLAWPATROL_TUNNEL_<UPPER_NAME>_AUTHKEY` /
`CLAWPATROL_TUNNEL_<UPPER_NAME>_OAUTH_CLIENT_SECRET` for tunnels, or
`$TS_AUTHKEY` for the gateway node.

In this mode the tunnel node joins synchronously at gateway startup
(`tsnet.Up` blocks), reads `authkey` (literal or env fallback), and
persists tsnet state on disk under `state_dir`. If both `credential =
...` and `authkey = "..."` are set on the same tunnel, the credential
takes precedence and the literal authkey is ignored with a load-time
warning.

One node per `tunnel` block in both modes — singleton sharing; all
endpoints referencing the same tunnel share the same tsnet node.
