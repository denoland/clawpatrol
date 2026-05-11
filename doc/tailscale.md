# clawpatrol — Tailscale mode

Tailscale as the primary control plane. The gateway joins your existing
tailnet as an exit-node via an embedded **tsnet.Server**; devices already
on the tailnet run `clawpatrol login` to pin it as their exit-node. No
public UDP port, no WireGuard keypair management, no subnet allocation
— Tailscale's control plane handles all of that.

## How it works

1. Gateway starts a `tsnet.Server` (embedded Tailscale node, no
   `tailscaled` required) using an auth key from `gateway {}` HCL or
   `$TS_AUTHKEY`. It joins the tailnet under the configured hostname
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

- `clawpatrol gateway -config gateway.hcl` boots the tsnet node, no
  public ports needed — only outbound HTTPS to the Tailscale control
  plane.
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
| **State** | `state_dir` (tsnet) | `oauth_dir` (wg-server.key, wg-peers.json) |

## Operator setup

```bash
# gateway VM — no public IP required, just outbound HTTPS
curl -fsSL https://denoland.github.io/clawpatrol/install.sh | sh

cat > /etc/clawpatrol/gateway.hcl <<'EOF'
listen       = "0.0.0.0:8443"
info_listen  = "0.0.0.0:8080"
public_url   = "http://clawpatrol-gateway"    # tailnet hostname suffices
admin_email  = "you@example.com"
ca_dir       = "/opt/clawpatrol/ca"
oauth_dir    = "/opt/clawpatrol/oauth"
integrations = ["claude", "codex", "github"]

gateway {
  control             = "tailscale"
  oauth_client_id     = "{{secret:TS_OAUTH_CLIENT_ID}}"
  oauth_client_secret = "{{secret:TS_OAUTH_CLIENT_SECRET}}"
  tags                = ["tag:client"]       # applied to minted device keys
  hostname            = "clawpatrol-gateway" # gateway's name on the tailnet
  state_dir           = "/opt/clawpatrol/ts-state"
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

clawpatrol gateway -config /etc/clawpatrol/gateway.hcl
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
that are only on the tailnet (e.g., internal Grafana, ClickHouse):

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

The tunnel node joins once at gateway startup (`tsnet.Up`), then all
matching endpoints dial via `tsnet.Server.Dial`. One node per `tunnel`
block (singleton model — all endpoints sharing a tunnel block share the
same tsnet node).

Auth key fallback: if `authkey` is omitted, reads
`CLAWPATROL_TUNNEL_<UPPER_NAME>_AUTHKEY` from the environment.
