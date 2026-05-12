# Tailscale mode

Claw Patrol can use Tailscale as its control plane instead of the
default embedded WireGuard. The gateway joins your existing tailnet
as an exit-node; devices already on the tailnet run `clawpatrol login`
and pin the gateway as their exit-node. No public UDP port, no
WireGuard keypair management, no subnet allocation — Tailscale
handles NAT traversal, identity, and ACLs.

Pick this mode if you already operate Tailscale and want Tailscale's
identity (`tailscale whois`) on every approval request, or if you
can't expose a public WireGuard endpoint from the gateway host.

## When to use it

| | Tailscale mode | WireGuard mode (default) |
|---|---|---|
| **Prerequisites** | Tailscale account + tailnet | None — self-hosted |
| **Control plane** | Tailscale Inc (SaaS) | Embedded in the gateway binary |
| **Public port on the gateway** | None — outbound HTTPS only | UDP/51820 |
| **NAT hairpin (peers behind same NAT)** | Works (DERP relay) | Fails — needs a routable UDP endpoint |
| **Device identity** | Tailscale user + hostname + OS via whois | Hostname captured at join |
| **Per-device key** | Minted via OAuth → Tailscale API | Generated locally on `clawpatrol join` |
| **Device IP** | Assigned by the Tailscale control plane | Allocated from `wg_subnet_cidr` |
| **Dashboard auth** | Tailscale user identity (no auth proxy needed) | Falls back to `admin_email`; needs an auth proxy for multi-user |
| **Client command** | `clawpatrol login` | `clawpatrol join <gw-url>` |

If you're not already on Tailscale, stay on the default WireGuard
mode — see [Getting Started](/docs/getting-started/).

## How it works

1. The gateway boots an embedded **tsnet** node (no `tailscaled` on
   the host) using an auth key from the `authkey` field or the
   `$TS_AUTHKEY` environment variable. It joins your tailnet under
   the configured hostname (default `clawpatrol-gateway`) and binds
   the MITM listener and dashboard on the resulting tailnet IP.
2. When a device runs `clawpatrol login`, the dashboard mints a
   single-use, preauthorized Tailscale auth key by exchanging the
   gateway's OAuth client credentials for a short-lived bearer
   token and calling the Tailscale key API (`reusable: false`,
   `preauthorized: true`, 10-minute TTL).
3. `clawpatrol login` runs `tailscale up --authkey=…` on the device
   (installing Tailscale if missing), then fetches the gateway CA,
   sets `--exit-node=clawpatrol-gateway`, and writes the CA bundle
   into the system trust store. On Linux it also installs a
   policy-routing override so the in-flight SSH session that
   approved the join doesn't drop when the exit-node flips.
4. All outbound traffic now exits through the gateway. The gateway
   intercepts at L4 — TCP/443 → SNI peek → MITM or splice,
   everything else forwarded. Tailscale handles NAT traversal and
   DERP relay.
5. Device identity (Tailscale user, hostname, OS) is populated via
   `tailscale whois` at first connection. Approval requests in the
   dashboard show `user@example.com`; no separate auth proxy
   needed.

## Gateway setup

The gateway host needs outbound HTTPS to Tailscale's control plane.
It does not need a public IP, a public port, or a DNS record — the
tailnet hostname is enough.

```bash
# On the gateway host:
curl -fsSL https://clawpatrol.dev/install.sh | sh

cat > /etc/clawpatrol/gateway.hcl <<'EOF'
listen       = "0.0.0.0:8443"
info_listen  = "0.0.0.0:8080"
public_url   = "http://clawpatrol-gateway"   # tailnet hostname suffices
admin_email  = "you@example.com"
ca_dir       = "/opt/clawpatrol/ca"
oauth_dir    = "/opt/clawpatrol/oauth"

dashboard_secret = "change-me-to-a-long-random-string"

control             = "tailscale"
oauth_client_id     = "{{secret:TS_OAUTH_CLIENT_ID}}"
oauth_client_secret = "{{secret:TS_OAUTH_CLIENT_SECRET}}"
tailscale_tags      = ["tag:client"]       # applied to minted device keys
hostname            = "clawpatrol-gateway" # the gateway's name on the tailnet
state_dir           = "/opt/clawpatrol/ts-state"

# Add endpoint / rule / credential / profile blocks for the upstreams
# you want to gate — see /docs/config-reference/ for the full schema.
EOF

mkdir -p /opt/clawpatrol
clawpatrol init-ca /opt/clawpatrol/ca
```

### Credentials

Two Tailscale credentials are required, both generated in the
[Tailscale admin console](https://login.tailscale.com/admin):

1. **An OAuth client** (Settings → OAuth clients) used to mint
   per-device auth keys at login time. Grant the scopes
   `write:auth_keys` and `read:devices`. Export the resulting ID
   and secret so the HCL `{{secret:…}}` references can resolve
   them:

   ```bash
   export TS_OAUTH_CLIENT_ID=<id>
   export TS_OAUTH_CLIENT_SECRET=<secret>
   ```

2. **An auth key for the gateway node itself** (Settings → Keys).
   Tag it `tag:gateway` (or any ACL-gated tag of your choice) so
   your Tailscale ACLs can distinguish the gateway from regular
   devices:

   ```bash
   export TS_AUTHKEY=tskey-auth-...
   ```

Then start the gateway:

```bash
clawpatrol gateway -config /etc/clawpatrol/gateway.hcl
```

The dashboard is reachable at `http://clawpatrol-gateway:8080` from
any device on the tailnet once the gateway is up.

## Device setup

The device must already be on the tailnet — log in once with your
normal Tailscale credentials, then run `clawpatrol login`:

```bash
# Install Tailscale if needed: https://tailscale.com/download
tailscale up   # join your tailnet

curl -fsSL https://clawpatrol.dev/install.sh | sh
clawpatrol login --name clawpatrol-gateway   # finds the gateway on the tailnet
                                             # an admin approves at the dashboard URL it prints
# done — claude / gh / codex now route through the gateway
```

Subsequent re-runs are idempotent — safe to call again after the
gateway moves, the CA rotates, or you want to re-pin the exit-node.

Options:

```
--name NAME         exit-node hostname to find on the tailnet (default: clawpatrol)
--no-exit-node      fetch the CA without setting an exit-node (CA-only install)
--no-trust          fetch the CA but skip the system trust install (handle it manually)
--ca-dir DIR        where to store the fetched CA (default: ~/.clawpatrol)
```

## Multi-user

Each device authenticates with its Tailscale identity, so approval
requests in the dashboard show `user@example.com` — no separate
auth proxy is needed in front of the dashboard. Use Tailscale ACLs
to control who can reach the gateway in the first place.

## Reaching internal tailnet services

The same Tailscale plumbing also powers Claw Patrol's **tunnel**
plugin, which lets endpoints dial out through a tsnet node into a
private tailnet (e.g. an internal Grafana or ClickHouse that's only
reachable on a corporate tailnet). The operator declares a
`credential "tailscale"` block, clicks **Connect** on the dashboard,
and signs the gateway's tsnet node into the target tailnet via
Tailscale's standard interactive login. The node identity persists
in SQLite so restarts don't re-prompt.

This is independent of the gateway's `control = "tailscale"` setting
— you can use tunnels in either mode. See the [config
reference](/docs/config-reference/#credential-tailscale) for the
schema, and the internal
[`doc/tailscale.md`](https://github.com/denoland/clawpatrol/blob/main/doc/tailscale.md)
note for the implementation details and the legacy `authkey = "…"`
form.

## Troubleshooting

**`clawpatrol login` says "no peer named clawpatrol-gateway on this
tailnet".** The gateway hasn't joined yet, or it joined under a
different hostname. Check `tailscale status` on the device and look
for the gateway's hostname; pass `--name <hostname>` if it differs
from the default.

**`clawpatrol login` says "not logged into a tailnet".** The device
isn't on Tailscale yet. Run `tailscale up` first and authenticate.

**SSH session drops the moment exit-node flips on Linux.** Setting
an exit-node rewrites every outbound route, so reply packets to
your SSH client suddenly route through the tailnet and the source
IP changes mid-stream. `clawpatrol login` installs a policy-routing
override before flipping exit-node to keep SSH alive; if it can't
(for example, the host lacks `iproute2`), it warns and falls back
to `--no-exit-node`. Re-run with `--no-exit-node` if you need to
keep SSH and add the route manually.

**Dashboard URL prints a tailnet hostname my browser can't resolve.**
The hostname only resolves on devices joined to the same tailnet
with MagicDNS enabled. Use the tailnet IP printed alongside the
hostname, or enable MagicDNS in the Tailscale admin console.

## What's next

- [Getting Started](/docs/getting-started/) — the default WireGuard path
- [Gateway](/docs/gateway/) — gateway HCL reference
- [Config reference](/docs/config-reference/) — every HCL field, including `control` and `tailscale_tags`
- [Security model](/docs/security-model/) — what Claw Patrol does and doesn't protect against
