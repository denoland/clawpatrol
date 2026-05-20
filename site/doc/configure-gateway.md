# Configure the gateway

[Getting Started](/docs/getting-started/) gets you running with
the example config, untouched. This page covers the operational
tuning you reach for as soon as you take the gateway past
"kick-the-tyres" — different control plane, dashboard auth,
where to bind the dashboard, systemd, state-dir hardening, and
the rest.

## Control plane: WireGuard or Tailscale

The example config uses WireGuard:

```hcl
control        = "wireguard"
wg_subnet_cidr = "10.55.0.0/24"
```

If your fleet already lives on a tailnet, swap to embedded tsnet:

```hcl
control = "tailscale"
funnel  = true
listen  = ":8443"

oauth_client_id     = "<tailscale oauth client id>"
oauth_client_secret = "<tailscale oauth client secret>"
tailscale_tags      = ["tag:clawpatrol"]
```

Embedded tsnet joins the tailnet in-process — no UDP port to open,
no `iptables` rule, no host Tailscale daemon. `funnel = true` lets
non-tailnet devices reach the gateway over Tailscale Funnel.
Devices onboard with `clawpatrol login` instead of `clawpatrol
join`; see [CLI reference](/docs/cli/) for the Tailscale variant.

### WireGuard endpoint

The default WireGuard listener is `0.0.0.0:51820`. Clients dial
`host(public_url):port`, so you only set `wg_endpoint` when you
need a non-default port or a different host for WG than for the
dashboard:

```hcl
wg_endpoint = ":41820"                # custom port, default host
wg_endpoint = "wg.example.com:51820"  # split-host deployment
```

## Dashboard auth

**The dashboard is how operators connect endpoint credentials
and inspect live traffic, so it requires a password on every
request.**

The first time you open the dashboard you set a `root` password.
It lives bcrypt-hashed in `clawpatrol.db` and is checked on every
subsequent request. You can also manage the password from the CLI:

```bash
clawpatrol gateway --set-dashboard-password '<password>' gateway.hcl
clawpatrol gateway --reset-dashboard-password gateway.hcl
```

### Where to bind the dashboard

`info_listen` is the dashboard's host-side HTTP bind. The shapes
that make sense for it — and the auth shortcuts available on top
of the root password — depend on the control plane mode, because
each mode automatically exposes the dashboard on its own overlay
network as well.

#### In WireGuard mode

The in-tunnel forwarder routes any connection to the info port on
the gateway's WG IP to the dashboard, so joined devices reach
`http://<gateway-wg-ip>:8080` with nothing extra configured.
`info_listen` only controls who can reach the dashboard from
**outside** the tunnel:

- **`127.0.0.1:8080`** (the example default) — only loopback.
  Operators who haven't joined as a device themselves reach the
  dashboard via SSH tunnel
  (`ssh -L 8080:127.0.0.1:8080 gateway-host`) or a local reverse
  proxy.
- **`0.0.0.0:8080`** — anyone with network reach to the host sees a
  login page. The root password is the only thing between the
  internet and the dashboard, so only do this when the gateway is
  fronted by an auth proxy (Cloudflare Access, oauth2-proxy) that
  does its own SSO first.

`dashboard_operators` is ignored in WireGuard mode — there is no
tailnet whois identity to match against, so the root password is the
only auth.

#### In Tailscale mode

The embedded tsnet node always serves the dashboard on the gateway's
tailnet IP at the info port, so tailnet peers reach
`http://<gateway-tailnet-ip>:8080` with no extra configuration.
`info_listen` controls the host-side bind:

- **`127.0.0.1:8080`** (recommended) — keeps the host socket
  loopback-only. Operators reach the dashboard over the tailnet
  using the tsnet IP; SSH tunnel is the out-of-band fallback when
  the tailnet is the thing that's broken.
- **`0.0.0.0:8080`** — also exposes the dashboard on every other
  network interface of the host (LAN, and the public IP if the host
  has one), on top of the always-on tailnet listener. Tailnet peers
  don't need this — they already reach the dashboard through the
  tsnet IP — so the only reason to bind `0.0.0.0` is to let
  something off the tailnet reach the dashboard. Do this only when
  the gateway sits behind an external auth proxy (Cloudflare Access,
  oauth2-proxy) doing its own SSO first; otherwise the root password
  is the only thing between those other interfaces and the
  dashboard.

Operators can be allowlisted by tailnet identity email so they skip
the root-password prompt:

```hcl
dashboard_operators = [
  "alice@example.com",
  "*@example.com",
]
```

Each entry is matched against the requesting peer's tsnet whois
login on every dashboard request. Tagged devices (your agents) have
a tag-name login, not a user email, so they never match a wildcard
entry — agent peers can never inherit operator powers through this
path.

`funnel = true` exposes a small allowlist of public-bootstrap routes
(`/api/onboard/{start,poll,claim}`, `/api/cred/*`,
`/api/hitl/operations/*/status`) on `<node>.ts.net:443` so off-tailnet
devices can join and OAuth callbacks can land. **The dashboard itself
is not Funnel-reachable** — Funnel does not replace the tailnet (or
SSH) path for operator access.

## Run under systemd

For anything beyond a quick test, run the gateway as a dedicated
service user so its state directory isn't readable by any
non-root user on the box:

```bash
useradd --system --home /opt/clawpatrol --shell /usr/sbin/nologin clawpatrol
chown -R clawpatrol:clawpatrol /opt/clawpatrol
chmod 700 /opt/clawpatrol
```

Drop the following at
`/etc/systemd/system/clawpatrol-gateway.service`, adjusting the
three paths to wherever you put the binary and config:

```ini
[Unit]
Description=clawpatrol gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=clawpatrol
Group=clawpatrol
WorkingDirectory=/opt/clawpatrol
ExecStart=/usr/local/bin/clawpatrol gateway /opt/clawpatrol/gateway.hcl
Restart=on-failure
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Then:

```bash
systemctl daemon-reload
systemctl enable --now clawpatrol-gateway
journalctl -u clawpatrol-gateway -f       # tail the gateway log
```

If you skip the dedicated-user step, the gateway logs a warning
at startup when `state_dir` or `clawpatrol.db` is readable beyond
owner.

## Security notes

A few footguns worth knowing about before you point an agent at a
production Claw Patrol gateway:

- **Don't run agents on the gateway host.** `clawpatrol run` is
  for client devices — the gateway's `state_dir` holds every
  credential the gateway mints plus the audit log. An agent running on
  the gateway host can read those directly, with or without
  `clawpatrol run` in front. The correct shape is: gateway on
  one box (small VPS, no human logins, no developer tools); your
  laptop / CI runner joins it over WireGuard. `clawpatrol run`
  prints a heads-up if it detects a gateway state db in a common
  location.

- **Lock down `state_dir`.** The systemd snippet above creates a
  dedicated `clawpatrol` service user with mode-700 ownership; if
  you skip that, anyone with shell access to the gateway host can
  read every credential. The gateway warns at startup when
  `state_dir` or `clawpatrol.db` is readable beyond owner.

- **`clawpatrol join --whole-machine` is for client devices
  only.** Running it on the gateway host itself routes the host's
  own traffic through its own WireGuard endpoint — a loop that
  breaks DNS, outbound traffic from the gateway daemon, and the
  dashboard's reachability. Per-process routing (the default
  `clawpatrol join` + `clawpatrol run` shape) is also what most
  people actually want on a multi-purpose laptop, so they don't
  accidentally route every browser tab through the gateway.

## Build from source

Released binaries are the supported path. To build from source
instead — for example to track an unreleased branch — set
`CLAWPATROL_FROM_SOURCE=1` on the installer (requires Go):

```bash
curl -fsSL https://clawpatrol.dev/install.sh | CLAWPATROL_FROM_SOURCE=1 sh
```

Set `CLAWPATROL_REF` to install a non-`main` ref.

## What's next

- [Config reference](/docs/config-reference/) — every HCL field, in detail
- [Rules](/docs/rules/) — gating writes behind a human or LLM
- [Architecture](/docs/architecture/) — how interception works
- [Security model](/docs/security-model/) — what Claw Patrol does and doesn't protect against
