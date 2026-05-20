# Configure the gateway

[Getting Started](/docs/getting-started/) gets you running with
the example config, untouched. This page covers the operational
tuning you reach for as soon as you take the gateway past
"kick-the-tyres" — different join transport, dashboard auth,
where to bind the dashboard, systemd, state-dir hardening, and
the rest.

## Join transport: WireGuard or Tailscale

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
request.** That check runs in the gateway itself — not in the
network — so an unauthenticated request must never reach it,
whether `info_listen` is on loopback, a tailnet IP, or
`0.0.0.0`.

The first time you open the dashboard you set a `root` password.
It lives bcrypt-hashed in `clawpatrol.db` and is checked on every
subsequent request. You can also manage the password from the CLI:

```bash
clawpatrol gateway --set-dashboard-password '<password>' gateway.hcl
clawpatrol gateway --reset-dashboard-password gateway.hcl
```

### Where to bind the dashboard

Network-layer reachability is cheap defence-in-depth on top of the
password. Pick the shape that matches your access model:

- **Loopback (`127.0.0.1:8080`)** — the default in the example.
  Reach the dashboard via SSH tunnel
  (`ssh -L 8080:127.0.0.1:8080 gateway-host`) or a local reverse
  proxy.
- **Tailnet / VPN IP (`100.x.x.x:8080`)** — reachable only from
  your tailnet or WireGuard subnet. List each operator's tailnet
  identity in
  `dashboard_operators` — the email Tailscale uses to identify
  that user — to let them in without typing the password:

  ```hcl
  dashboard_operators = [
    "alice@example.com",
    "bob@example.com",
  ]
  ```

  Tagged devices (agents) never match the allowlist.
- **Public (`0.0.0.0:8080`)** — works, but everyone on the
  internet sees a login page. Front it with an auth proxy
  (Cloudflare Access, oauth2-proxy) if you really need it.

## Run under systemd

For anything beyond a quick test, run the gateway as a dedicated
service user so its state directory (every credential the gateway
holds — CA private key, WireGuard server key, SSH host keys — plus
the audit log) isn't readable by any non-root user on the box:

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
  credential the gateway mints (CA private key, WireGuard server
  key, SSH host keys) plus the audit log. An agent running on
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
- [Approval rules](/docs/approval-rules/) — gating writes behind a human or LLM
- [Architecture](/docs/architecture/) — how interception works
- [Security model](/docs/security-model/) — what Claw Patrol does and doesn't protect against
