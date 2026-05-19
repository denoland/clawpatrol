# Getting Started

Claw Patrol is a firewall for AI agents. It has two pieces: a
**gateway** that runs on a server you control and one or more
**devices** (your laptop, a CI runner) that join the gateway and
route agent traffic through it.

This guide walks the fast path: stand up a gateway, join your
laptop, and run an agent.

## Install

Gateway and device run the **same `clawpatrol` binary** — there's no
separate server package. Install it on both the gateway host and any
machine you want to enroll:

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

The installer drops a single binary in `~/.local/bin`. macOS and Linux
on amd64/arm64 are supported. To build from source instead, set
`CLAWPATROL_FROM_SOURCE=1` (requires Go and `gh auth login`).

## Configure the gateway

On the server, pick a data directory (anywhere — `/opt/clawpatrol`,
`/srv/clawpatrol`, your home), drop a copy of
[`gateway.example.hcl`](https://github.com/denoland/clawpatrol/blob/main/cmd/clawpatrol/gateway.example.hcl)
into it, and edit the operational fields:

```hcl
info_listen = "127.0.0.1:9080"   # bind the dashboard private — see below
public_url  = "https://gw.example.com"
admin_email = "you@example.com"
state_dir   = "/opt/clawpatrol"

control        = "wireguard"
wg_subnet_cidr = "10.55.0.0/24"
```

(Prefer Tailscale? Swap `control` to `"tailscale"`, add `funnel =
true`, `listen = ":8443"`, and `oauth_client_id` /
`oauth_client_secret` / `tailscale_tags`. Embedded tsnet joins the
tailnet in-process, no UDP port or iptables rule needed. The rest
of this guide works the same way.)

**Dashboard auth is required at the app layer, on every bind.** The
dashboard holds the credential vault, so an unauthenticated request
must never reach it — regardless of whether `info_listen` is on
loopback, a tailnet IP, or `0.0.0.0`. The first time you open the
dashboard you set a "root" password; it lives bcrypt-hashed in
`clawpatrol.db` and is checked on every subsequent request. To skip
the web first-run flow (or rotate the password later), pass
`--set-dashboard-password '<pw>'` or `--reset-dashboard-password`
to `clawpatrol gateway`.

`info_listen` still wants to be private if you can manage it —
network-layer reachability is cheap defence-in-depth on top of the
password. Recommended shapes:

- **`127.0.0.1:9080`** — loopback. Reach the dashboard via SSH tunnel
  (`ssh -L 9080:127.0.0.1:9080 gateway-host`) or a local reverse proxy.
- **A tailnet / VPN IP** — e.g. `100.x.x.x:9080`. Add
  `dashboard_operators = ["you@yourdomain.com"]` to let your tailnet
  identity pass without typing the password. Tagged devices (agents)
  never match the allowlist.
- **Public** — works, but everyone on the internet sees a login page.
  Front it with an auth proxy (Cloudflare Access, oauth2-proxy) if
  you really need it.

The CA is lazy-minted into sqlite under `state_dir` on first boot —
nothing to pre-create besides the directory itself. See
[Config reference](/docs/config-reference/) for the full HCL grammar
and the rest of the credential / endpoint / rule blocks.

## Run the gateway

Open the WireGuard UDP port on the host firewall —
`iptables -I INPUT -p udp --dport 51820 -j ACCEPT`. Leave the
dashboard port closed to the public internet; reach it via the
private bind you chose above.

```bash
clawpatrol gateway /opt/clawpatrol/gateway.hcl
```

For a loopback bind, reach the dashboard from your laptop with
`ssh -L 9080:127.0.0.1:9080 gateway-host` and open
`http://127.0.0.1:9080`. For a tailnet bind, just open the tailnet
URL.

### Under systemd

Create a dedicated service user so the gateway's state directory
(CA private key, OAuth tokens, audit log) isn't readable by any
human or agent on the box:

```bash
useradd --system --home /opt/clawpatrol --shell /usr/sbin/nologin clawpatrol
chown -R clawpatrol:clawpatrol /opt/clawpatrol
chmod 700 /opt/clawpatrol
```

Drop the following at `/etc/systemd/system/clawpatrol-gateway.service`,
adjusting the three paths to wherever you put the binary and config:

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

If you skip the dedicated-user step, the gateway logs a warning at
startup when `state_dir` or `clawpatrol.db` is readable beyond owner.

## Join a device

On the machine you want to route through the gateway:

```bash
clawpatrol join http://<gateway-host>:9080
```

You'll see a one-time code. Open the URL it prints, confirm the code
matches, and approve. Once approved the device is enrolled, the gateway
CA is installed in your system trust store, and `clawpatrol env` is wired
into your shell rc.

By default `join` sets up per-process routing: only commands you wrap
with `clawpatrol run` go through the gateway. Pass `--whole-machine` if
you want every packet on the host to route through it.

On macOS, the first join prompts you to approve the Claw Patrol
Network Extension in **System Settings → Privacy & Security**.

## Run an agent

Wrap any command with `clawpatrol run`:

```bash
clawpatrol run -- claude
clawpatrol run -- gh pr create
clawpatrol run -- psql 'host=db user=agent'
```

The gateway intercepts the wrapped process's HTTPS traffic, matches each
request against the rules in `gateway.hcl`, injects the configured
credential, and forwards the request upstream. The agent never sees the
real key.

## Security notes

A few footguns worth knowing about before you point an agent at a
Claw Patrol gateway:

- **Don't run agents on the gateway host.** `clawpatrol run` is for
  client devices — the gateway's `state_dir` holds the CA private
  key, OAuth tokens, and audit log. An agent running on the gateway
  host can read those directly, with or without `clawpatrol run` in
  front. The correct shape is: gateway on one box (small VPS, no
  human logins, no developer tools); your laptop / CI runner joins
  it over WireGuard. `clawpatrol run` prints a heads-up if it
  detects a gateway state db in a common location.

- **Lock down `state_dir`.** The gateway warns at startup when
  `state_dir` or `clawpatrol.db` is readable beyond owner. The
  systemd snippet above creates a dedicated `clawpatrol` service
  user with mode-700 ownership; if you skip that, anyone with
  shell access to the gateway host can read every credential.

- **`clawpatrol join --whole-machine` is for client devices only.**
  Running it on (or pointed at) the gateway host itself routes the
  host's own traffic through its own WireGuard endpoint — a loop
  that breaks DNS, outbound traffic from the gateway daemon, and
  the dashboard's reachability. Per-process routing (the default
  `clawpatrol join` + `clawpatrol run` shape) is also what most
  people actually want on a multi-purpose laptop, so they don't
  accidentally route every browser tab through the gateway.

## What's next

- [Architecture](/docs/architecture/) — how interception works
- [CLI](/docs/cli/) — full command reference
- [Config reference](/docs/config-reference/) — HCL grammar
- [Approval rules](/docs/approval-rules/) — gating writes behind a human or LLM
- [Security model](/docs/security-model/) — what Claw Patrol does and doesn't protect against
