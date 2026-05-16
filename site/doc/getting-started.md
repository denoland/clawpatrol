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
[`gateway.example.hcl`](https://github.com/denoland/clawpatrol/blob/main/gateway.example.hcl)
into it, and edit the operational fields:

```hcl
info_listen = "127.0.0.1:9080"   # bind the dashboard private — see below
public_url  = "https://gw.example.com"
admin_email = "you@example.com"
state_dir   = "/opt/clawpatrol"

control        = "wireguard"
wg_subnet_cidr = "10.55.0.0/24"
```

**`info_listen` should bind privately.** The dashboard holds the
credential vault — the gateway refuses to boot when `info_listen`
is publicly bound (`0.0.0.0`, `::`, or a routable IP) without
`dashboard_secret`. When `info_listen` is on a private interface
(loopback / RFC1918 / RFC4193 ULA / link-local / CGNAT including
Tailscale's 100.64.0.0/10) the network IS the trust boundary —
no `dashboard_secret` needed. Recommended shapes, ranked:

- **`127.0.0.1:9080`** — loopback. No `dashboard_secret` required.
  Reach the dashboard via SSH tunnel (`ssh -L 9080:127.0.0.1:9080
  gateway-host`) or front it with a local reverse proxy.
- **A tailnet / VPN IP** — e.g. `100.x.x.x:9080`. No
  `dashboard_secret` required. Tailscale whois attributes audit
  events to each operator (see [Architecture](/docs/architecture/)).
- **Public + `dashboard_secret`** — works if you really need it,
  but logs a warning. Pair with an auth proxy
  (Cloudflare Access, oauth2-proxy) before pointing real users
  at it.

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

### Put the dashboard on an unlisted host

For internet-reachable gateways, run Claw Patrol on a VM dedicated to
the gateway and publish the dashboard at a high-entropy hostname, for
example `https://cp-7v4m9k2q.example.com`. Set `public_url` to that
full URL, keep `dashboard_secret` enabled, and point `wg_endpoint` at a
separate stable WireGuard host or port if needed.

Treat the hostname as exposure reduction, not authentication: do not
link to it from public pages, disable directory listings / default
landing pages on any reverse proxy, add `X-Robots-Tag: noindex` if your
proxy can, and avoid reusing the VM for sites that may be indexed. The
dashboard secret and host firewall remain the security controls.

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
