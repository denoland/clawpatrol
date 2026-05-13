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
listen           = "0.0.0.0:8443"
info_listen      = "0.0.0.0:9080"
public_url       = "http://gw.example.com:9080"
admin_email      = "you@example.com"
dashboard_secret = "<long random string>"
state_dir        = "/opt/clawpatrol/state"

control        = "wireguard"
wg_endpoint    = "gw.example.com:51820"
wg_subnet_cidr = "10.55.0.0/24"
```

The CA is lazy-minted into sqlite under `state_dir` on first boot —
nothing to pre-create besides the directory itself. See
[Config reference](/docs/config-reference/) for the full HCL grammar
and the rest of the credential / endpoint / rule blocks.

## Run the gateway

Open the WireGuard UDP port and the dashboard TCP port on the host
firewall (e.g. `iptables -I INPUT -p udp --dport 51820 -j ACCEPT`,
same for `tcp/9080`), then:

```bash
clawpatrol gateway /opt/clawpatrol/gateway.hcl
```

The dashboard is at `http://<gateway-host>:9080`.

### Under systemd

Drop the following at `/etc/systemd/system/clawpatrol-gateway.service`,
adjusting the three paths to wherever you put the binary and config:

```ini
[Unit]
Description=clawpatrol gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
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

## What's next

- [Architecture](/docs/architecture/) — how interception works
- [CLI](/docs/cli/) — full command reference
- [Config reference](/docs/config-reference/) — HCL grammar
- [Approval rules](/docs/approval-rules/) — gating writes behind a human or LLM
- [Security model](/docs/security-model/) — what Claw Patrol does and doesn't protect against
