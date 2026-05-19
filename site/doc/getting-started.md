# Getting Started

This guide takes you from zero to a working Claw Patrol gateway
with one device wired in. The example config works as-is; once
you want to tune anything, read
[Configure the gateway](/docs/configure-gateway/) next.

Claw Patrol has two pieces: a **gateway** that runs on a server
you control, and one or more **devices** — the machines where
your agents run — that join the gateway and route agent
traffic through it.

## Install

Gateway and device run the **same `clawpatrol` binary** — there's
no separate server package. Install it on both the gateway host
and any machine that will run agents:

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

The installer drops a single binary in `~/.local/bin`. macOS and
Linux on amd64/arm64 are supported.

## Run the gateway

On the server, pick a data directory (anywhere — `/opt/clawpatrol`,
`/srv/clawpatrol`, your home), drop a copy of
[`gateway.example.hcl`](https://github.com/denoland/clawpatrol/blob/main/cmd/clawpatrol/gateway.example.hcl)
into it, open UDP 51820 on the host firewall, and start the
gateway:

```bash
iptables -I INPUT -p udp --dport 51820 -j ACCEPT
clawpatrol gateway /opt/clawpatrol/gateway.hcl
```

The example config binds the dashboard to `127.0.0.1:8080`. Reach
it from your laptop with an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 gateway-host
```

Open `http://127.0.0.1:8080` and set the root password — that's
the operator login. The CA is lazy-minted into sqlite under
`state_dir` on first boot; there's nothing else to pre-create.

That's the gateway side. Paste your real API keys into the
dashboard's credential entries (the example wires up Anthropic,
GitHub, Slack, and the rest with empty slots) and you're ready
to enroll a device.

## Wire a device into the gateway

On any machine where you want to run an agent — your laptop, a
CI runner, an EC2 instance, anywhere you'd otherwise run the
agent directly:

```bash
clawpatrol join http://<gateway-host>:8080
```

You'll see a one-time code. Open the URL it prints, confirm the
code matches in the dashboard, and approve. Once approved the
device is enrolled, the gateway CA is installed in the device's
system trust store, and `clawpatrol env` is wired into your
shell rc.

By default `join` sets up per-process routing: only commands you
wrap with `clawpatrol run` go through the gateway. Pass
`--whole-machine` if you want every packet on the host to route
through it.

On macOS, the first join prompts you to approve the Claw Patrol
Network Extension in **System Settings → Privacy & Security**.

> **Don't run `clawpatrol join --whole-machine` on the gateway
> host itself** — the gateway shouldn't route its own traffic
> through itself; the loop breaks DNS and the dashboard's own
> reachability. For every *other* machine, pointing at the
> gateway is exactly what you want.

## Run an agent

Wrap any command with `clawpatrol run`:

```bash
clawpatrol run -- claude
clawpatrol run -- gh pr create
clawpatrol run -- psql 'host=db user=agent'
```

The gateway intercepts the wrapped process's HTTPS traffic,
matches each request against the rules in `gateway.hcl`, injects
the configured credential, and forwards the request upstream.
The agent never sees the real key.

## Ready to customise?

The example config is enough to kick the tyres, but before you
point a real workload at the gateway you'll want to change the
dashboard bind, paste real credentials, swap to Tailscale if
that fits, run under systemd, and lock down `state_dir`. Continue
with [Configure the gateway](/docs/configure-gateway/).

## What's next

- [Configure the gateway](/docs/configure-gateway/) — operational tuning
- [Architecture](/docs/architecture/) — how interception works
- [CLI](/docs/cli/) — full command reference
- [Config reference](/docs/config-reference/) — HCL grammar
- [Approval rules](/docs/approval-rules/) — gating writes behind a human or LLM
- [Security model](/docs/security-model/) — what Claw Patrol does and doesn't protect against
