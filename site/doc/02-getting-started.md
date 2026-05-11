# Getting Started

Claw Patrol has two pieces: a **gateway** that runs on a server you control
and one or more **devices** (your laptop, a CI runner) that join the
gateway and route agent traffic through it.

This guide walks the fast path: stand up a gateway, join your laptop,
and run an agent.

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

## Stand up a gateway

On the server:

```bash
clawpatrol gateway init
```

This generates a CA, writes `/etc/clawpatrol/gateway.hcl`, opens
`udp/51820` and `tcp/9080`, and installs a systemd unit. Start it:

```bash
systemctl enable --now clawpatrol-gateway
```

The dashboard is at `http://<gateway-host>:9080`. The `join` command
printed by `gateway init` is what your devices will run.

See [Self-hosting](/docs/06-self-hosting/) for the gateway host
requirements and [Gateway](/docs/07-gateway/) for the config reference.

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

On macOS, the first join prompts you to approve the Claw Patrol Network
Extension in **System Settings → Privacy & Security**.

See [Onboarding](/docs/03-onboarding/) for the full join flow.

## Run an agent

Wrap any command with `clawpatrol run`:

```bash
clawpatrol run claude
clawpatrol run gh pr create
clawpatrol run -- psql 'host=db user=agent'
```

The gateway intercepts the wrapped process's HTTPS traffic, matches each
request against the rules in `gateway.hcl`, injects the configured
credential, and forwards the request upstream. The agent never sees the
real key.

## What's next

- [Architecture](/docs/04-architecture/) — how interception works
- [CLI](/docs/05-cli/) — full command reference
- [Approval rules](/docs/12-approval-rules/) — gating writes behind a human or LLM
- [Security model](/docs/11-security-model/) — what Claw Patrol does and doesn't protect against
