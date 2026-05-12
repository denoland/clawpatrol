# Onboarding

`clawpatrol onboard` is an interactive setup wizard that prepares your machine
to run AI agents through Claw Patrol. It connects to an Claw Patrol gateway, discovers
your existing API keys, imports them into the gateway, and configures your
system so that `clawpatrol run` can transparently inject those secrets into
agent traffic.

## Onboard walkthrough

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
clawpatrol onboard
```

The wizard walks you through a series of prompts. On a typical run it will:

1. **Select a gateway** — local or a remote (self-hosted)
   instance.
2. **Start the gateway** — on macOS this is a launchd background service; on
   Linux you choose between a systemd unit or an ephemeral process.
3. **Register this machine** as a device on the gateway.
4. **Install the CA certificate** so the gateway can intercept HTTPS traffic.
5. **Discover secrets** — scans environment variables and config files for
   known API keys (Anthropic, OpenAI, Gemini, OpenRouter, GitHub, Slack,
   Grafana, Telegram, Notion, and others). You pick which ones to import.
6. **Replace local credentials with placeholders** — the originals are
   backed up, and the files that held them now contain
   `CLAWPATROL_PLACEHOLDER_*` tokens. This way the agent never sees your real
   keys; they are injected by the gateway at request time.

When the wizard finishes you'll have:

| Path | Contents |
| --- | --- |
| `~/.clawpatrol/device.json` | Device registration (server URL + device token) |
| `~/.clawpatrol/ca.pem` | Gateway CA certificate |
| `~/.clawpatrol/ca-bundle.pem` (macOS) | System roots + Claw Patrol CA, used by `SSL_CERT_FILE` |
| `~/.clawpatrol/env.sh` (macOS) | Shell exports for the CA bundle |
| `~/.clawpatrol/data/gateway.json` | Persisted bind address chosen during onboarding |

The dashboard is available at `http://localhost:8080`.

### macOS note

On first run macOS will prompt you to approve the Claw Patrol Network Extension
in **System Settings → Privacy & Security**. The wizard waits for this
approval before continuing.

## Running agents

Once onboarded, wrap any command with `clawpatrol run`:

```bash
clawpatrol run --name openclaw -- openclaw gateway
clawpatrol run -- python agent.py
```

The gateway intercepts the agent's HTTPS requests, matches them against your
configured integrations (by hostname), injects the real API key, forwards
the request upstream, and logs it. When the command exits, the session ends.

Options:

- `--name NAME` — label for this session (defaults to the command name).
- `--profile PROFILE` — select a specific integration profile instead of the
  default one.
- `--no-expose` — (Linux only) don't tunnel the wrapped command's TCP
  listeners back to the host network. By default Claw Patrol auto-tunnels them.

If you set up a local gateway but it is not running when you call
`clawpatrol run`, Claw Patrol automatically spawns an ephemeral gateway for the
lifetime of the command. No manual restart needed.

## OpenClaw integration

If OpenClaw is installed on your machine, `clawpatrol onboard` detects it and
offers to wrap its daemon so that all OpenClaw agent traffic goes through
the Claw Patrol gateway automatically.

### Automatic setup

During onboarding, the wizard looks for an existing OpenClaw daemon:

- **macOS** — checks for a launchd agent at
  `~/Library/LaunchAgents/ai.openclaw.gateway.plist`. If found, it rewrites
  the plist's `ProgramArguments` to prepend `clawpatrol --name openclaw --` and
  updates `NODE_EXTRA_CA_CERTS` to point to the Claw Patrol CA bundle. The
  original plist is backed up with a `.bak` extension. The daemon is then
  reloaded automatically.
- **Linux** — checks for `openclaw*.service` user systemd units. If found,
  it writes a systemd drop-in override at
  `~/.config/systemd/user/<unit>.d/clawpatrol.conf` that prepends
  `clawpatrol run --name openclaw --` to the unit's `ExecStart`. The unit is
  reloaded and restarted automatically.

In both cases the wizard confirms before making changes.

### Manual setup

If you installed OpenClaw after onboarding, or prefer to set it up
yourself, run the OpenClaw daemon through `clawpatrol run` directly:

```bash
clawpatrol run --name openclaw -- openclaw gateway
```

For a persistent setup, modify the OpenClaw service definition to prepend
`clawpatrol run --name openclaw --` to the existing command. For example, in a
systemd unit:

```ini
ExecStart=/path/to/clawpatrol run --name openclaw -- /path/to/openclaw gateway
```

## Linux gateway options

On Linux, `clawpatrol onboard` asks how you want to run the gateway. The
choices are:

**Systemd user unit** — runs as your user, managed by `systemctl --user`.
Optionally enable *linger* so the gateway starts at boot and survives
logout. Best for single-user machines or personal dev setups.

**Systemd system unit** — runs as a dedicated `clawpatrol` system user, managed
by `systemctl` (requires sudo). Data lives in `/var/lib/clawpatrol/`. Best for
shared machines or server deployments.

**Ephemeral** — no persistent service. The gateway is spawned on demand by
`clawpatrol onboard` or `clawpatrol run` and dies when the parent process exits.
Good for quick experiments, but concurrent `clawpatrol run` invocations share a
single gateway that stops when the first one exits. Use a systemd unit if
you need concurrent sessions.

You also choose a bind address (loopback, LAN IP, or custom). Loopback is
the default and doesn't require authentication beyond the local dev token.
A non-loopback bind requires browser-based OAuth sign-in.

## Remote gateways

Instead of running a local gateway you can point at a self-hosted
Claw Patrol gateway URL. Remote onboarding skips local gateway setup
entirely. You authenticate via an OAuth device-code flow (a
browser window opens for sign-in), then the wizard registers your
device and discovers secrets as usual.

## Managing secrets

After onboarding, open the dashboard at `http://localhost:8080` to add,
remove, or edit integrations. You can also re-run `clawpatrol onboard` to
re-discover secrets that were added since the initial setup.

### 1Password-backed credentials

If you'd rather not paste API keys into the dashboard or stash them in
shell env vars, declare them as `credential "1password" "<name>"` blocks
in `gateway.hcl`. The gateway reads each secret via the 1Password CLI
(`op read op://Vault/Item/field`) the first time it's needed and caches
the value for 60 seconds (configurable via `ttl`).

Prerequisites on the gateway host:

1. Install the [1Password CLI][op-cli] (`op` must be on `$PATH`).
2. Sign in once with `op signin` — the gateway inherits the resulting
   session token from its environment. For unattended hosts, use a
   service-account token (`OP_SERVICE_ACCOUNT_TOKEN`) and skip the
   interactive signin step.
3. Reload the gateway. Op-read errors fail closed: a missing or
   unauthorized ref returns 502 to the agent rather than forwarding an
   un-credentialed request upstream.

Example:

```hcl
credential "1password" "openai-prod" {
  ref = "op://Engineering/OpenAI/api_key"
}

endpoint "https" "openai" {
  hosts      = ["api.openai.com"]
  credential = openai-prod
}
```

[op-cli]: https://developer.1password.com/docs/cli/get-started/

## Uninstalling

```bash
clawpatrol offboard
```

This stops the gateway, removes the Network Extension (macOS) or systemd
service (Linux), and optionally deletes all data in `~/.clawpatrol/`.
