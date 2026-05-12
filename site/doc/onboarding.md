# Onboarding

Onboarding connects a machine to a Claw Patrol gateway, installs the gateway CA
locally, and prepares either per-process or whole-machine traffic routing.

For most client machines the flow is:

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
clawpatrol join https://gateway.example.com
```

An operator must approve the device from the gateway dashboard before the join
finishes.

## What `join` does

`clawpatrol join <gateway-url>` runs a device-flow enrollment against the
gateway:

1. Downloads the gateway CA into the local Claw Patrol config directory.
2. Starts an onboard request with the gateway, including the local hostname and
   optional profile suggestion.
3. Prints or opens the approval URL for an operator.
4. Polls until the operator approves the device.
5. Writes local tunnel/client configuration.
6. Installs the CA into system trust unless `--no-trust` is set.
7. For Tailscale-backed gateways, completes the Tailscale-specific `login`
   path and can set the gateway as an exit node.

Common flags:

```bash
clawpatrol join https://gateway.example.com \
  --hostname ci-runner-42 \
  --profile default
```

- `--hostname NAME` — device name shown in the dashboard.
- `--profile NAME` — suggested profile for this device.
- `--whole-machine` — route all host traffic through the gateway with the
  generated WireGuard config.
- `--no-trust` — fetch the CA but do not install it into system trust.
- `--ca-dir DIR` — choose where local CA/client state is written.

## Per-process routing

The default join mode writes local config but does not route the whole host.
Wrap an agent command with `clawpatrol run` when you want that command's
traffic to go through the gateway:

```bash
clawpatrol run claude
clawpatrol run python agent.py
```

On Linux, `run` creates a network namespace, brings up WireGuard inside it, and
executes the child command there. The rest of the machine keeps its normal
network path. This is the recommended mode for agent sessions because it scopes
routing to the process tree you explicitly launched.

## Whole-machine routing

Use whole-machine mode when the entire host should route through Claw Patrol:

```bash
clawpatrol join https://gateway.example.com --whole-machine
```

This brings up the generated WireGuard configuration with host-level routing.
It is useful for dedicated workers, shared jump boxes, or environments where
wrapping each process is impractical. Be careful when enabling it over SSH: the
CLI includes safeguards, but changing the default route can interrupt remote
sessions if the host network is unusual.

## Tailscale-backed gateways

Some gateways use Tailscale as the control plane. `clawpatrol join` detects
that mode from the gateway response and delegates to the Tailscale setup path.
You can also run that path directly when the gateway is already reachable on
the tailnet:

```bash
clawpatrol login --name clawpatrol
```

Useful flags:

- `--name NAME` — Tailscale exit-node hostname to locate.
- `--no-exit-node` — skip automatically selecting the gateway as an exit node.
- `--no-trust` — skip CA trust installation.

## Gateway bootstrap for operators

Gateway operators start by creating a gateway data directory:

```bash
clawpatrol gateway init --data-dir /var/lib/clawpatrol
```

Then edit the generated `gateway.hcl` and start the daemon:

```bash
clawpatrol gateway -config /var/lib/clawpatrol/gateway.hcl
```

The dashboard/API listener is controlled by the `info_listen` field in
`gateway.hcl`. Public URL, control plane, WireGuard, Tailscale, policy,
credential, endpoint, tunnel, and rule settings are documented in the
[HCL config reference](/docs/config-reference/).

## Approving devices

When a user runs `clawpatrol join`, the gateway creates a pending onboard
request. Operators approve it from the dashboard. The approver can assign or
change the device profile before approval. Profiles select the endpoints a
device may reach; rules attached to those endpoints still enforce policy at
request time.

## Agent environment

After joining, shells can evaluate the generated environment helper:

```bash
eval "$(clawpatrol env)"
```

The helper points common clients at the Claw Patrol CA and placeholder-based
credential values. Set `CLAWPATROL_NO_ENV=1` to disable this env pushdown for a
shell.

Secrets themselves live on the gateway side in credential blocks, OAuth-backed
credential storage, or `CLAWPATROL_SECRET_<NAME>` environment fallbacks. The
agent sees placeholders; the gateway injects real credentials when a matching
endpoint handles the request.

## Checking and removing setup

Use `status` to diagnose local setup:

```bash
clawpatrol status
```

Remove local client setup with:

```bash
clawpatrol uninstall
```

Pass `--keep-ca` if you need to preserve local Claw Patrol state and trust
entries while removing other setup pieces.
