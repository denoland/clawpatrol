# CLI Reference

## Installation

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

The installer drops a single Go binary in `~/.local/bin`. The
`clawpatrol` command contains both gateway/operator commands and client
commands for joining and running agent processes.

## Commands

### `clawpatrol gateway init`

Bootstrap a gateway data directory with a starter `gateway.hcl`, CA material,
and gateway state.

```bash
clawpatrol gateway init [--data-dir DIR] [--public-url URL] [--public-ip IP] [--wg-port PORT] [--dash-port PORT] [--tls-port PORT] [--subnet CIDR] [--no-firewall]
```

Options:

- `--data-dir DIR` — where to write gateway config, CA, and state. Defaults to
  the platform gateway data directory.
- `--public-url URL` — public dashboard/join URL to write into the generated
  config. When omitted, `gateway init` derives one from the public IP and
  dashboard port.
- `--public-ip IP` — public IP to use for the WireGuard endpoint. When omitted,
  `gateway init` attempts to detect it.
- `--wg-port PORT` — WireGuard UDP port. Defaults to `51820`.
- `--dash-port PORT` — dashboard and join HTTP port. Defaults to `9080`.
- `--tls-port PORT` — TLS gateway port on the host. Defaults to `8443`.
- `--subnet CIDR` — WireGuard subnet pool. Defaults to `10.55.0.0/24`.
- `--no-firewall` — skip adding iptables `ACCEPT` rules.

After editing `gateway.hcl`, start the gateway with `clawpatrol gateway`.

### `clawpatrol gateway`

Run the long-lived gateway daemon.

```bash
clawpatrol gateway [-config FILE] [--read-only-config]
```

Options:

- `-config FILE` — gateway HCL file to load. Defaults to `config.yaml` for
  compatibility with older invocations.
- `--read-only-config` — reject dashboard writes to the HCL config file.

The daemon loads `gateway.hcl`, starts the dashboard/API listener when
`info_listen` is configured, starts data-plane forwarding, and watches the
config file for reloads.

### `clawpatrol join`

Register the current machine with an existing gateway and prepare it for
Claw Patrol-routed agent traffic.

```bash
clawpatrol join [--hostname NAME] [--profile NAME] [--whole-machine] [--no-trust] [--ca-dir DIR] [--name NAME] <gateway-url>
```

Options:

- `--hostname NAME` — device name shown to gateway approvers. Defaults to
  `os.Hostname()`.
- `--profile NAME` — suggested profile for the device; the approver can still
  change it in the dashboard.
- `--whole-machine` — bring up the generated WireGuard config with `wg-quick`
  so all host traffic routes through the gateway. Without this flag, the join
  persists config and `clawpatrol run` provides per-process routing.
- `--no-trust` — fetch the gateway CA but skip installing it into system trust.
- `--ca-dir DIR` — directory where `ca.crt` and local client state are stored.
- `--name NAME` — Tailscale gateway hostname to look for when the gateway uses
  the Tailscale control plane. Defaults to `clawpatrol`.

### `clawpatrol login`

Complete local Tailscale-oriented setup against a gateway that is already
reachable on the tailnet.

```bash
clawpatrol login [--name NAME] [--ca-dir DIR] [--no-trust] [--no-exit-node]
```

Options:

- `--name NAME` — exit-node hostname to look for on the tailnet.
- `--ca-dir DIR` — directory where the fetched CA is stored.
- `--no-trust` — skip installing the CA into system trust.
- `--no-exit-node` — do not set the Tailscale exit node automatically.

Most users should start with `clawpatrol join <gateway-url>`; it delegates to
`login` only when the gateway's control plane requires the Tailscale path.

### `clawpatrol run`

Run one command with per-process Claw Patrol routing.

```bash
clawpatrol run [-conf FILE] <command> [args...]
```

Options:

- `-conf FILE` — WireGuard config written by `clawpatrol join`. Defaults to the
  standard per-user Claw Patrol config path.

On Linux, `run` creates an isolated network namespace for the child process,
brings up WireGuard inside that namespace, and executes the command there. Use
`join --whole-machine` instead when you want all host traffic routed through the
gateway without wrapping individual commands.

Examples:

```bash
clawpatrol run claude
clawpatrol run python agent.py
```

### `clawpatrol env`

Print shell exports that point common AI/API clients at Claw Patrol-managed
placeholders and the installed CA.

```bash
clawpatrol env [--ca-dir DIR]
```

Options:

- `--ca-dir DIR` — directory containing `ca.crt`.

The command is meant to be sourced from a shell profile or evaluated for a
single session:

```bash
eval "$(clawpatrol env)"
```

Set `CLAWPATROL_NO_ENV=1` to disable env pushdown in shells that source this
helper.

### `clawpatrol status`

Report local install and tunnel state.

```bash
clawpatrol status
```

`status` is read-only and prints the signals that usually explain why traffic
is not flowing: local config presence, CA/trust state, tunnel state, and gateway
reachability.

### `clawpatrol validate`

Parse and compile a gateway HCL config without starting the gateway.

```bash
clawpatrol validate <config.hcl>
```

Use this in CI or before restarting a gateway to catch syntax, reference, and
policy compilation errors.

### `clawpatrol init-ca`

Generate a standalone CA in a directory.

```bash
clawpatrol init-ca DIR
```

This writes `ca.crt` and `ca.key`. Most installations should use
`clawpatrol gateway init` instead, which creates a complete gateway data
directory.

### `clawpatrol uninstall`

Remove local Claw Patrol client setup.

```bash
clawpatrol uninstall [--keep-ca]
```

Options:

- `--keep-ca` — keep local Claw Patrol state and system trust entries.

Without `--keep-ca`, uninstall removes local state directories and trust/env
configuration that were added during setup.

### `clawpatrol version`

Print the build version and git SHA when available.

```bash
clawpatrol version
```

## Configuration and state

Gateway behavior is controlled by `gateway.hcl`; see the
[HCL config reference](/docs/config-reference/). Client commands store local
state under the platform Claw Patrol config directory, including the fetched
`ca.crt` and generated WireGuard config.

## Environment variables

Claw Patrol recognizes a small set of operational environment variables:

| Variable | Purpose |
|---|---|
| `CLAWPATROL_NO_ENV` | Set to `1` to disable `clawpatrol env` pushdown. |
| `CLAWPATROL_TELEMETRY` | Set to `0` to disable telemetry. |
| `DO_NOT_TRACK` | Set to `1` to disable telemetry. |
| `CLAWPATROL_SECRET_<NAME>` | Fallback secret source for credential blocks. Hyphens in names become underscores. |
| `CLAWPATROL_SECRET_<NAME>_CERT`, `_KEY`, `_CA` | mTLS secret material for credential blocks. Values may be inline PEM or `@/path/to/file`. |
| `CLAWPATROL_TUNNEL_<NAME>_AUTHKEY` | Tailscale tunnel auth key fallback. Hyphens in names become underscores. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Export OpenTelemetry metrics when configured. |
| `OTEL_METRIC_EXPORT_INTERVAL` | Override OpenTelemetry metric export interval. |
