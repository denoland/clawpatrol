# CLI Reference

The `clawpatrol` binary is the unified entry point for both the
gateway server and the client tools. Same binary, different
subcommands.

## Install

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

Statically-linked Go binary, dropped in `~/.local/bin`. macOS and
Linux on amd64 + arm64. Set `CLAWPATROL_FROM_SOURCE=1` to build from
source instead (requires Go + `gh auth login`).

## Commands

### `clawpatrol gateway`

Run the gateway daemon against an HCL config. Start from
[`gateway.example.hcl`](https://github.com/denoland/clawpatrol/blob/main/examples/gateway.example.hcl)
— see [Getting Started](/docs/getting-started/) for the operational
fields you need to edit.

```bash
clawpatrol gateway <config.hcl>
```

By default the gateway is read-only-config: the dashboard can
generate HCL from observed actions, but it will not edit the running
file. Set `dashboard_config_writes = true` in `gateway {}` to let the
dashboard append generated rules after validating the full candidate
config and hot-reloading it. Git-managed deployments should leave it
false and push edits through their normal review/deploy flow. See
[config-reference](config-reference) for the HCL grammar.

### `clawpatrol join`

Enroll the current device with a gateway. Prints a one-time code,
opens the dashboard so an operator can confirm and assign a
profile, persists the WireGuard conf, and installs the CA in your
trust store. Falls back to the Tailscale path (see `login` below)
when the gateway runs in Tailscale mode.

```bash
clawpatrol join <gateway-url> [flags]
```

| Flag | Default | Notes |
|---|---|---|
| `--hostname NAME` | OS hostname | Device name registered with the gateway |
| `--profile NAME` | gateway default | Profile to assign at approval time |
| `--whole-machine` | off | Route every packet through the gateway. Linux installs system Tailscale (or `wg-quick` for WG gateways); macOS uses the NE in whole-host config. Default: per-process via `clawpatrol run`. |
| `--no-trust` | off | Fetch the CA but skip system trust install |
| `--ca-dir DIR` | `~/.clawpatrol` | Where to store the fetched CA |
| `--name NAME` | `clawpatrol` | Exit-node hostname (Tailscale gateway, `--whole-machine` only) |

### `clawpatrol login`

Tailscale-based onboarding alternative for fleets already on a
tailnet. Joins the device to the tailnet, finds the gateway by its
exit-node hostname, and installs the CA.

```bash
clawpatrol login [flags]
```

| Flag | Default | Notes |
|---|---|---|
| `--name NAME` | `clawpatrol` | Exit-node hostname to look for on the tailnet |
| `--no-trust` | off | Fetch the CA but skip system trust install |
| `--no-exit-node` | off | Skip setting the tailscale exit-node (run manually) |

### `clawpatrol run`

Run a command with its traffic routed through the joined gateway.

```bash
clawpatrol run [--conf <path>] -- <command> [args...]
```

`--conf` points at the WG conf written by `clawpatrol join`; defaults
to the standard location so you rarely need it. On Linux the wrapped
command runs in an unprivileged user namespace with a private WG
tunnel; on macOS the Network Extension does the capture.

```bash
clawpatrol run -- claude
clawpatrol run -- gh pr create
clawpatrol run -- psql 'host=db user=agent'
```

The agent sees a normal network — outbound flows just route through
the gateway, which matches each request against the rules, injects
the configured credential, and forwards.

### `clawpatrol test`

Replay recorded gateway actions against a candidate HCL policy and
report verdict drift.

```bash
clawpatrol test <config.hcl> <fixture.json | fixture-dir>
```

See [Testing](clawpatrol-test) for the fixture format and
CI integration. Exit 0 = all match, 1 = drift, 2 = usage/config
error.

### `clawpatrol validate`

Parse and compile a gateway HCL config, then exit. Use it in CI to
catch typos before they hit production.

```bash
clawpatrol validate <config.hcl>
```

`validate` runs the same load path the daemon does, so any
[external plugin](plugins) referenced from the file is spawned and
its manifest is checked. Beyond the HCL pipeline it also runs a
schema-only pass that exercises every plugin-declared facet’s CEL
env and resolves every plugin endpoint’s `Family` against the
facet registry — catches authoring bugs (typo’d Family, invalid
identifier in a facet name, …) the operator’s HCL didn’t happen to
exercise. The success line names what loaded:

```
ok: gateway.hcl — 7 endpoints across 3 profile(s)
  plugin "example" v0.1: 2 facet(s), 1 credential type(s), 1 tunnel type(s), 3 endpoint type(s)
```

### `clawpatrol status`

Report device install state — whether `join`/`login` ran, whether
the CA is trusted, whether the WG conf or tailnet membership is
healthy.

```bash
clawpatrol status
```

### `clawpatrol uninstall`

Tear down everything `join` / `login` put on this machine — stops
the macOS Network Extension, brings down the WG interface, removes
the CA from system trust, drops per-user state dirs, strips the
shell-rc.

```bash
clawpatrol uninstall [-y] [--keep-ca] [--keep-conf]
```

### `clawpatrol env`

Print the shell exports clawpatrol injects when wrapping a command
(`SSL_CERT_FILE`, credential-placeholder env vars). Source from
your shell rc if you need them outside `clawpatrol run`.

```bash
eval "$(clawpatrol env)"
```

### `clawpatrol version`

Print the version. Also accepts `-v` and `--version`.

## Environment variables

Most configuration lives in `gateway.hcl` on the gateway side. A few
device-side knobs:

| Variable | Effect |
|---|---|
| `CLAWPATROL_RUN_CONF` | Override the WG conf path `clawpatrol run` reads |
| `CLAWPATROL_NO_ENV` | Skip the env pushdown (`SSL_CERT_FILE`, placeholders) when wrapping a command |
| `CLAWPATROL_TELEMETRY` | `0` to disable telemetry (same as `DO_NOT_TRACK=1`) |
| `DO_NOT_TRACK` | Standard opt-out, honored |
| `TS_AUTHKEY` | Used by `clawpatrol login` to authenticate to Tailscale non-interactively |

## Data directories

Where state lives, by role:

**Gateway host** — the operator picks the location; nothing is
hardcoded. A typical layout under `/opt/clawpatrol/`:

```
gateway.hcl              HCL config (operator-edited)
state/clawpatrol.db      SQLite — everything else
```

`state_dir` in the HCL points at the sqlite directory. The DB holds
the CA cert + key, WireGuard server key, SSH host keys, sessions,
audit log, telemetry UUID, and DNS-VIP allocations.

**Device** (set up by `join` / `login`):

```
~/.clawpatrol/
  ca.crt                  Fetched gateway CA
~/.config/clawpatrol/
  wg.conf                 Per-device WireGuard config (join path)
```
