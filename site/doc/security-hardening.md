# Security hardening

Recommended production configuration for the Claw Patrol gateway.
None of this is required to run the gateway — the defaults are
chosen for first-boot ergonomics — but in production each of the
settings below closes a real attack path.

If you're new here, read [the security model](./security-model.md)
first for the threat model these settings exist to defend against.

## Limit `tunnel "local_command"`

`tunnel "local_command"` spawns an arbitrary OS process whose argv
comes straight from the HCL. That's the right shape for proxies
like `cloud_sql_proxy` and `kubectl port-forward`, but it also
means: *any* operator who can write to `gateway.hcl` can run
arbitrary commands as the gateway service user.

The `/api/config/save` endpoint authenticates with
`dashboard_secret`. A leak of that secret (HAR file in a support
ticket, browser dev-tools screenshot, mis-handled cookie) ends in
RCE on the gateway host if the attacker can introduce a new
`tunnel "local_command"` block.

Two opt-in mitigations ship in the gateway:

### Confirmation gate on new blocks

The dashboard's `Settings → gateway.hcl` editor shows a **red
warning** with the names of every newly-introduced `local_command`
tunnel and requires the operator to type `confirm` before the Save
button enables. The server enforces the same gate independently:
`/api/config/save` rejects with `412 Precondition Failed` when the
request would introduce new `local_command` blocks without
`confirm_high_risk: true` in the JSON body.

This is on by default. There's no way to disable it (and no
operational reason to — the gesture is one extra keystroke per
high-risk change).

### `--allow-tunnels` boot flag

```bash
clawpatrol gateway \
  --allow-tunnels=ssh_command,kubernetes_port_forward \
  /etc/clawpatrol/gateway.hcl
```

The gateway rejects any HCL — at boot and through every dashboard
save — that declares a `tunnel "..."` block whose plugin type isn't
in the comma-separated allowlist. Omitting `local_command` here is
the strongest mitigation: a leaked dashboard secret can't add an
RCE-shaped tunnel because the server refuses to load one.

Recommended starting allowlist: whatever tunnel types your config
already uses, minus `local_command` if you don't deliberately
need it. Add `local_command` back when you have a use case
(`cloud_sql_proxy`, etc.) and review every new instance through
the confirmation gate above.

Unset (the default) means "no restriction" — preserves the current
behaviour so existing deployments aren't broken on upgrade.

## `--read-only-config`

```bash
clawpatrol gateway --read-only-config /etc/clawpatrol/gateway.hcl
```

Disables the dashboard's HCL editor entirely. Operators edit
`gateway.hcl` on disk and reload by restarting the gateway.

Combined with file-system permissions (`gateway.hcl` owned by
`root`, readable by the gateway user, writable only by root),
this removes the gateway HTTP API from the configuration-write
attack surface. The dashboard secret only buys read access.

## Systemd sandboxing

If you run the gateway under systemd, harden the unit file. None
of these prevent an in-process compromise from abusing the
gateway's own credentials, but they raise the cost of a privilege-
escalation chain from inside a compromised tunnel process.

```ini
[Service]
ExecStart=/usr/local/bin/clawpatrol gateway /etc/clawpatrol/gateway.hcl
User=clawpatrol
Group=clawpatrol

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Allow read/write only where the gateway actually writes:
#   state_dir (default ~/.clawpatrol), and the directory containing
#   gateway.hcl (so atomic save's tmp + rename can write).
ReadWritePaths=/var/lib/clawpatrol /etc/clawpatrol
```

`NoNewPrivileges=true` is the headline one — it stops a child
process from gaining privileges through setuid binaries, which
neutralises whole classes of escape from a compromised
`local_command` tunnel.

## Dashboard secret hygiene

The dashboard secret is a bearer credential. Treat it like any
other long-lived secret:

- Don't commit it to shared repositories.
- Don't paste it into chat or pastebins.
- Avoid screenshotting the dashboard's URL when it contains the
  secret in a query parameter — the cookie is the long-lived
  form; URLs in screenshots and browser history are not.
- Rotate it after any suspected exposure: edit `gateway.hcl` on
  disk, restart the gateway, and re-bookmark.

`--read-only-config` and `--allow-tunnels=...` (without
`local_command`) together turn a dashboard-secret leak from a
host-compromise event into a read-only information leak — the
same severity tier as exposing the gateway's request log.
