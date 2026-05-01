# Onboarding

`unclaw onboard` is a platform-aware setup routine. It ensures a gateway is
reachable, registers this machine as a _device_, and installs the gateway's CA
where wrapped commands find it. Once onboarding has run, `unclaw run` reuses the
device config — and, when the configured gateway is local and unreachable,
auto-spawns an ephemeral one for the lifetime of the wrapped command.

Source of truth: `src/onboard/index.ts`. For the gateway's own architecture and
request-handling semantics, see [07-gateway.md](../07-gateway.md).

## Gateway lifetime

The gateway runs in one of three modes.

| Mode                     | Started by                | Lifetime                                         | Data dir                              |
| ------------------------ | ------------------------- | ------------------------------------------------ | ------------------------------------- |
| launchd user agent (mac) | `runMacosOnboard`         | persists; `launchctl` managed                    | `~/.unclaw/data`                      |
| systemd user/system unit | `ensureLocalLinuxGateway` | persists; `systemctl` managed                    | `~/.unclaw/data` or `/var/lib/unclaw` |
| Ephemeral (linux)        | `unclaw onboard` / `run`  | tied to invoking process; SIGTERM on parent exit | `~/.unclaw/data`                      |

The ephemeral path is `spawnManagedGateway` in `src/gateway-runner.ts`. It
spawns with `detached: false`, never calls `child.unref()`, never writes a pid
file that outlives the parent, and installs `SIGINT`/`SIGTERM`/`SIGHUP`
forwarders that stop the child before the parent exits. Each invocation owns its
own gateway.

## Top-level dispatch

```
unclaw onboard
  |
  +-- darwin  -> runMacosOnboard                 (src/onboard/macos.ts)
  |              ensureLocalGateway (launchd user agent)
  |              installApp + waitForExtension
  |              registerDeviceApi + downloadCA + createCaBundle
  |              importSecrets
  |              wrapOpenClawDaemon (optional)
  |
  +-- linux   -> detectLocalGateway()            (src/onboard/linux-gateway.ts)
  |              -> phrased local/remote prompt  (src/onboard/index.ts)
  |                 local  -> ensureLocalLinuxGateway(state)
  |                 remote -> resolveGateway()   (src/onboard/common.ts)
  |              -> method:
  |                   wireguard-netns -> runWireguardNetnsOnboard(resolved)
  |                   docker          -> runDockerOnboard(resolved)
  |
  +-- other   -> refuse, exit
```

## Two tokens

Two bearer tokens flow through onboard:

- **User token** — returned by `acquireToken`. Authenticates onboard-time calls
  that operate on user-scoped objects (`POST /api/integrations`,
  `POST /api/profiles`). Discarded when onboard exits.
- **Device token** — returned by `registerDeviceApi`, saved to
  `~/.unclaw/device.json` via `saveDeviceConfig`. Narrower scope, used later by
  `unclaw run` to create sessions.

## macOS install

`runMacosOnboard` in `src/onboard/macos.ts`:

1. `ensureLocalGateway()` picks a LAN IP (`ipconfig getifaddr en0`, then `en1`)
   for `UNCLAW_HOSTNAME` — advertised as the WireGuard endpoint to the Network
   Extension, which can't send UDP to `127.0.0.1`. The gateway's HTTP API itself
   still binds to loopback via the default `API_HOST=127.0.0.1`. Writes
   `~/Library/LaunchAgents/dev.unclaw.gateway.plist` with `RunAtLoad=true`,
   `KeepAlive=true`, env (`UNCLAW_DATA`, `UNCLAW_HOSTNAME`, `DEV_AUTH_EMAIL`),
   stdio → `~/.unclaw/gateway.log`. `launchctl load`, poll `/api/status` for
   30×500ms, mint a dev token via `getDevToken`, cache to
   `~/.unclaw/credentials`.
2. `installApp()` ensures `/Applications/Unclaw.app`. Either a running process,
   a pre-installed bundle, or extracts `macos/Unclaw.app.tar.gz` shipped in the
   npm package.
3. `waitForExtension()` polls `systemextensionsctl list` for
   `com.unclaw.app.extension ... activated enabled`; macOS prompts the user in
   Privacy & Security on first run.
4. `registerDeviceApi` + `downloadCA` + `createCaBundle` — the last concatenates
   `/etc/ssl/cert.pem` with the unclaw CA into `~/.unclaw/ca-bundle.pem` and
   emits `~/.unclaw/env.sh` with `SSL_CERT_FILE` / `CURL_CA_BUNDLE` /
   `NODE_EXTRA_CA_CERTS` exports.
5. Secret discovery and import via `src/onboard/secrets.ts`.
6. Optional `wrapOpenClawDaemon` rewrites
   `~/Library/LaunchAgents/ai.openclaw.gateway.plist`'s `ProgramArguments` to
   `[unclaw, --name, <device>, --, ...]`.

The launchd agent is written directly to `~/Library/LaunchAgents/` rather than
registered through `SMAppService`, so it runs and shows in `launchctl list` but
does not appear in System Settings → Login Items & Extensions.

macOS sets `DEV_AUTH_EMAIL` unconditionally because the API binds to loopback
regardless of `UNCLAW_HOSTNAME`. The Linux flows apply the loopback rule
described below.

## Linux detection

`detectLocalGateway()` in `src/onboard/linux-gateway.ts` returns one of three
states:

1. `listListeningSockets()` parses `ss -tlnpH` into every current listener,
   tagging wildcard binds (`*`, `0.0.0.0`, `::`).
2. Each listener's `http://HOST:PORT/api/status` is probed in parallel (500ms
   per probe).
3. First `200` → `{ kind: "running", gateway }`.
4. Otherwise, if `~/.unclaw/data` exists and is non-empty →
   `{ kind: "installed", dataDir }` — gateway state that a previous local
   gateway wrote here.
5. Else → `{ kind: "none" }`.

The state drives the local-vs-remote prompt wording in `src/onboard/index.ts`
and the local option's label (`Use the local
gateway` vs.
`Set up a local gateway`).

The same `listListeningSockets()` snapshot is threaded into the state and reused
when building the bind-address prompt: we only propose host:port combinations
that no listener is occupying. `firstFreePort(listeners, host, 8080)` walks
upward from 8080 until it finds a free port; whatever it returns is what the
corresponding option shows. For the "custom" text path,
`findConflict(listeners,
bind)` validates the user's input inline — the
occupant's `pid` / `cmd` from the same snapshot becomes the error message.

## Linux local-gateway flow

```
ensureLocalLinuxGateway(state)

  state.kind == "running"
    -> acquireToken(state.gateway.baseUrl, state.gateway.bind)
       return { baseUrl, token }

  state.kind == "installed"
    -> log "reusing ~/.unclaw/data"
    -> fall through

  state.kind == "none"
    -> fall through

  pickBindAddress(state.listeners)
    options derived from the snapshot:
      loopback -> 127.0.0.1:<firstFreePort from 8080>
      LAN      -> <lanIp>:<firstFreePort from 8080>   (if detectLanIp)
      custom   -> user types host:port; findConflict validates inline
    no conflict-resolution loop: taken ports are never proposed, and
    custom input is rejected by the validate callback if occupied.

  hasSystemctl ?
    no  -> runEphemeralForOnboard(bind)
    yes -> confirm "Install systemd unit?"
             no  -> runEphemeralForOnboard(bind)
             yes -> select user | system
                      user   -> confirm "Enable linger?"
                                  yes -> installUserUnit(bind, linger=true)
                                  no  -> installUserUnit(bind, linger=false)
                      system -> installSystemUnit(bind)

  (all install/install-reuse paths end with a single)
    acquireToken(baseUrl, bind)
```

`installSystemUnit` creates the `unclaw` system user via `useradd -r` if missing
and `chown`s `/var/lib/unclaw`. `installUserUnit` writes under
`~/.config/systemd/user/`. When linger is enabled it also runs
`sudo loginctl enable-linger $USER`.

## Token acquisition

`acquireToken(baseUrl, bind)` branches on the bind host:

- **Loopback** (`127.0.0.0/8`, `::1`, `localhost`) → `mintDevToken` does
  `POST /api/auth/dev-token`, which succeeds because the gateway was started
  with `DEV_AUTH_EMAIL=local@unclaw.dev`.
- **Non-loopback** (LAN / custom host) → `deviceCodeAuth` runs the interactive
  OAuth device-code flow (extracted from `resolveGateway` in
  `src/onboard/common.ts`). The gateway was started _without_ `DEV_AUTH_EMAIL`,
  so `/api/auth/dev-token` returns 404 and only a real Google-backed sign-in
  mints a user token.

The split prevents an exposed LAN gateway from handing out user tokens to anyone
who can reach port 8080.

## Linux env vars per mode

| Env var           | User unit        | System unit         | Ephemeral        |
| ----------------- | ---------------- | ------------------- | ---------------- |
| `UNCLAW_DATA`     | `~/.unclaw/data` | `/var/lib/unclaw`   | `~/.unclaw/data` |
| `API_HOST`        | bind.host        | bind.host           | bind.host        |
| `API_PORT`        | bind.port        | bind.port           | bind.port        |
| `UNCLAW_HOSTNAME` | bind.host        | bind.host           | bind.host        |
| `DEV_AUTH_EMAIL`  | loopback only    | loopback only       | loopback only    |
| `User=`/`Group=`  | — (current user) | `unclaw` / `unclaw` | — (current user) |
| `WantedBy`        | `default.target` | `multi-user.target` | n/a              |

Unit rendering is `renderUnit` in `src/onboard/linux-gateway.ts`. macOS's
launchd plist sets the same env minus `User=`/`Group=`/ `WantedBy=` and always
includes `DEV_AUTH_EMAIL` as noted above.

## `unclaw run` fallback

`src/cli.ts:runWrap`:

- After `loadDeviceConfig`, if `isLocalBaseUrl(config.server)` and
  `!(await probeGateway(config.server))`, call
  `spawnManagedGateway({ bind: parseBind(baseUrl) })`. The child runs under this
  `unclaw run` and is tracked via `spawnedGateway`.
- `cleanup()` is a combined closure: `DELETE /api/sessions/:id`, then
  `spawnedGateway.stop()` (SIGTERM → SIGKILL after 3s). It is registered as a
  `SIGINT`/`SIGTERM`/`SIGHUP` handler and passed to `runMacOS` / `runLinux` as
  `onBeforeExit` so it also runs after `sandbox-exec` / `runInNetns` returns.
- When `config.server` is remote and unreachable, `runWrap` errors out instead.
  Autospawn is local-only.

The autospawned gateway reads `~/.unclaw/data`, which was populated by the
onboard-time gateway (ephemeral or persistent). The `deviceToken` in
`~/.unclaw/device.json` therefore stays valid: every local gateway instance sees
the same underlying device store.

Concurrent `unclaw run` on a box without a unit: the second invocation probes,
sees the first's gateway, reuses it, and does not spawn its own — so it also
will not stop it on exit. When the first `unclaw run` exits, `cleanup()` stops
the shared gateway out from under the second. Concurrent workloads need a
systemd unit.

## State on disk

| Path                                               | Written by                 | Contents                               |
| -------------------------------------------------- | -------------------------- | -------------------------------------- |
| `~/.unclaw/data/`                                  | gateway (`src/main.ts`)    | sqlite, keys, CA                       |
| `~/.unclaw/ca.pem`                                 | `downloadCA`               | gateway CA cert                        |
| `~/.unclaw/ca-bundle.pem` (mac)                    | `createCaBundle`           | system roots + unclaw CA               |
| `~/.unclaw/env.sh` (mac)                           | `createCaBundle`           | shell exports for the CA bundle        |
| `~/.unclaw/device.json`                            | `saveDeviceConfig`         | `{server, deviceToken}`                |
| `~/.unclaw/credentials` (mac only; Linux re-mints) | `getDevToken`              | cached dev token + email + server      |
| `~/.unclaw/gateway.log`                            | launchd/systemd/ephemeral  | stdout + stderr                        |
| `~/Library/LaunchAgents/dev.unclaw.gateway.plist`  | `ensureLocalGateway` (mac) | launchd user agent                     |
| `~/.config/systemd/user/unclaw-gateway.service`    | `installUserUnit`          | systemd user unit                      |
| `/etc/systemd/system/unclaw-gateway.service`       | `installSystemUnit`        | systemd system unit                    |
| `/var/lib/unclaw/`                                 | systemd system unit        | data dir when running as `unclaw` user |
