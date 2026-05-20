# Local development setup

Claw Patrol is a single statically-linked Go binary. The dashboard
SPA is built separately with Vite and embedded into the binary at
build time.

## Prerequisites

- Go (see `go.mod` for the required version)
- [Deno](https://deno.com) v2+ (only required if you want to rebuild
  the dashboard SPA in `dashboard/`). Deno reads `dashboard/package.json`
  directly; npm isn't needed.
- Docker with Compose (optional, for end-to-end testing against an
  in-container agent)

### macOS extras

If you're going to exercise `clawpatrol run` on macOS you also need
to build the `Clawpatrol.app` system extension:

- Xcode 15+
- [xcodegen](https://github.com/yonaskolb/XcodeGen) — `brew install xcodegen`
- Apple Development certificate for team `2H4KBF436B`
- Two **macOS App Development** provisioning profiles, created at
  [developer.apple.com/account/resources/profiles](https://developer.apple.com/account/resources/profiles):
  - App ID `com.clawpatrol.app` — needs Network Extensions, System
    Extension, App Groups
    (`group.2H4KBF436B.com.clawpatrol.app.extension`).
  - App ID `com.clawpatrol.app.extension` — needs Network
    Extensions, App Groups (same group).

  Name them "Claw Patrol App Dev" and "Claw Patrol Extension Dev"
  (these names are referenced in `macos/project.yml`). After
  creating them, install via Xcode: Settings → Apple Accounts → your
  team → Download Manual Profiles.

See [`macos/README.md`](https://github.com/denoland/clawpatrol/blob/main/macos/README.md)
for the full system-extension build walkthrough.

## Build

```sh
make            # builds dashboard SPA + Go binary -> ./clawpatrol
make test       # go test ./...
make fmt        # gofmt + dashboard formatter
make fmt-check  # CI's format gate
make clean      # drop ./clawpatrol, dashboard/dist, dashboard/node_modules
make install    # PREFIX=~/.local/bin (override with PREFIX=...)
```

Under the hood, the dashboard build runs `deno install && deno task
build` in `dashboard/`. Skip it (`go build ./cmd/clawpatrol` directly)
and the Go embed ships a placeholder.

## Quick start

Copy the example config into a local data directory, edit the
operational fields (listen ports, `public_url`, `wg_endpoint`,
`state_dir`), then run:

```sh
mkdir -p ./data
cp cmd/clawpatrol/gateway.example.hcl ./data/gateway.hcl
$EDITOR ./data/gateway.hcl
./clawpatrol gateway ./data/gateway.hcl
```

Ports used by the example:

| What | Port |
|---|---|
| Dashboard + HTTP API | `tcp/9080` |
| TLS MITM listener | `tcp/8443` |
| WireGuard listener | `udp/51820` |

Dashboard: <http://localhost:9080>.

Tests live alongside the code: `go test ./...`. The docgen drift
test (`go test ./tools/docgen/...`) fails if you change a
`Plugin.New()` body struct without regenerating
`site/doc/config-reference.md` — run `go run ./tools/docgen` to fix.

## Testing with a Docker agent

Build and run openclaw against your local gateway:

```sh
cd /path/to/openclaw
docker build -t openclaw:local .
mkdir -p /tmp/openclaw-dev/{config,workspace}
echo '{"gateway":{"mode":"local"}}' > /tmp/openclaw-dev/config/openclaw.json
OPENCLAW_CONFIG_DIR=/tmp/openclaw-dev/config \
OPENCLAW_WORKSPACE_DIR=/tmp/openclaw-dev/workspace \
docker compose up -d openclaw-gateway
```

Join the openclaw container against your local gateway:

```sh
docker exec <openclaw-container> clawpatrol join \
  http://host.docker.internal:9080
```

Verify interception:

```sh
docker exec <openclaw-container> curl -sf https://httpbin.org/get
# then check http://localhost:9080/requests for the captured action
```
