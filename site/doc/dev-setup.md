# Local Development Setup

Claw Patrol is a single statically linked Go binary. The dashboard SPA
is built separately with Vite and embedded into the binary at build time.

## Prerequisites

- Go (see `go.mod` for the required version)
- Docker with Compose (optional, for end-to-end testing against an
  in-container agent)
- npm (only required if you want to rebuild the dashboard SPA in `www/`)

### macOS only

If you're going to exercise `clawpatrol run` on macOS you also need to
build the `Clawpatrol.app` system extension:

- Xcode 15+
- [xcodegen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`)
- Apple Development certificate for team `2H4KBF436B`
- Two **macOS App Development** provisioning profiles (created at
  [developer.apple.com/account/resources/profiles](https://developer.apple.com/account/resources/profiles)):
  - App ID `com.clawpatrol.app` -- must include: Network Extensions,
    System Extension, App Groups
    (`group.2H4KBF436B.com.clawpatrol.app.extension`)
  - App ID `com.clawpatrol.app.extension` -- must include: Network
    Extensions, App Groups
    (`group.2H4KBF436B.com.clawpatrol.app.extension`)

  Name them "Claw Patrol App Dev" and "Claw Patrol Extension Dev" (these
  names are referenced in `macos/project.yml`). After creating them,
  download and install via Xcode: Settings > Apple Accounts > your team
  > Download Manual Profiles.

See [`macos/README.md`](https://github.com/denoland/clawpatrol/blob/main/macos/README.md)
for the full system-extension build walkthrough.

## Build and run from source

The gateway is a single Go binary. To build and run it:

```sh
# Optional: build the dashboard SPA. The Go build embeds whatever is
# under www/dist/ — if you skip this, the dashboard ships a placeholder.
cd www && npm ci && npm run build && cd ..

# Build the binary.
go build -o clawpatrol .

# Or run directly without producing a binary on disk.
go run .
```

## Quick start

The simplest dev loop is to point `gateway init` at a temporary data
directory and start the gateway against the generated config:

```sh
CLAWPATROL_DATA=./data ./clawpatrol gateway init
CLAWPATROL_DATA=./data ./clawpatrol gateway
```

This generates a CA, writes a `gateway.hcl`, and brings up:

- The CONNECT/MitM proxy on `tcp/9443`
- The WireGuard listener on `udp/51820`
- The dashboard and HTTP API on `tcp/9080`

Dashboard: <http://localhost:9080>

Tests live alongside the code and run with `go test ./...`.

## Testing with a Docker agent (openclaw)

Build and run openclaw in Docker:

```sh
cd /path/to/openclaw
docker build -t openclaw:local .
mkdir -p /tmp/openclaw-dev/{config,workspace}
echo '{"gateway":{"mode":"local"}}' > /tmp/openclaw-dev/config/openclaw.json
OPENCLAW_CONFIG_DIR=/tmp/openclaw-dev/config \
OPENCLAW_WORKSPACE_DIR=/tmp/openclaw-dev/workspace \
docker compose up -d openclaw-gateway
```

Onboard the openclaw container against your local gateway (see
[Onboarding](/docs/onboarding/) for the full flow):

```sh
docker exec <openclaw-container> clawpatrol join http://host.docker.internal:9080
```

Verify interception:

```sh
docker exec <openclaw-container> curl -sf https://httpbin.org/get
# Check http://localhost:9080/requests to see the intercepted request
```
