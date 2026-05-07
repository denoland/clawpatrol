# Local Development Setup

## Prerequisites

- Node.js 24+
- Rust (stable)
- Docker with Compose (for server testing)

### macOS only

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
  names are referenced in `macos/project.yml`). After creating
  them, download and install via Xcode: Settings > Apple Accounts
  > your team > Download Manual Profiles.

## Building on macOS

The macOS client has three components that are built separately:

```sh
# 1. Native FFI lib (static lib linked into the macOS app)
cd native && cargo build --release -p clawpatrol-ffi --target-dir target/ffi && cd ..

# 2. macOS app + system extension
cd macos && xcodegen && xcodebuild -scheme Claw Patrol -configuration Debug \
  build SYMROOT="$PWD/build" && cd ..
# (The CLI auto-installs to /Applications on first run)

# 3. Native Node addon (XPC client, WireGuard tunnel)
cd native/napi && npm run build && cd ../..

# 4. TypeScript CLI + server
npm run build
```

The FFI lib and Node addon use separate output directories
(`target/ffi/` vs `target/`) so they don't clobber each other.

Test with:

```sh
node dist/cli.js onboard
node dist/cli.js run echo hi
```

On first run you'll need to approve the system extension and
proxy configuration in System Settings.

## Quick Start (no Google OAuth)

```sh
CLAWPATROL_DATA=./data DEV_AUTH_EMAIL=dev@localhost CLAWPATROL_SESSION_SECRET=devsecret npm run dev
```

This starts clawpatrol with:

- Proxy on `0.0.0.0:8443`
- Dashboard/API on `127.0.0.1:8080`
- Auto-logged in as `dev@localhost` (no browser auth needed)
- Data stored in `./data/` (SQLite DB, CA certs, etc.)

Dashboard: http://localhost:8080

## With Google OAuth

For testing the real login flow (device-code auth, `clawpatrol onboard`, etc.):

1. Create OAuth credentials at https://console.cloud.google.com/apis/credentials
   - Application type: Web application
   - Authorized redirect URIs:
     - `http://localhost:8080/auth/callback`
     - `http://localhost:8080/auth/device/callback`
2. Start clawpatrol:

```sh
CLAWPATROL_DATA=./data \
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com \
GOOGLE_CLIENT_SECRET=xxx \
CLAWPATROL_SESSION_SECRET=devsecret \
npm run dev
```

Optional: `ALLOWED_EMAIL_DOMAIN=deno.com` restricts login to a specific domain.

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

Build the sidecar image:

```sh
cd /path/to/clawpatrol
docker build -t clawpatrol/sidecar:dev sidecar/
```

Run the onboard script (see [Onboarding](/docs/03-onboarding/) for
the full flow):

```sh
npx tsx src/cli.ts onboard
# Pick "Self-hosted" → http://localhost:8080
```

Verify interception:

```sh
docker exec <openclaw-container> curl -sf https://httpbin.org/get
# Check http://localhost:8080/requests to see the intercepted request
```
