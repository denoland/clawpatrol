# Testing

## Automated tests

```bash
# Unit + integration tests. Node's built-in runner picks up every
# src/**/*.test.ts file; no new framework.
npm test

# Platform smoke against the built artifact. Validates dist/cli.js
# boots and the per-platform native addon loads.
npm run build && npm run smoke
```

Smoke source gating (see the header comment in `scripts/smoke-cli.mjs`):

- `UNCLAW_SMOKE_SOURCE=local` -- require `native/napi/index.<triple>.node`
  (pins napi-rs to that file so a bad artifact can't silently fall
  back to an installed `@unclaw/binding-*`).
- `UNCLAW_SMOKE_SOURCE=package` -- require the matching
  `@unclaw/binding-<triple>` package at the root version.
- `UNCLAW_SMOKE_SOURCE=any` -- default; either satisfies.

Template for a new integration test:

```ts
import { startTestGateway } from "./test_helpers/gateway.js";

const g = await startTestGateway();
try {
  // ...hit g.apiUrl / g.proxyPort...
} finally {
  await g.stop();
}
```

Rule: **one `startTestGateway()` per test file.** Several core modules
hold global singletons (agents DB, credentials, plugin registry, TLS
CA, endpoint cache) that `stop()` does not reset. `node --test` already
runs each `*.test.ts` in its own subprocess, so this is enforced by
convention rather than code -- adding explicit `reset*()` hooks is
follow-up work.

## macOS Network Extension

This section covers building and testing the macOS transparent proxy
(Network Extension) locally. The NE intercepts traffic from processes
launched via `unclaw run` and routes it through a WireGuard tunnel to
the unclaw gateway.

### Prerequisites

- macOS 11+ with Xcode
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`)
- Rust toolchain (`rustup`)
- Node.js >= 22.5
- Provisioning profiles for the `com.unclaw.app` and
  `com.unclaw.app.extension` bundle IDs (team `2H4KBF436B`)
- Logged in to a gateway: `npx tsx src/cli.ts login`

### Build

```bash
# 1. Build the native Rust library (includes FFI for the NE extension)
cd native && cargo build --release -p unclaw-ffi && cd ..

# 2. Generate the Xcode project and build
cd macos
xcodegen generate
xcodebuild -project Unclaw.xcodeproj -scheme Unclaw -configuration Release \
  -derivedDataPath build DEVELOPMENT_TEAM=2H4KBF436B
cd ..

# 3. Install the app (replaces any running instance)
pkill -f "Unclaw.app/Contents/MacOS/Unclaw" 2>/dev/null; sleep 1
rm -rf /Applications/Unclaw.app
cp -R macos/build/Build/Products/Release/Unclaw.app /Applications/Unclaw.app
open /Applications/Unclaw.app
```

When updating extension code, bump `CFBundleVersion` in
`macos/UnclawExtension/Info.plist` so macOS replaces the running
extension. Verify it activated:

```bash
systemextensionsctl list 2>&1 | grep "activated enabled"
```

### Smoke tests

#### curl (TCP + TLS interception)

```bash
npx tsx src/cli.ts --name test -- /usr/bin/curl -sv https://httpbin.org/get
```

Expected: TLS issuer is `CN=Unclaw CA` (or `CN=ClawProxy CA`) and the
`origin` field in the JSON body shows the gateway's public IP.

#### dig (UDP interception)

```bash
npx tsx src/cli.ts --name test -- dig @1.1.1.1 clickhouse-o11y.tail9a48e.ts.net
```

Expected: `NOERROR` with an answer in the `10.78.x.x` VIP range.

#### Chromium (headless)

```bash
npx @puppeteer/browsers install chromium@latest --path /tmp/chromium-test

npx tsx src/cli.ts --name test-chrome -- \
  /tmp/chromium-test/chromium/mac_arm-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium \
  --no-first-run --disable-extensions --disable-quic \
  --ignore-certificate-errors --headless --dump-dom \
  https://httpbin.org/get
```

`--ignore-certificate-errors` is needed because Chromium ignores CA
bundle environment variables. `--disable-quic` avoids sustained UDP
flows that the current relay times out on.

### Debugging

```bash
# Enable persistent debug logging for the extension
sudo log config --subsystem com.unclaw.app.extension --mode level:debug

# Stream logs
log stream --predicate 'subsystem == "com.unclaw.app.extension"' --style compact

# Show recent logs
log show --predicate 'subsystem == "com.unclaw.app.extension"' --last 30s
```

Common issues:

- **"Connection refused" on NE IPC** -- The CLI talks to the NE over
  XPC (Mach service `group.2H4KBF436B.com.unclaw.app.extension`).
  Ensure Unclaw.app is running, the system extension is activated
  (`systemextensionsctl list`), and both app and extension have the
  `application-groups` entitlement.
- **Tunnel not activating** -- Check extension logs for errors.
- **DNS_PROBE_FINISHED_NO_INTERNET in Chromium** -- DNS responses not
  reaching the UDP flow. Look for "UDP IN MISMATCH" in extension logs.
