# Self-Hosting

Claw Patrol is designed to run locally with zero external
dependencies. When you run `clawpatrol onboard` or
`clawpatrol gateway`, everything stays on your machine.

## What Runs Locally

- **Proxy server** — intercepts HTTPS traffic, injects
  secrets, forwards requests
- **Dashboard** — web UI at `http://localhost:8080`
- **SQLite database** — stores devices, integrations,
  profiles, and request logs
- **CA certificate** — generated on first run, used for
  TLS interception

No data is sent to any external service. No telemetry,
no analytics, no phone-home.

## Running as a Service

`clawpatrol onboard` sets up a background service automatically:

- **macOS** — launchd agent at
  `~/Library/LaunchAgents/dev.clawpatrol.gateway.plist`
- **Linux** — systemd user unit or system unit at
  `/etc/systemd/system/clawpatrol-gateway.service`

You can also run the gateway directly:

```bash
clawpatrol gateway
```

Or with Docker:

```bash
docker run -v ~/.clawpatrol:/root/.clawpatrol -p 8080:8080 -p 8443:8443 clawpatrol/clawpatrol
```

## Configuration

All configuration is via environment variables. Set them in
your shell profile, systemd unit, or launchd plist.

See [CLI Reference](/docs/05-cli/) for the full list.

## Extending with Providers

Claw Patrol supports a pluggable auth backend for custom deployments:

- **`AUTH_PROVIDER`** — path to a JS module that implements
  the `AuthProvider` interface (login URL + OAuth code
  exchange).

When unset, auth is disabled and the dashboard is open. This
is the right default for local use. Request analytics are
always persisted to the SQLite database at
`$CLAWPATROL_DATA/clients.db`.

## Network

The proxy listens on two ports:

- **8443** — CONNECT proxy (agents connect here)
- **8080** — Dashboard and API (you open this in a browser)

On macOS, the Network Extension routes traffic from wrapped
processes to the proxy transparently. On Linux, a WireGuard
tunnel in a network namespace does the same. Either way, the
agent doesn't need to know about the proxy.
