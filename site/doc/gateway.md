# Gateway

The Claw Patrol gateway is the policy and data-plane process. It owns the
trusted credentials, accepts enrolled devices, routes traffic from those
devices, applies endpoint/rule policy, injects credentials, and serves the
operator dashboard.

## Responsibilities

A running gateway:

- loads `gateway.hcl` and compiles profiles, credentials, endpoints, tunnels,
  approvers, and rules;
- serves the dashboard and JSON API on `info_listen` when configured;
- handles device onboarding through `/api/onboard/*` routes;
- accepts WireGuard-routed or Tailscale-routed client traffic;
- dispatches connections to configured endpoint plugins;
- evaluates rules and human/LLM approval chains;
- injects secrets from credential storage or environment fallbacks;
- records request/action/session activity for the dashboard and telemetry.

## Starting a gateway

Operators usually bootstrap a data directory first:

```bash
clawpatrol gateway init --data-dir /var/lib/clawpatrol
```

Then run the daemon with the generated config:

```bash
clawpatrol gateway -config /var/lib/clawpatrol/gateway.hcl
```

Useful flags:

- `-config FILE` — gateway HCL file to load.
- `--read-only-config` — let the dashboard preview config changes but reject
  writes back to disk.

## Control plane and data plane

The gateway can expose different control-plane modes from `gateway.hcl`.
Clients discover the selected mode during `clawpatrol join`.

In WireGuard mode, the gateway runs an embedded userspace WireGuard server.
Approved peers receive generated WireGuard configuration. Client traffic enters
at the gateway and is dispatched by destination port and endpoint policy:

- HTTPS traffic is MITM-terminated for endpoint matching and credential
  injection.
- PostgreSQL and other protocol-specific endpoints are dispatched to their
  registered endpoint runtime.
- DNS/VIP routes support endpoint families that require stable virtual IPs.
- Non-matching traffic can pass through according to the active gateway
  forwarding path and policy.

In Tailscale-oriented setups, the gateway can use tailnet identity and exit-node
routing for enrolled clients while still keeping Claw Patrol policy and secret
injection at the gateway.

## Dashboard and API

When `info_listen` is set, the gateway serves dashboard/API routes from the
same HTTP listener. Important route families include:

| Route family | Purpose |
| --- | --- |
| `/info`, `/ca.crt` | Public discovery and CA download. |
| `/api/onboard/*` | Device enrollment start, poll, approval, lookup, and claim. |
| `/api/state`, `/api/status` | Dashboard state and device status. |
| `/api/config/*` | Config read, preview, and save. |
| `/api/rules*` | Rule listing and AI-assisted rule generation. |
| `/api/hitl/*` | Human-in-the-loop pending requests and decisions. |
| `/api/oauth/*`, `/api/credentials/*`, `/api/cred/*` | Credential OAuth, manual secret, and webhook flows. |
| `/api/events`, `/api/actions/*`, `/api/analytics`, `/api/facets` | Live events, action details, analytics, and facets. |
| `/api/env-pushdown` | Authenticated client environment pushdown. |
| `/api/peer/ephemeral` | Authenticated ephemeral peer registration. |

Dashboard routes are protected by the configured dashboard secret and/or
operator identity, depending on the deployment mode. Self-authenticating client
routes use per-peer API tokens issued during onboarding.

## Request path

A typical enrolled agent flow is:

```text
agent process
  -> local per-process or whole-machine tunnel
  -> gateway data plane
  -> endpoint plugin selected from gateway.hcl
  -> rule / approval chain
  -> credential injection
  -> upstream service
```

The agent does not need the real upstream credential locally. It can run with
placeholder values from `clawpatrol env`; matching credential plugins replace
those placeholders at the gateway before the request reaches the upstream.

## Config as source of truth

`gateway.hcl` is the source of truth for gateway behavior. The dashboard can
help inspect, preview, and edit it, but the HCL config remains the canonical
artifact for review and deployment.

Key block kinds:

- `profile` — maps enrolled devices/owners to allowed endpoint sets.
- `credential` — describes secret shape and injection behavior.
- `endpoint` — describes upstream service/protocol handling.
- `tunnel` — optionally creates shared upstream tunnels such as SSH port
  forwards, local commands, Kubernetes port-forwards, or Tailscale tsnet
  clients.
- `rule` — attaches policy to endpoint families.
- `approver` — handles human or LLM approval stages.

See the [HCL config reference](/docs/config-reference/) for every registered
field and plugin type.
