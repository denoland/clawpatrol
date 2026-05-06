# Gateway

Reverse proxy for clients that can't use WireGuard or CONNECT
(e.g. Cloudflare Workers, serverless functions, mobile apps).

```
POST https://gateway.example.com/gw/api.openai.com/v1/chat/completions
X-Claw Patrol-Token: <client-token>
Content-Type: application/json

{"model": "gpt-4", ...}
```

The worker doesn't need API keys. Claw Patrol holds them server-side
via endpoint configs and injects them into the forwarded request.


## URL format

```
https://gateway.example.com/gw/{upstream-host}/{path}
```

Examples:
```
/gw/api.openai.com/v1/chat/completions
/gw/api.anthropic.com/v1/messages
/gw/api.github.com/repos/org/repo/issues
```


## Authentication

Clients authenticate with `X-Claw Patrol-Token: <token>` header.
The token is the same client token from `POST /api/register`.
The client must be approved.

`Authorization` passes through to upstream untouched -- it's
not consumed by clawpatrol. This means secrets can inject API keys
into the Authorization header via endpoint configs.


## How it works

```
CF Worker              gateway.example.com/gw         api.openai.com
   |                         |                           |
   |-- POST /gw/api.openai.com/v1/chat/completions ---->|
   |   X-Claw Patrol-Token: abc                               |
   |   Authorization: Bearer PLACEHOLDER_OPENAI          |
   |                         |                           |
   |                   1. Auth client                    |
   |                   2. Strip X-Claw Patrol-Token           |
   |                   3. Inject secrets                 |
   |                      (replace PLACEHOLDER_OPENAI    |
   |                       with real sk-...)             |
   |                   4. Forward to upstream ---------->|
   |                   5. Log to analytics store         |
   |                         |<-- 200 response ---------|
   |<-- 200 response -------|                           |
```


## Secret injection

Same endpoint configs as the CONNECT proxy. Secrets defined in
`/opt/clawpatrol/data/endpoints/*.ts` apply to gateway requests
targeting the same hosts.

If no endpoint config exists for the target host, the request
forwards as-is (no secret injection, still logged).


## Differences from CONNECT proxy

| | CONNECT proxy | Gateway |
|---|---|---|
| Client sends | raw TCP via CONNECT | HTTP to /gw/ |
| TLS to upstream | server terminates | server initiates |
| Auth | Proxy-Authorization | X-Claw Patrol-Token |
| Streaming | yes (chunked) | buffered |
| WebSocket | yes | no |
| Client needs | WireGuard or CONNECT support | HTTP client |


## Deployment

The gateway runs on the same API listener (port 8080, behind
Caddy on 443). No additional ports or config needed.

A reverse proxy in front of the gateway (e.g. Caddy, nginx)
routes `/gw/*` to `localhost:8080` alongside the dashboard and
API.

Local-gateway install modes (launchd on macOS, systemd system/user/linger
on Linux, ephemeral per-invocation) are documented in
[Onboarding](/docs/03-onboarding/).
