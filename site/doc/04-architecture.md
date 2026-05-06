# Architecture

> See [Glossary](03a-glossary.md) for definitions of gateway, endpoint,
> credential, rule, profile, plugin, runtime, and the rest of the
> vocabulary used below.

## Overview

Claw Patrol is an HTTPS MitM proxy that intercepts, inspects, and forwards
HTTPS traffic from agent machines. It runs as a single Node.js process
with two listeners:

```
Internet
  |
  +-- port 443 (Caddy/TLS) --> localhost:8080 (Dashboard + API)
  +-- port 8443 (direct)   --> 0.0.0.0:8443  (CONNECT proxy + transparent MitM)
  +-- port 51820 (UDP)     --> WireGuard tunnel
```

## Connection Methods

Clients connect via one of two methods:

### 1. WireGuard Tunnel (recommended)

All traffic from the client is routed through a WireGuard VPN tunnel
(`AllowedIPs = 0.0.0.0/0`). On the server, iptables transparently redirects
port 443 traffic from the WireGuard subnet to the proxy:

```
Client (10.77.0.x) --> WireGuard tunnel --> Server wg0
  --> iptables PREROUTING REDIRECT :443 -> :8443
  --> Proxy detects TLS ClientHello, extracts SNI
  --> MitM: generate cert, terminate TLS, forward upstream
```

The client needs no `HTTPS_PROXY` environment variable. The interception is
completely transparent. The CA certificate is installed system-wide during
onboarding.

Non-443 traffic (HTTP, etc.) passes through the tunnel and is forwarded
via NAT masquerade. DNS queries (port 53) are intercepted by the
proxy's DNS server for virtual IP resolution (see DNS Interception).

Client identification: by WireGuard tunnel source IP (10.77.0.x).

### 2. HTTPS_PROXY (explicit proxy)

The client sets `HTTPS_PROXY=http://ID:TOKEN@gateway.example.com:8443`. Tools that
respect this env var send CONNECT requests to the proxy:

```
Client --> CONNECT httpbin.org:443 HTTP/1.1
        Proxy-Authorization: Basic base64(ID:TOKEN)
  --> Proxy responds: 200 Connection Established
  --> Client starts TLS inside the tunnel
  --> MitM: generate cert, terminate TLS, forward upstream
```

This works without root access on the client, but only covers tools that
respect `HTTPS_PROXY`. Per-tool CA certificate configuration is needed
(the join script sets `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, etc.).

Client identification: by Proxy-Authorization header (Basic auth with
client ID and token).

### 3. macOS Network Extension (transparent proxy)

On macOS, `clawpatrol run <cmd>` uses a system extension
(`NETransparentProxyProvider`) to intercept traffic from the wrapped
process tree. The CLI registers the child PID with the NE over XPC
(Mach service `group.2H4KBF436B.com.clawpatrol.app.extension`). The NE
walks the PPID chain of each outbound flow to check if it belongs to a
registered process tree, then relays matched flows through a userspace
WireGuard tunnel (boringtun + smoltcp) to the gateway.

```
clawpatrol run <cmd>
  --> XPC: registerPid(child, agent, cmd)
  --> XPC: tunnelActivate(wgConfig)
  --> NE intercepts outbound TCP/UDP from child's process tree
  --> boringtun encrypts --> UDP to gateway:51820
  --> Gateway decrypts, MitM, injects secrets, forwards upstream
```

The process is sandboxed via `sandbox-exec` to deny access to local
credentials. No `HTTPS_PROXY` env var or system-wide CA install is
needed — the NE handles interception transparently at the network
layer.

## MitM TLS Interception

The proxy intercepts HTTPS traffic using the "loopback bridge" pattern
(from the Avocet proxy):

1. Generate a per-host TLS certificate signed by the Claw Patrol CA
   (EC P-256, cached in memory with LRU eviction at 256 entries)
2. Create an ephemeral `tls.createServer()` listening on `127.0.0.1:0`
   with the forged certificate
3. Connect to the ephemeral listener via `net.connect()`
4. Bidirectionally pipe the client connection to the loopback connection
   (the encrypted TLS data flows through this pipe)
5. The TLS server's `secureConnection` event fires with the decrypted
   `TLSSocket`
6. Read HTTP requests from the decrypted connection, forward upstream
   via `fetch()`, relay responses back

This avoids node:tls's lack of a way to wrap an arbitrary existing
duplex stream as a TLS server.

## Protocol Detection

Port 8443 handles both CONNECT and transparent connections on the same
listener. The first byte of the connection determines the protocol:

- `0x16` (TLS handshake record) -> transparent mode: extract SNI from
  ClientHello, identify client by WireGuard IP
- `C` (start of `CONNECT ...`) -> explicit proxy mode: parse CONNECT
  request, identify client by Proxy-Authorization header

## CA Certificate Management

The CA is auto-generated on first startup using `@peculiar/x509` and the
Web Crypto API (no external tools like `openssl` needed):

- EC P-256 key pair
- Self-signed X.509 certificate (CN=Claw Patrol CA, 10 year validity)
- Saved to `data/ca/ca-cert.pem` and `data/ca/ca-key.pem`
- Loaded from disk on subsequent starts

Per-host certificates are generated on demand:

- EC P-256 key pair per hostname
- Signed by the CA with SAN extension (DNS or IP type)
- 30-day validity
- Cached in memory (LRU, max 256 entries)

## Secret Injection

The proxy replaces placeholder strings in HTTP requests with real secret
values before forwarding upstream. Agents never see or handle real
credentials -- they use placeholders like `CLAWPATROL_PLACEHOLDER_github`.

### Endpoint Configuration

Endpoint configs live in `data/endpoints/*.ts` (outside the source tree).
Each file defines target hosts and secrets:

```ts
export default {
  hosts: ["api.github.com", "github.com"],
  secrets: [{
    placeholder: "CLAWPATROL_PLACEHOLDER_github",
    file: "/opt/clawpatrol/data/secrets/github-token",
    headers: ["authorization"],  // only replace in this header
  }],
};
```

Secret fields:
- `placeholder`: the string agents use in requests
- `file`: path to the file containing the real secret value
- `headers`: (optional) restrict replacement to specific header names
- `body`: (optional) if `true`, also replace in the request body

Secrets are read from disk at startup and on SIGHUP reload.

### Replacement Pipeline

For each intercepted HTTP request:

1. Look up the endpoint by trusted hostname (from SNI or CONNECT target,
   never from the HTTP Host header)
2. Replace placeholders in allowed headers (respecting the `headers` filter)
3. Replace placeholders in the body (if `body: true`)
4. Handle Basic auth specially: base64-decode, replace, re-encode
5. Update Content-Length if the body was modified

### Anti-Exfiltration

Secrets are never injected into headers that could be echoed back in
error responses or debug pages:

- **Blocked headers**: `user-agent`, `accept`, `content-type`, `origin`,
  `referer`, `cache-control`, `sec-*`, `openai-organization`,
  `anthropic-version`, and others
- **Blocked paths**: `/cdn-cgi/*` (Cloudflare debug endpoints)

### Host Header Security

The proxy enforces that the HTTP Host header matches the trusted hostname
from SNI/CONNECT. This prevents a malicious agent from setting
`Host: evil.com` to redirect injected secrets to an attacker-controlled
server. The Host header is always overwritten with the trusted hostname.

### Hot Reload

Endpoint configs can be reloaded without restarting:

```
systemctl reload clawpatrol   # sends SIGHUP
```

This re-reads all `data/endpoints/*.ts` files and reloads secrets from
disk. Active connections are not interrupted.

## IP Binding

Per the spec, leaked credentials should be useless from an unknown IP.

On first request after approval, the client is bound to its external IP
(`approvedIp`). If a subsequent request comes from a different IP,
approval is auto-revoked and the client goes back to "pending" on the
dashboard.

For WireGuard clients, the real endpoint IP is resolved via
`wg show wg0 dump` (not the tunnel IP `10.77.0.x`). For HTTPS_PROXY
clients, the source IP of the CONNECT request is used.

Re-approving a client clears the IP binding, allowing it to bind to
a new IP on next use.

## Client Lifecycle

1. **Join**: client runs the onboarding script, which:
   - Checks server availability
   - Chooses connection method (interactive wizard or `--method` flag)
   - Registers via `POST /api/register` (client starts as "pending")
   - Installs the CA certificate
   - Configures WireGuard tunnel or HTTPS_PROXY env vars

2. **Approval**: admin approves the client on the dashboard
   (`POST /api/clients/:id/approve`)

3. **Active**: proxy allows the client's traffic. Each connection is
   identified (by WireGuard IP or Proxy-Authorization), checked for
   approval, then MitM'd.

4. **Deny**: admin can revoke access (`POST /api/clients/:id/deny`).
   The client remains registered but traffic is rejected.

Client state is persisted in SQLite (`data/clients.db`). Registrations,
approvals, WireGuard links, and IP bindings survive service restarts.
On startup, WireGuard peers from the database are re-added to the `wg0`
interface.

## API Endpoints

**Public** (no auth required):

| Method | Path                         | Description                     |
| ------ | ---------------------------- | ------------------------------- |
| GET    | `/join`                      | Client onboarding script        |
| GET    | `/api/status`                | Health check + WG availability  |
| GET    | `/api/ca.pem`                | CA certificate download         |
| POST   | `/api/register`              | Register new client             |
| POST   | `/api/setup-wireguard`       | Configure WireGuard for client  |

**Auth** (Google OAuth, configurable domain restriction):

| Method | Path                         | Description                     |
| ------ | ---------------------------- | ------------------------------- |
| GET    | `/auth/login`                | Redirect to Google OAuth        |
| GET    | `/auth/callback`             | OAuth callback, sets session    |
| GET    | `/auth/logout`               | Clear session cookie            |

**Protected** (requires session):

| Method | Path                                  | Description                         |
| ------ | ------------------------------------- | ----------------------------------- |
| GET    | `/`                                   | Dashboard SPA (index.html)          |
| GET    | `/assets/*`                           | Dashboard static assets (JS, CSS)   |
| GET    | `/api/me`                             | Current user email                  |
| GET    | `/api/clients`                        | List all clients                    |
| POST   | `/api/clients/:id/profile`            | Assign profile to client            |
| DELETE | `/api/clients/:id/profile`            | Remove profile from client          |
| DELETE | `/api/clients/:id`                    | Delete client                       |
| GET    | `/api/plugins`                        | List available plugins              |
| GET    | `/api/integrations`                   | List integrations                   |
| POST   | `/api/integrations`                   | Create integration                  |
| DELETE | `/api/integrations/:id`               | Delete integration                  |
| GET    | `/api/profiles`                       | List profiles                       |
| POST   | `/api/profiles`                       | Create profile                      |
| DELETE | `/api/profiles/:id`                   | Delete profile                      |
| POST   | `/api/profiles/:id/integrations`      | Add integration to profile          |
| DELETE | `/api/profiles/:id/integrations/:id`  | Remove integration from profile     |
| POST   | `/api/oauth/authorize`                | Start OAuth flow for integration    |
| POST   | `/api/oauth/disconnect`               | Disconnect OAuth for integration    |
| GET    | `/api/oauth/status/:id`               | OAuth connection status             |
| GET    | `/api/requests`                       | Query request audit log             |

## WireGuard Network

- Server interface: `wg0`, IP `10.77.0.1/24`, port `51820/UDP`
- Client IPs: `10.77.0.2`, `.3`, `.4`, ... (assigned sequentially)
- Server keypair stored in `data/wg/`
- iptables rules (managed by the application, cleaned up on restart):
  - `INPUT -i wg0 -s 10.77.0.0/24 -j ACCEPT` (allows DNS + VIP DNAT traffic)
  - `PREROUTING -s 10.77.0.0/24 -p tcp --dport 443 -j REDIRECT --to-port 8443`
  - `PREROUTING -s 10.77.0.0/24 -d 10.78.x.y -p tcp -j DNAT --to 10.77.0.1:<port>` (per DNS entry)
  - `FORWARD -i wg0 -j ACCEPT`
  - `FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT`
  - `POSTROUTING -s 10.77.0.0/24 -o enp1s0 -j MASQUERADE`

## DNS Interception

For protocols without TLS SNI (e.g. SSH), the proxy intercepts DNS
queries from WireGuard clients and returns virtual IPs that route traffic
to per-hostname TCP listeners.

### Flow

1. Plugin declares `dnsEntries(config)` returning hostnames it wants to
   intercept (e.g. the GitHub plugin registers `github.com:22`)
2. On startup, each unique hostname gets a virtual IP from `10.78.0.0/16`
3. An iptables DNAT rule routes traffic for that VIP to a per-hostname
   TCP listener on a random port
4. A DNS server on `10.77.0.1:53` (UDP + TCP) intercepts DNS from WG
   clients (requires `CAP_NET_BIND_SERVICE` on the node binary):
   - Registered hostnames: return the virtual IP (A record, TTL 30s)
   - AAAA queries for registered hostnames: empty response (force IPv4)
   - All other queries: forwarded to upstream DNS (8.8.8.8)
   - EDNS (OPT records) are parsed and echoed in responses
5. When a WG client connects to the virtual IP, the listener:
   - Identifies the client by WireGuard tunnel IP
   - Verifies the client's profile registered this DNS entry (prevents
     a client from bypassing DNS and using another profile's VIP directly)
   - If TLS (first byte 0x16): performs MitM TLS termination using the
     loopback bridge pattern (same as the main proxy), then processes
     the decrypted stream
   - Tries plugin protocol handlers for credential injection
   - Otherwise pipes to the upstream host bidirectionally

### Virtual IP Subnet

`10.78.0.0/16` is reserved for DNS-intercepted hostnames. These IPs are
never routed to the internet -- they only exist within the WireGuard
tunnel and are resolved by iptables DNAT rules to local listeners.

Allocations are ephemeral (reset on restart). The 30s DNS TTL ensures
clients pick up new mappings quickly.

### DNS Transport

Both UDP and TCP are supported. UDP is used for normal queries. TCP
is used by clients when responses are large or when the truncation
(TC) flag is set. TCP DNS messages are framed with a 2-byte length
prefix per RFC 1035.

## Request Logging

Every proxied request/response is logged to the SQLite database
at `$CLAWPATROL_DATA/clients.db` with a 7-day retention (configurable
via `ANALYTICS_RETENTION_DAYS`). See
[Self-Hosting](06-self-hosting.md) for details.
