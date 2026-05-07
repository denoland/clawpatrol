# Plugin System

## Overview

Claw Patrol's functionality is extended through plugins. A plugin module is a
TypeScript file (or npm package) that registers one or more typed plugins via
a registration API.

There are two plugin types:

- **Integration plugins** -- intercept traffic for specific hostnames and
  inject credentials. Each integration has its own config schema, dashboard
  form layout, and endpoint handlers.
- **Credential plugins** -- manage dynamic credentials (OAuth tokens,
  device-code tokens) with login flows and automatic refresh.

Source of truth: `src/plugins/types.ts`, `src/plugins/registry.ts`.

---

## Plugin Module Format

A plugin module's default export is either:

### Object form (recommended)

```typescript
import { definePlugin } from "clawpatrol/plugins/types.ts";

export default definePlugin({
  id: "my-plugin",       // optional; used in log prefixes
  name: "My Plugin",     // optional
  version: "1.0.0",      // optional; informational
  register(api) {
    api.registerCredential({ ... });
    api.registerIntegration({ ... });
  },
});
```

### Function form

```typescript
export default (api: Claw PatrolPluginApi) => {
  api.registerIntegration({ ... });
};
```

### Type definitions

```typescript
type Claw PatrolPluginModule =
  | Claw PatrolPluginDefinition
  | ((api: Claw PatrolPluginApi) => void | Promise<void>);

interface Claw PatrolPluginDefinition {
  id?: string;
  name?: string;
  version?: string;
  register?: (api: Claw PatrolPluginApi) => void | Promise<void>;
}
```

`definePlugin()` is an identity function that provides type inference. It has
no runtime effect.

A single module can register multiple plugins of different types by calling
multiple `api.register*()` methods. For example, the OpenAI plugin registers
both a credential plugin and an integration plugin.

---

## Plugin Registration API (`Claw PatrolPluginApi`)

The `register` function receives an API object with these methods:

```typescript
interface Claw PatrolPluginApi {
  /** Register an integration plugin. */
  registerIntegration<C>(plugin: IntegrationPlugin<C>): void;

  /** Register a credential plugin. */
  registerCredential(plugin: CredentialPlugin): void;

  /**
   * Return a Zod schema for a credential-backed config field.
   * The credential plugin must be registered first.
   */
  credentialField(credentialPluginId: string): ZodType;

  /** Scoped logger. Messages are prefixed with the module ID. */
  log: {
    info(msg: string): void;
    warn(msg: string): void;
    error(msg: string): void;
  };
}
```

### Registration rules

- **Duplicate IDs are rejected.** If an integration or credential with the
  same ID is already registered, the second registration is silently skipped
  with a warning.
- **Order matters for `credentialField()`.** The credential plugin must be
  registered before any integration calls `api.credentialField("that-id")`.
  Within a single module, register credentials first.
- **Credential fields are auto-detected.** When an integration is registered,
  the registry walks its `configSchema` looking for schemas returned by
  `credentialField()`. Matches are merged into the integration's `credentials`
  map automatically.

---

## Integration Plugins

```typescript
interface IntegrationPlugin<C = any> {
  id: string;
  name: string;
  description: string;
  icon?: string;                     // SVG markup for the dashboard
  configSchema: ZodType<C, any, any>;
  configLayout?: LayoutItem[];
  credentials?: Record<string, string>;  // field name -> credential plugin ID
  endpoints: Endpoint<C>[];
}
```

### Endpoints (layered hook model)

Each endpoint declares which hostnames to intercept and can hook into the
connection at one or more layers:

```
Client --[TCP]--> conn hook --[TLS terminate]--> tls hook --[HTTP parse]--> fetch hook
                                                                              |
                                                                        connect hook
                                                                              |
                                                                           Upstream
```

**Inbound (peel layers):**
- `conn` -- raw TCP stream from the client
- `tls` -- plaintext stream after TLS termination
- `fetch` -- parsed HTTP request/response

**Outbound:**
- `connect` -- upstream connection factory (called by `fn.fetch()`)

Each hook is optional. The framework provides defaults:
- No `conn`: terminate TLS, call `tls` hook
- No `tls`: parse HTTP, call `fetch` hook per request
- No `fetch`: `fn.fetch(req)` (passthrough)
- No `connect`: default TLS connection to upstream
- No hooks at all: transparent TCP pipe to upstream

```typescript
interface Endpoint<C = Record<string, unknown>> {
  /** Whether this endpoint is active. Default: true. */
  enabled?: (config: C) => boolean;
  /** Hostnames this endpoint handles. */
  domains: string[] | ((config: C) => string[]);
  /** Port (default: 443). */
  port?: number | ((config: C) => number);

  /** Layer 1: raw TCP stream from client. */
  conn?: (config: C, fn: EndpointFn, stream: DuplexStream, info: ConnInfo)
    => Promise<void>;
  /** Layer 2: plaintext stream after TLS termination. */
  tls?: (config: C, fn: EndpointFn, stream: DuplexStream, info: ConnInfo)
    => Promise<void>;
  /** Layer 3: HTTP request/response. */
  fetch?: (config: C, fn: EndpointFn, req: Request, info: ConnInfo)
    => Response | Promise<Response>;
  /** Upstream connection factory. Called by fn.fetch(). */
  connect?: (config: C, fn: EndpointFn, info: ConnInfo)
    => Promise<DuplexStream>;
}
```

All hooks receive `config` first, `fn` second, then layer-specific inputs,
then `info` last.

### The `fn` object

Provides methods for forwarding traffic and connecting upstream:

```typescript
interface EndpointFn {
  /** Forward an HTTP request upstream. Uses the connect hook if present. */
  fetch(req: Request): Promise<Response>;

  /** Open a raw TCP connection. */
  connectTcp(addr: { hostname: string; port: number }): Promise<DuplexStream>;

  /** Open a TLS connection to an upstream server. */
  connectTls(opts: TlsConnectOptions): Promise<DuplexStream>;
}

interface TlsConnectOptions {
  hostname: string;
  port?: number;
  caCerts?: string[];  // custom CA certificates (PEM)
  cert?: string;       // client certificate (PEM)
  key?: string;        // client private key (PEM)
}
```

When a `connect` hook is present, `fn.fetch()` uses it for upstream
connections. When the `connect` hook returns TLS options (via
`fn.connectTls()`), the framework extracts those options and applies them to
the HTTP client directly.

### Supporting types

```typescript
interface DuplexStream {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

interface ConnInfo {
  hostname: string;    // target hostname (from SNI or CONNECT)
  port: number;        // target port
  remoteAddr: string;  // client IP address
}
```

### DNS entries (automatic)

Endpoints with `port !== 443` automatically get DNS entries registered. The
framework scans endpoint `domains` and `port` to build the DNS entry table.
WireGuard clients querying DNS for matching hostnames receive a virtual IP
from `10.78.0.0/16`. Connections to those VIPs are routed to the proxy via
iptables DNAT. See [Architecture](/docs/04-architecture/) for details.

### Config schema

Each integration declares a Zod schema that defines the config shape. This
schema is used for validation, form generation, and defaults:

```typescript
const configSchema = z.object({
  domains: z.array(z.string())
    .default(["api.github.com"])
    .describe("GitHub API hostnames to intercept"),
  placeholder: z.string()
    .default("CLAWPATROL_PLACEHOLDER_github")
    .describe("Placeholder string agents use in Authorization header"),
  token: z.string()
    .describe("GitHub PAT (classic or fine-grained)"),
});
```

### Config layout (`LayoutItem[]`)

Controls how the config form is rendered in the dashboard. Without a layout,
fields render in schema order with default widgets.

```typescript
type LayoutItem = string | LayoutObject;

interface LayoutObject {
  key?: string;                // config field path
  type?: "fieldset";           // container type
  title?: string;              // section title
  expandable?: boolean;        // collapsible section
  expanded?: boolean;          // initial state (default: false)
  sensitive?: boolean;         // masked input
  multiline?: boolean;         // textarea
  items?: LayoutItem[];        // children (for fieldsets)
  condition?: {                // conditional visibility
    functionBody: string;      // JS receiving `model`, return true to show
  };
  description?: string;        // override schema description
  placeholder?: string;        // input placeholder text
}
```

---

## Credential Plugins

A credential plugin manages dynamic credentials with login flows and
optional automatic refresh.

```typescript
interface CredentialPlugin {
  id: string;
  label: string;
  schema: ZodType;           // Zod schema for the credential data shape
  flow?: AuthorizationCodeFlow | DeviceCodeFlow;
  refresh?: (params: {
    credential: Record<string, unknown>;
    config: Record<string, unknown>;
  }) => Promise<Record<string, unknown>>;
  refreshMarginSeconds?: number;  // default: 300
}
```

Two flow types are supported:

### Authorization code flow (OAuth 2.0)

Standard redirect-based OAuth. The dashboard shows a "Connect" button.

```typescript
interface AuthorizationCodeFlow {
  type: "authorization-code";
  authorizeUrl(params: {
    config: Record<string, unknown>;
    callbackUrl: string;
    state: string;
  }): string | Promise<string>;
  exchangeCode(params: {
    code: string;
    config: Record<string, unknown>;
    callbackUrl: string;
  }): Promise<Record<string, unknown>>;
}
```

### Device code flow (RFC 8628)

For headless/device authentication. The dashboard shows a user code and
verification URL, then polls until the user completes authentication.

```typescript
interface DeviceCodeFlow {
  type: "device-code";
  start(): Promise<{
    deviceAuthId: string;
    userCode: string;
    verificationUrl: string;
    interval: number;
  }>;
  poll(params: {
    deviceAuthId: string;
    userCode: string;
  }): Promise<
    | { status: "pending" }
    | { status: "ok"; credential: Record<string, unknown> }
  >;
}
```

### Linking credentials to integrations

Use `api.credentialField()` in the integration's config schema. The framework
auto-detects credential fields, stores credentials separately from config, and
merges credential data into config before calling endpoint handlers.

```typescript
register(api) {
  // 1. Register credential plugin first
  api.registerCredential({
    id: "my-oauth",
    label: "My Service OAuth",
    schema: z.object({
      access_token: z.string(),
      refresh_token: z.string(),
      expires_at: z.number(),
    }),
    flow: { type: "authorization-code", ... },
    refresh: async ({ credential }) => { ... },
  });

  // 2. Use credentialField() in the integration schema
  const configSchema = z.object({
    domains: z.array(z.string()).default(["api.example.com"]),
    auth: api.credentialField("my-oauth"),
  });

  // 3. Register the integration
  api.registerIntegration({
    id: "my-service",
    configSchema,
    endpoints: [{
      domains: (config) => config.domains,
      fetch: (config, fn, req) => {
        // config.auth contains the credential data (merged by framework)
        const token = config.auth?.access_token;
        // ...
      },
    }],
  });
}
```

Static credentials (API keys) don't need credential plugins -- they remain
as regular config fields.

---

## Examples

### Simple header injection (GitHub)

```typescript
endpoints: [{
  domains: (config) => config.domains,
  fetch: (config, fn, req) => {
    const headers = new Headers(req.headers);
    replacePlaceholder(headers, "authorization",
      config.placeholder, config.token);
    return fn.fetch(new Request(req, { headers }));
  },
}]
```

### TCP passthrough (GitHub SSH)

An endpoint with no hooks -- the framework pipes TCP bidirectionally.

```typescript
endpoints: [
  {
    // HTTP interception
    domains: (config) => config.domains,
    fetch: (config, fn, req) => { ... },
  },
  {
    // SSH passthrough -- port 22, no hooks needed
    domains: ["github.com"],
    port: 22,
  },
]
```

### mTLS upstream (Kubernetes)

```typescript
endpoints: [{
  enabled: (config) => !!config.server,
  domains: (config) => [config.server.trim()],
  connect: (config, fn, info) =>
    fn.connectTls({
      hostname: info.hostname,
      port: info.port,
      caCerts: [config.ca_cert],
      cert: config.client_cert,
      key: config.client_key,
    }),
}]
```

### Binary protocol over TLS (ClickHouse native)

```typescript
endpoints: [{
  enabled: (config) => config.enable_native,
  domains: (config) => config.native_hosts,
  port: (config) => config.native_port,
  tls: async (config, fn, stream, info) => {
    const { data, reader } = await readFirst(stream);
    const hello = parseHello(data);

    // Inject credentials
    hello.username = config.username;
    hello.password = config.password;

    // Connect upstream and pipe
    const upstream = await fn.connectTls({
      hostname: info.hostname,
      port: info.port,
    });
    await writeAll(upstream, serializeHello(hello));
    await pipeBidi(reader, stream.writable, upstream);
  },
}]
```

### mTLS + HTTP credential injection (ClickHouse HTTPS)

```typescript
endpoints: [{
  enabled: (config) => config.enable_https,
  domains: (config) => config.https_hosts,
  fetch: (config, fn, req) => {
    const url = new URL(req.url);
    const path = url.pathname + url.search;
    const newPath = path
      .replaceAll(config.user_placeholder, encodeURIComponent(config.username))
      .replaceAll(config.pass_placeholder, encodeURIComponent(config.password));
    return fn.fetch(new Request(new URL(newPath, url.origin), req));
  },
  connect: (config, fn, info) =>
    fn.connectTls({
      hostname: info.hostname,
      port: info.port,
      caCerts: config.server_ca_cert ? [config.server_ca_cert] : undefined,
      cert: config.client_cert || undefined,
      key: config.client_key || undefined,
    }),
}]
```

### OAuth credential plugin (OpenAI device-code)

```typescript
register(api) {
  api.registerCredential({
    id: "openai-oauth",
    label: "OpenAI Account",
    schema: z.object({
      access_token: z.string(),
      refresh_token: z.string(),
      expires_at: z.number(),
      account_id: z.string().optional(),
    }),
    flow: {
      type: "device-code",
      start: async () => {
        // Start device auth flow with provider
        const res = await fetch("https://auth.openai.com/.../usercode", ...);
        const data = await res.json();
        return {
          deviceAuthId: data.device_auth_id,
          userCode: data.user_code,
          verificationUrl: "https://auth.openai.com/codex/device",
          interval: data.interval || 5,
        };
      },
      poll: async ({ deviceAuthId, userCode }) => {
        // Poll for completion
        const res = await fetch("https://auth.openai.com/.../token", ...);
        if (res.status === 202) return { status: "pending" };
        // Exchange code for tokens...
        return { status: "ok", credential: { ... } };
      },
    },
    refresh: async ({ credential }) => {
      // Use refresh_token to get a new access_token
      // ...
      return { access_token: newToken, ... };
    },
    refreshMarginSeconds: 60,
  });

  const configSchema = z.object({
    domains: z.array(z.string()).default(["api.openai.com"]),
    placeholder: z.string().default("CLAWPATROL_PLACEHOLDER_openai"),
    auth: api.credentialField("openai-oauth"),
  });

  api.registerIntegration({
    id: "openai",
    configSchema,
    configLayout: ["domains", "placeholder"],
    endpoints: [{
      domains: (config) => config.domains,
      fetch: (config, fn, req) => {
        if (!config.auth?.access_token) return fn.fetch(req);
        const headers = new Headers(req.headers);
        replacePlaceholder(headers, "authorization",
          config.placeholder, config.auth.access_token);
        return fn.fetch(new Request(req, { headers }));
      },
    }],
  });
}
```

---

## Loading and Installation

Plugins are loaded from two sources at startup:

1. **Built-in plugins** -- compiled into the server (12 currently):

   | Plugin | Type | Auth mechanism |
   |--------|------|----------------|
   | `apikey` | Integration | Generic header injection |
   | `anthropic` | Integration | `x-api-key` header |
   | `clickhouse` | Integration | URL params + native protocol (`tls` hook) |
   | `gemini` | Integration | Header injection |
   | `github` | Integration | `Authorization` header + SSH passthrough (port 22) |
   | `grafana` | Integration | `Authorization: Bearer` header |
   | `kubernetes` | Integration | mTLS client certificates (`connect` hook) |
   | `notion` | Credential + Integration | OAuth 2.0 authorization code |
   | `openai` | Credential + Integration | OAuth 2.0 device code |
   | `openrouter` | Integration | Header injection |
   | `slack` | Integration | `Authorization` header |
   | `telegram` | Integration | Header injection |

2. **External plugins** -- `.ts` files in `data/plugins/`, loaded via
   dynamic import after built-in plugins.

Duplicate integration IDs are rejected with a warning.

On `SIGHUP`, endpoint and DNS caches are invalidated so config changes take
effect without a full restart.

---

## Configuration

Integration plugins are configured through the dashboard:

1. An admin creates an **integration** -- an instance of an integration plugin
   with filled-in config values (e.g. a specific GitHub PAT)
2. Integrations are assigned to **profiles**
3. Agents are assigned to profiles, inheriting all the profile's integrations

Multiple instances of the same plugin can coexist (e.g. two different GitHub
PATs for different accounts).

Config is validated against the integration's Zod schema on creation and
update. Sensitive fields are masked in API responses.

Dynamic credentials (OAuth tokens, etc.) are stored in a separate
`credentials` table, not in the integration config. The framework loads
and merges credential data into config before calling endpoint handlers,
and proactively refreshes credentials before expiry.

---

## Key Source Files

| File | Purpose |
| ---- | ------- |
| `src/plugins/types.ts` | All type definitions |
| `src/plugins/registry.ts` | Module loading and registration |
| `src/plugins/endpoint-fn.ts` | `EndpointFn` implementation |
| `src/plugins/*/index.ts` | Built-in plugin implementations |
| `src/endpoints.ts` | Hostname-to-handler resolution |
| `src/credentials.ts` | Credential storage, caching, and refresh |
| `src/dns.ts` | DNS entry collection and virtual IP listeners |
| `src/proxy.ts` | Hook invocation (tls, fetch) and traffic forwarding |
