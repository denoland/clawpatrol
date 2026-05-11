# `tailscale_oauth` credential (design proposal)

Goal: bind a `tailscale_oauth` credential to the `tunnel "tailscale"`
block, so the operator pastes Tailscale OAuth client credentials
into the dashboard once and the tunnel mints its own join authkey
via the Tailscale API on Open. Replaces the inline `authkey = "..."`
field (and the `CLAWPATROL_TUNNEL_<NAME>_AUTHKEY` env-var fallback)
for tunnels that opt into the credential reference.

Target shape:

```hcl
credential "tailscale_oauth" "my-tailnet" {}

tunnel "tailscale" "my-tunnel" {
  credential = my-tailnet
  hostname   = "clawpatrol-tunnel-prod"
  tags       = ["tag:client"]
}

endpoint "clickhouse_native" "o11y" {
  hosts  = ["clickhouse-o11y:9440"]
  tunnel = my-tunnel
}
```

OAuth client_id + client_secret are pasted via the existing
dashboard secret modal and stored in the credential_secrets SQLite
table like every other credential. The tunnel's `Open` resolves the
credential, fetches the slot bytes, does the OAuth client-credentials
exchange against `api.tailscale.com`, mints a fresh single-use
authkey, and hands it to `tsnet.Server`.

Old tunnels with literal `authkey = "..."` / env-var fallback keep
working unchanged.

## Phase 1 — current state

- `TailscaleTunnel` (config/plugins/tunnels/tailscale.go) already
  carries a framework-level `Credential string` field via
  `commonRefs` (config/plugins/tunnels/util.go:37). It's currently
  unused — `Open` reads `t.AuthKey` and falls back to
  `CLAWPATROL_TUNNEL_<NAME>_AUTHKEY`. No credential resolution path
  exists yet for this tunnel type.
- The runtime side already plumbs `TunnelHost.Credential` (resolved
  entity) and `TunnelHost.SecretStore` (paste-slot SQLite reader)
  to every tunnel's `Open` (config/runtime/tunnel.go:84-107). The
  ssh_port_forward tunnel is prior art for the exact pattern we
  need: resolve `host.Credential.Body` as a protocol-specific
  interface and pull bytes via `host.SecretStore.Get`
  (ssh_port_forward.go:77-94).
- Tailscale's OAuth exposes only the client-credentials grant —
  there is no end-user authorization-code redirect. So "oauth into
  tailscale" reduces to "paste your client_id + client_secret here,
  the gateway exchanges them for a bearer token and mints authkeys."

### Reference plugins

- **Closest template — credential side:**
  config/plugins/credentials/mtls.go. Multi-slot paste via
  `SecretSlotsProvider`, runtime exposed through a single
  protocol-specific interface (`ConfigureUpstreamTLS`) that the
  tunnel / endpoint reads off `host.Credential.Body`.
- **Closest template — tunnel side:**
  config/plugins/tunnels/ssh_port_forward.go. The tunnel requires a
  credential, declares it via `Refs` (`{Path: "Credential", Kind:
  KindCredential, Optional: false}`), and asserts
  `host.Credential.Body.(sshproto.AuthCredential)` in `Open`. The
  protocol-side interface lives in config/plugins/sshproto/ and
  registers with the runtime checker via
  `runtime.AcceptCredentialRuntime` in `init()` so the runtime
  package doesn't have to import the protocol package
  (config/runtime/checker.go:33-35).
- **Not a good template:** the existing `OAuthFlowProvider` plugins
  (anthropic_oauth.go, github.go, openai_codex.go) drive
  authorization-code / device-code flows with per-owner browser
  redirects and per-owner `OAuthRegistry` state. Tailscale has no
  end-user flow; the credentials are tunnel-level, not per-owner.

### Secret-store wiring (already in place)

- `gatewaySecretStore.Get` (secrets.go:37) walks credential_secrets
  (paste-slot SQLite) → `OAuthRegistry.Token` (browser-flow) →
  `CLAWPATROL_SECRET_<NAME>` env. The paste-slot tier covers us.
- The dashboard `/api/credentials/set` endpoint accepts a
  `{slot, value}` map for any credential whose body implements
  `SecretSlotsProvider`. Two slots fall out for free if we get the
  plugin shape right.

## Phase 2 — design positions

### Q1. Credential plugin shape: multi-slot paste, not OAuth-flow

- `tailscale_oauth` body is an empty struct with `SecretSlots()`
  returning two named slots (`client_id`, `client_secret`).
- Plugin satisfies a new `tailscaleproto.AuthKeyMinter` interface
  defined under `config/plugins/tailscaleproto/`:

  ```go
  type AuthKeyMinter interface {
      MintAuthKey(ctx context.Context, sec runtime.Secret, opts AuthKeyOpts) (string, error)
  }

  type AuthKeyOpts struct {
      Tags       []string // from the tunnel block
      Reusable   bool     // tsnet wants single-use → false
      Ephemeral  bool     // false (state survives restarts)
      ExpirySecs int      // short — tsnet consumes it on first Up
  }
  ```

- `tailscaleproto.init()` calls
  `runtime.AcceptCredentialRuntime((*AuthKeyMinter)(nil))` so the
  runtime checker accepts the new interface without runtime needing
  to import the protocol package (sshproto.go:42-49 is the pattern).

Reasoning: Tailscale's OAuth flow is degenerate — server-to-server
exchange, no per-user redirect, credentials are gateway-level.
Forcing it through `OAuthFlowProvider` / `OAuthRegistry` would
create a per-owner row holding bytes that are identical across
owners and that the runtime never injects into a request header.
The `SecretSlotsProvider` + protocol-specific runtime interface
model already exists for exactly this shape (mtls + sshproto are
prior art) and reuses the dashboard's paste-secret modal end-to-end.

### Q2. Tunnel block extension: opt-in `credential` field, literal `authkey` kept for back-compat

- `TailscaleTunnel.Credential` already exists (framework-level).
  Wire it through:
  - Add `{Path: "Credential", Kind: KindCredential, Optional: true}`
    to the tunnel plugin's `Refs` (so it's validated against the
    credentials symbol table but stays optional for back-compat).
  - In `Open`, when `host.Credential != nil`:
    - type-assert `host.Credential.Body.(tailscaleproto.AuthKeyMinter)`,
    - fetch `host.SecretStore.Get(host.Credential.Name, "")`,
    - call `MintAuthKey(ctx, sec, opts)` to obtain a fresh authkey,
    - pass it to `tsnet.Server.AuthKey`.
  - When `host.Credential == nil`: keep the current literal /
    env-var path verbatim.
- If both `credential` and literal `authkey` are set: emit a
  load-time warning ("`tunnel.credential` takes precedence; literal
  `authkey` is ignored").
- If only the literal is set: keep working silently for now. A
  deprecation warning is a follow-up — too noisy for the first
  iteration when most operators are still on literals.

Reasoning: opt-in keeps every existing deployment working without
config changes. Hard removal of the literal path is a follow-up
once dashboards exist for the operator to migrate.

### Q3. Token caching / authkey lifetime: mint per Open, cache the bearer

- Each `tsnet.Server.Up` consumes a single-use authkey, so caching
  the authkey doesn't help — by the time we'd want it again, it's
  spent.
- The OAuth bearer token (lifetime ~1h) we DO cache on the plugin
  singleton, keyed by credential bare-name. Refresh on miss /
  expiry. Secret rotation (operator pastes a new client_secret)
  invalidates the cache by hash comparison: cached
  `(client_id, client_secret)` bytes don't match the current secret
  bytes → drop the cache and re-fetch.
- Since `tsnet.Server` joins once at boot and stays joined
  (singleton, keepalive=always), the mint+up sequence runs ~once
  per process. Caching deeper than the bearer token isn't worth the
  invariant cost.

Reasoning: keeps Tailscale-shaped logic next to its schema. The
tunnel side stays a thin dispatcher.

### Q4. Dashboard UX: existing paste-secret modal, no new endpoints

- `SecretSlots()` returns two named slots:
  - `client_id` — label "OAuth client ID", description points at
    the Tailscale admin console
  - `client_secret` — label "OAuth client secret"
- The dashboard's existing `ConnectModal` renders these two
  password inputs against `/api/credentials/set` with no frontend
  changes. Disconnect → `/api/credentials/clear`.
- Owner is the special `default` profile / fixed sentinel — the
  credential is gateway-level, per-owner partitioning doesn't apply.
  Stored with a constant owner so re-pasting is idempotent.

If the existing modal special-cases `OAuthFlowProvider` in ways the
paste-only Tailscale case can't reach, that's frontend work this
iteration scopes out — flag it on review.

### Q5. Failure modes at runtime: surface clearly, don't crash the gateway

- If `tunnel.credential` is set but the referenced credential is
  missing → config-load diagnostic (caught by the `KindCredential`
  symbol resolution pass). The gateway refuses to start with a
  clear message.
- If the credential is present but no slot bytes are persisted
  (operator hasn't pasted yet) → tunnel `Open` returns an error
  ("tailscale credential %q: client_id missing"); the dependent
  endpoints surface the failure on first use. The rest of the
  gateway stays up so the operator can paste the credentials.
- If the OAuth exchange fails (network, bad client, revoked) →
  same surface: `Open` returns the error, caller logs it, dependent
  endpoints fail loudly.

Reasoning: matches the failure surface every other credential-bound
tunnel uses today (ssh_port_forward errors the same way when its
credential is unset).

### Q6. Backwards compatibility

- Tunnels with literal `authkey = "..."` (or env-var fallback) keep
  working unchanged — the credential path is opt-in.
- `{{secret:...}}` template inside the literal `authkey` field
  still resolves through the existing path.
- One iteration of overlap. Future bead: hard-deprecate the literal
  path once enough operators have migrated.

### Q7. Relationship to `gateway { control = "tailscale" }` OAuth (out of scope)

There's a *separate* OAuth path in main.go / onboard.go
(`mintTailscaleAuthKey`, onboard.go:386-449) used to mint per-device
authkeys for client onboarding. It reads
`Tailscale.OAuthClientID` / `OAuthClientSecret` literal fields on
the gateway block. The Tailscale API calls are nearly identical to
what the credential plugin will do, but the code path is unrelated
to the `tunnel "tailscale"` block this proposal targets.

Plausible follow-up: factor the OAuth + key-mint logic out of
onboard.go into the credential plugin (or a shared helper under
`tailscaleproto`) and let `gateway { credential = ... }` reference
the same `tailscale_oauth` credential. Not in this iteration —
keeps the change scoped and reviewable.

## Phase 3 — implementation outline (gated on review)

1. **`config/plugins/tailscaleproto/tailscaleproto.go`** — new
   package: `AuthKeyMinter` interface, `AuthKeyOpts` struct,
   `runtime.AcceptCredentialRuntime` registration in `init()`.
2. **`config/plugins/credentials/tailscale_oauth.go`** — plugin
   (empty body), `SecretSlots`, `MintAuthKey` (OAuth client-creds
   exchange + `POST /tailnet/-/keys`), bearer-token cache keyed by
   credential name + secret hash.
3. **`config/plugins/credentials/tailscale_oauth_test.go`** —
   `MintAuthKey` against `httptest.Server` mocking the Tailscale
   token + key endpoints; rotated-secret invalidation case.
4. **`config/plugins/tunnels/tailscale.go`** — `Open` learns to
   dispatch via `host.Credential` when set; `Refs` gains the
   optional credential entry; registration unchanged otherwise.
5. **`config/plugins/tunnels/tailscale_test.go` (or augment
   existing)** — config load with `credential = X` resolves to the
   right entity; literal-only path unchanged; both-set precedence
   warning fires.
6. **`doc/tailscale.md`** — operator-facing snippet leading with
   the credential shape; literal shape as a "Legacy" block.
7. **`config/plugins/all/all.go`** — import the new packages so the
   plugins register on startup.

## Out of scope

- The `gateway { control = "tailscale" } ... oauth_client_id/secret`
  path used by the onboarder (`mintTailscaleAuthKey` in onboard.go).
  Migrating it onto the same credential is a follow-up bead.
- Multi-tenant / multi-tailnet credentials per gateway.
- Replacing the long-lived `tailscale` tunnel's behaviour of caching
  state in `state_dir` (the authkey is consumed once; state persists
  across restarts).
- Authorization-code flow for Tailscale (the service doesn't expose
  one).
