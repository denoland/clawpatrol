# `tailscale_oauth` credential (design proposal)

Goal: replace the literal `oauth_client_id` / `oauth_client_secret`
fields on the `gateway {}` block with a credential reference, so the
operator pastes Tailscale OAuth client credentials into the dashboard
once instead of inlining them via `{{secret:...}}` env-var templating
in `gateway.hcl`.

Target shape:

```hcl
credential "tailscale_oauth" "ts" {}

gateway {
  control    = "tailscale"
  credential = ts
  tags       = ["tag:client"]
}
```

Old configs with literal `oauth_client_id` / `oauth_client_secret`
keep working through a deprecation window.

## Phase 1 — current state

- `Tailscale` struct (config/config.go:68-81) carries
  `OAuthClientID` / `OAuthClientSecret` literal fields. They're
  consumed only by `mintTailscaleAuthKey` (onboard.go:380), which does
  a Tailscale OAuth 2.0 *client-credentials* exchange and then mints a
  single-use device authkey via `POST
  https://api.tailscale.com/api/v2/tailnet/-/keys`.
- The gateway's own tailnet node (tailscale.go) uses
  `cfg.Tailscale.AuthKey` / `$TS_AUTHKEY` directly through
  `tsnet.Server`. That's an unrelated, long-lived authkey — not the
  OAuth path. Out of scope.
- Per-device authkey minting is the only place the OAuth client
  credentials are read at runtime.

Tailscale's OAuth exposes only the client-credentials grant — there is
no authorization-code redirect for end users. So the "OAuth flow" on
the dashboard reduces to "paste your client_id + client_secret here."

### Reference plugins

- **Closest template:** config/plugins/credentials/mtls.go — multi-
  slot paste via `SecretSlotsProvider`, runtime via
  `TLSCredentialRuntime` consumed protocol-side. The shape (multi-
  slot Bytes/Extras + protocol-specific runtime interface registered
  in a sibling package) maps cleanly onto Tailscale's needs.
- **Multi-slot + protocol runtime:** config/plugins/credentials/slack.go
  shows the pattern of a multi-slot paste credential that satisfies
  more than one runtime interface.
- **Protocol-package extension hook:** config/plugins/sshproto/sshproto.go
  defines a protocol-specific `AuthCredential` interface and calls
  `runtime.AcceptCredentialRuntime` in `init()` so the runtime
  checker accepts it without having to import the protocol package
  (config/runtime/checker.go:33-35). Same trick for Tailscale.
- **Not a good template:** the existing
  `OAuthFlowProvider` plugins (anthropic_oauth.go, github.go,
  openai_codex.go) drive authorization-code / device-code flows with
  per-owner browser redirects and per-owner `OAuthRegistry` state.
  Tailscale has no end-user flow; the credentials are gateway-level,
  not per-owner.

### Secret-store wiring (already in place)

- `gatewaySecretStore.Get` (secrets.go:37) walks credential_secrets
  (paste-slot SQLite) → `OAuthRegistry.Token` (browser-flow) →
  `CLAWPATROL_SECRET_<NAME>` env. The paste-slot tier covers us.
- The dashboard `/api/credentials/set` endpoint
  (web.go:715 `apiCredentialsSet`) accepts a `{slot, value}` map for
  any credential whose body implements `SecretSlotsProvider`. Two
  slots fall out for free if we get the plugin shape right.

## Phase 2 — design positions

### Q1. Credential plugin shape: multi-slot paste, not OAuth-flow

- `tailscale_oauth` body is an empty struct with a `SecretSlots()`
  returning two named slots (`client_id`, `client_secret`).
- Plugin satisfies a new `tailscaleproto.AuthKeyMinter` interface
  defined under `config/plugins/tailscaleproto/`. The Tailscale
  runtime side (onboarder) calls `MintAuthKey(ctx, secret, opts)` on
  the credential plugin; the plugin does the OAuth client-credentials
  exchange and the key-mint API call.
- `tailscaleproto.init()` calls
  `runtime.AcceptCredentialRuntime` so the runtime checker accepts
  the new interface without runtime needing to import the package
  (same trick as sshproto.go:42-49).

Reasoning: Tailscale's OAuth flow is degenerate — gateway-level
credentials, server-to-server exchange, no per-user redirect. Forcing
it through `OAuthFlowProvider` / `OAuthRegistry` would create a
per-owner row in the `credentials` table holding bytes that are
identical across owners and that the runtime never injects into a
request header. The `SecretSlotsProvider` + protocol-specific runtime
interface model already exists for exactly this shape (mtls is the
prior art) and reuses the dashboard's paste-secret modal end-to-end.

### Q2. Gateway block extension: opt-in `credential` field with deprecation on the literals

- Add `Credential string` (hcl:"credential,optional") to the
  `Tailscale` struct (config/config.go:68).
- Validation runs after the policy decode pass: if set, must resolve
  to a `credential "tailscale_oauth" "<name>" {}` in the symbol
  table. If unset, the literal `oauth_client_id` /
  `oauth_client_secret` path stays active.
- When `credential` is set, ignore the literals. When *both* are set,
  emit a load-time warning ("`gateway.credential` takes precedence;
  `oauth_client_id` / `oauth_client_secret` are ignored").
- When only the literals are set, emit a deprecation warning pointing
  operators at the new shape.

Reasoning: the cleaner long-term shape is "credential reference only"
but flipping unconditionally would break every existing tailnet-mode
deployment. The deprecation window is cheap; hard removal is a
follow-up.

The gateway block is parsed in pass 1 (operational gohcl decode) before
the policy symbol table exists, so we resolve the reference lazily —
the field holds the bare name as a plain string and the onboarder
looks it up in `policy.Credentials` at boot. This avoids restructuring
the two-pass loader for one field.

### Q3. Token refresh / lifetime: in the credential plugin

- The plugin caches the access token in an internal `tokenCache`
  keyed by credential bare-name. Refresh happens on cache miss / on
  expiry; secret rotation (operator pastes a new client_secret) is
  detected by comparing the cached `(client_id, client_secret)` hash
  against the current secret bytes — mismatch drops the cache.
- Authkey mints don't cache: each onboarding mints a fresh single-use
  key. The cache is for the OAuth access token only.
- The cache lives on the plugin singleton; clearing happens
  automatically on `/api/credentials/set` (which writes new slot
  bytes) because the next mint reads the rotated bytes and the hash
  check trips.

Reasoning: putting refresh in the credential keeps Tailscale-shaped
logic next to its schema. The runtime side (onboarder) stays a thin
dispatcher and doesn't grow per-provider OAuth knowledge.

### Q4. Dashboard UX: existing paste-secret modal, no new endpoints

- `SecretSlots()` returns two named slots:
  - `client_id` — label "OAuth client ID", description points at
    Tailscale admin console
  - `client_secret` — label "OAuth client secret"
- The dashboard's existing `ConnectModal` renders these two password
  inputs against `/api/credentials/set` with no frontend changes.
  Disconnect → `/api/credentials/clear`.
- Owner is the special `default` profile (or a fixed
  "gateway-owner" sentinel) — the credential is gateway-level so
  per-user partitioning doesn't apply. Stored with a constant
  `owner` so re-pasting is idempotent.

If the existing modal turns out to special-case the OAuthFlow path in
ways the paste-only Tailscale case can't reach, that's frontend work
that this iteration would scope out — flag it on review.

### Q5. Failure modes at boot: refuse to start (mirror today)

- If `gateway.credential` is set but the referenced credential is
  missing → config-load diagnostic, gateway won't start.
- If the credential is present but no slot bytes are persisted
  (and no env-var fallback `CLAWPATROL_SECRET_<NAME>_CLIENT_ID` etc.
  resolves) → onboarder returns an error at first device-onboard
  attempt, surfaced on the dashboard's onboarding page. The gateway
  itself stays up (its tailnet node uses the long-lived authkey, not
  the OAuth path), so the operator can paste the credentials in the
  dashboard to recover.

Reasoning: same shape as today. The existing
`tailscale oauth not configured` error (onboard.go:384) becomes
`tailscale credential %q: client_id missing` or similar.

### Q6. Backwards compatibility

- Old configs with `oauth_client_id` / `oauth_client_secret` literal
  fields keep working unchanged.
- The `{{secret:...}}` template path stays — it's a general HCL
  feature used by other plugins.
- One iteration of overlap: both paths supported, deprecation
  warning on the literals. Removal of the literal fields is a
  follow-up bead.

## Phase 3 — implementation outline (gated on review)

1. `config/plugins/tailscaleproto/tailscaleproto.go` — new
   `AuthKeyMinter` interface + `AcceptCredentialRuntime`
   registration.
2. `config/plugins/credentials/tailscale_oauth.go` — plugin (empty
   body), `SecretSlots`, `MintAuthKey`, token cache.
3. `config/config.go` — add `Credential string` field to
   `Tailscale`.
4. `onboard.go` — `mintTailscaleAuthKey` learns to dispatch via
   `policy.Credentials[ts.Credential]` when set, falling back to
   the literal path. Deprecation warnings via `log.Printf` (matching
   existing style).
5. `config/emit.go` — round-trip the new `credential` attr.
6. `doc/tailscale.md` — update operator-facing snippet to lead with
   the credential shape; keep the literal shape as a "Legacy"
   block.
7. Tests:
   - Plugin Build / Emit round-trip on a `tailscale_oauth` block.
   - Config load: gateway block with `credential = X` resolves to
     the right entity; with both set, deprecation warning fires;
     with unknown credential ref, load error.
   - `MintAuthKey` against a mock Tailscale token+key endpoint,
     plus the rotated-secret invalidation case.
   - Existing literal-field config loads & onboards unchanged
     (backwards-compat).

## Out of scope

- Removing the literal `oauth_client_id` / `oauth_client_secret`
  fields (follow-up).
- Multi-tenant / multi-tailnet credentials per gateway.
- Replacing `gateway.authkey` / `$TS_AUTHKEY` (the long-lived
  authkey for the gateway's own tailnet node — unrelated path).
- Authorization-code flow for Tailscale (the service doesn't expose
  one).
