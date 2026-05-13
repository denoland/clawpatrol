# `tailscale` credential (design proposal)

Goal: bind a `tailscale` credential to the `tunnel "tailscale"` block so the
operator authenticates the gateway's tsnet node into a tailnet *once*, via the
dashboard, by completing Tailscale's interactive login flow — exactly the
sequence `tailscale up` runs on a fresh device. The node identity (node key +
machine key) lands in SQLite via the credential secret store and is reused
across gateway restarts. Replaces the inline `authkey = "..."` field (and the
`CLAWPATROL_TUNNEL_<NAME>_AUTHKEY` env-var fallback) for tunnels that opt into
the credential reference.

Target shape:

```hcl
credential "tailscale" "my-tailnet" {}

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

Operator UX (per `arnauorriols`' clarification on #221):

1. Add `credential "tailscale" "my-tailnet" {}` to HCL.
2. Add `credential = my-tailnet` into a `tunnel "tailscale" "..."` block.
3. In the dashboard, on every profile that uses a tunnel bound to this
   credential, the tailscale credential appears in the integrations list.
4. Click the integration → click "Connect" → redirected to the standard
   Tailscale device-login URL. Approve the node on tailscale's side.
5. The gateway's tsnet node finishes joining the tailnet (`tailscale up`
   semantics). The node key is persisted in SQLite via credential_secrets and
   reused on every subsequent gateway restart — no re-auth required until the
   operator explicitly Disconnects.

Old tunnels with literal `authkey = "..."` / env-var fallback keep working
unchanged.

## Phase 1 — current state

- `TailscaleTunnel` (config/plugins/tunnels/tailscale.go) already carries a
  framework-level `Credential string` field via `commonRefs`
  (config/plugins/tunnels/util.go). It's currently unused — `Open` reads
  `t.AuthKey` and falls back to `CLAWPATROL_TUNNEL_<NAME>_AUTHKEY`. No
  credential resolution path exists yet for this tunnel type.
- The runtime side already plumbs `TunnelHost.Credential` (resolved entity)
  and `TunnelHost.SecretStore` (paste-slot SQLite reader/writer) to every
  tunnel's `Open` (config/runtime/tunnel.go). The ssh_port_forward tunnel is
  prior art for the dispatch pattern: resolve `host.Credential.Body` as a
  protocol-specific interface and pull bytes via `host.SecretStore.Get`.
- `tsnet.Server` already supports everything we need to ride the interactive
  flow without an authkey:
  - leave `AuthKey` empty and tsnet emits an interactive login URL via
    `Server.LoginURL()` / its `WatchIPNBus` notifications;
  - inject a custom `ipn.StateStore` via `Server.Store` and tsnet routes all
    node-identity bytes (machine key, node key, login profile) through it.
  - subsequent `Up()` calls with the same Store re-use the stored identity
    silently — no URL prompt — exactly the `tailscale up` cached-state path.

### Reference plugins

- **Closest template — credential side (slot layout & secret-store wiring):**
  config/plugins/credentials/mtls.go. Multi-slot paste, runtime exposed
  through a protocol-specific interface that the tunnel reads off
  `host.Credential.Body`. Our case has one slot (the tsnet state blob)
  written by the gateway itself, not pasted — but the storage/runtime
  hand-off is identical.
- **Closest template — tunnel side:** config/plugins/tunnels/ssh_port_forward.go.
  The tunnel declares its credential via `Refs` (`{Path: "Credential", Kind:
  KindCredential}`) and asserts `host.Credential.Body.(sshproto.AuthCredential)`
  in `Open`. The protocol-side interface lives in config/plugins/sshproto/
  and registers with the runtime checker via `runtime.AcceptCredentialRuntime`
  in `init()` so the runtime package doesn't have to import the protocol
  package (config/runtime/checker.go).
- **Closest template — dashboard "Connect" UX (with caveats):** the existing
  `OAuthFlowProvider` plugins (anthropic_oauth.go, github.go, openai_codex.go).
  They drive browser redirects against an IdP and stash a token in
  `OAuthRegistry`. Tailscale's case is *visually* identical from the dashboard's
  POV ("click Connect, follow a redirect, come back authed"), but the underlying
  primitive is wrong — see Q4.

### Secret-store wiring (already in place)

- `gatewaySecretStore.Get` (config/runtime/secrets.go) walks credential_secrets
  (paste-slot SQLite) → `OAuthRegistry.Token` (browser-flow) →
  `CLAWPATROL_SECRET_<NAME>` env. The paste-slot tier is the one we'll write
  through, with the gateway as the *writer* (not the operator pasting).
- The dashboard `/api/credentials/set` endpoint accepts a `{slot, value}` map
  for any credential whose body implements `SecretSlotsProvider`. We do *not*
  use this — the node state is gateway-written, not operator-pasted.

## Phase 2 — design positions

### Q1. Credential plugin shape: empty body, gateway-written state, new protocol interface

- `tailscale` credential body is an empty struct. No `SecretSlots()` —
  there's nothing for the operator to paste. The slot the gateway writes
  through is reserved/named internally (e.g. `"state"`) but invisible in the
  paste-modal flow.
- Plugin satisfies a new `tailscaleproto.NodeIdentity` interface under
  `config/plugins/tailscaleproto/`:

  ```go
  type NodeIdentity interface {
      // StateStore returns an ipn.StateStore that persists tsnet's
      // identity bytes through the gateway secret store (sqlite).
      // `name` is the credential bare name; `store` is the gateway's
      // SecretStore handle plumbed through TunnelHost.
      StateStore(name string, store runtime.SecretStore) ipn.StateStore
  }
  ```

- `tailscaleproto.init()` calls `runtime.AcceptCredentialRuntime((*NodeIdentity)(nil))`
  so the runtime checker accepts the new interface without runtime needing to
  import the protocol package (sshproto is the pattern).

Reasoning: we don't want the operator pasting anything — that defeats the
"works like `tailscale up`" UX. The credential body carries no
operator-relevant fields; its only job is to (a) attest a tunnel's intent to
authenticate as a node in *some* tailnet, and (b) own a stable name under
which the gateway persists node state. Per-tailnet selection (`control_url`,
tailnet ID) is the same set of optional knobs already on the tunnel block.

### Q2. Tunnel block extension: opt-in `credential`, kept literal `authkey` for back-compat

- `TailscaleTunnel.Credential` already exists (framework-level). Wire it
  through:
  - Add `{Path: "Credential", Kind: KindCredential, Optional: true}` to the
    tunnel plugin's `Refs` (validated against the credentials symbol table,
    optional for back-compat).
  - In `Open`, when `host.Credential != nil`:
    - type-assert `host.Credential.Body.(tailscaleproto.NodeIdentity)`,
    - build the per-credential `ipn.StateStore`,
    - construct `tsnet.Server` with `Store: store` and **no** `AuthKey`,
    - call `Up(ctx)`. If state already exists in sqlite, Up returns silently.
      If state is empty, tsnet emits a `LoginURL` — see Q3.
  - When `host.Credential == nil`: keep the current literal / env-var path
    verbatim.
- If both `credential` and literal `authkey` are set: emit a load-time warning
  ("`tunnel.credential` takes precedence; literal `authkey` is ignored").
- If only the literal is set: keep working silently for now. A deprecation
  warning is a follow-up.

Reasoning: opt-in keeps every existing deployment working without config
changes. Hard removal of the literal path is a follow-up once dashboards exist
for the operator to migrate.

### Q3. The "OAuth flow" is tsnet's interactive login URL, not a clawpatrol OAuth flow

- When `tsnet.Server.Up` runs without an authkey and without prior state,
  tsnet contacts the control plane and yields a login URL of the form
  `https://login.tailscale.com/a/<token>`. We capture it.
- The capture path: the tunnel's `Open` runs tsnet asynchronously. While the
  node is unjoined, it parks the LoginURL on a side-channel keyed by
  credential name — concretely, a `runtime.PendingNodeAuth` registry plumbed
  through `TunnelHost` (or a small in-process map owned by the
  `tailscaleproto` package) that the dashboard can read.
- The dashboard's "Connect" handler reads the pending URL and serves it as
  the redirect target. The user lands on tailscale.com, approves the node,
  tsnet receives the node-state notification, our `ipn.StateStore` writes the
  bytes through `host.SecretStore.Set(name, "state", bytes)`, and tsnet
  finishes `Up`. Subsequent restarts find the state in sqlite and skip the
  URL step.
- "Disconnect" → dashboard wipes credential_secrets for this credential and
  signals the tunnel to drop its tsnet node (force re-auth on next Open).

Reasoning: this is the only way to deliver `tailscale up` semantics. The
alternatives (operator pastes an authkey, operator pastes OAuth client_id +
secret) are both forms of "now you go figure out how to mint a key" — exactly
what the user pushed back on. The interactive flow already exists inside
tsnet; the design just needs to expose its emitted URL to the dashboard and
back its StateStore by sqlite instead of a filesystem dir.

### Q4. Dashboard UX: new `TailscaleAuthProvider`, not `OAuthFlowProvider`

- The dashboard's existing `OAuthFlowProvider` mechanism is the right shape
  (a credential surfacing a "Connect" affordance that opens a redirect) but
  the wrong primitive:
  - `OAuthFlow()` returns a *static* `OAuthIntegration` with hardcoded
    `AuthURL`/`TokenURL`/`Scopes`. Tailscale's URL is *dynamic*, minted by
    tsnet per attempt, and there is no clawpatrol-side token exchange.
  - `OAuthRegistry` stores a single OAuth access/refresh token per
    credential. Tailscale's persistence shape is different — tsnet writes
    a multi-slot identity bundle (machine key, node key, login profile)
    through `ipn.StateStore`, and the registry has no notion of that.
- Introduce `TailscaleAuthProvider` in `config/plugins/tailscaleproto/`
  (lives next to the `NodeIdentity` interface — both are the protocol-
  specific contract between the tailscale tunnel/credential plugins and
  the dashboard):

  ```go
  type TailscaleAuthProvider interface {
      TailscaleAuth() *TailscaleAuthIntegration
  }

  type TailscaleAuthIntegration struct {
      // BeginURL is a dashboard-relative endpoint the frontend POSTs
      // to start (or re-fetch) the live auth URL. The handler reads
      // the runtime PendingNodeAuth registry and returns either the
      // URL or "node already connected".
      BeginURL string
      // Status / Disconnect endpoints follow the same shape as the
      // existing OAuth integrations — different handlers, same
      // dashboard contract.
  }
  ```

- The dashboard's connect modal grows one branch: if a credential exposes
  `TailscaleAuth()`, render the "Connect" button against the live BeginURL
  flow instead of the OAuthRegistry handshake.
- Surfacing: per the user's UX ask, the integrations list rendered for a
  profile must include every credential referenced (directly or transitively)
  by a tunnel that is wired into that profile's endpoints. This is a
  resolution change in the integrations endpoint (today it walks
  endpoint-attached credentials; it has to also walk tunnel-attached
  credentials). Already partly there — endpoints in this tunnel's
  dependency cone surface their auth requirements; we extend the walk one
  hop further to include the tunnel's `Credential`.

If the dashboard's existing connect modal can't be cleanly forked without a
larger rewrite, the implementation iteration is allowed to ship the backend
hooks and stub the frontend on a follow-up bead — flag at review.

### Q5. Boot ordering: don't block startup on operator click

- The credential is *required* for tsnet to come up the first time, but the
  operator has to click Connect in the dashboard for that to happen. So:
  - `Open` returns immediately with a tunnel whose `Dial` errors with
    `"tailscale credential %q: node not connected — visit dashboard"` until
    the underlying tsnet reports Joined.
  - The async tsnet Up runs in a goroutine. Once joined, the tunnel flips to
    operational; in-flight retries from endpoints succeed naturally.
  - If state already exists in sqlite (post-first-connect, every restart),
    tsnet joins in seconds and the error window is invisible.
- This mirrors the failure surface of OAuth credentials: requests fail with
  "credential not connected" until the operator completes the dance.

Reasoning: blocking gateway startup on a dashboard click would deadlock the
operator (the dashboard runs on the gateway). Async with clear error text on
dependent endpoints is the only sane shape.

### Q6. Failure modes at runtime: surface clearly, don't crash the gateway

- `tunnel.credential` set but missing → config-load diagnostic (caught by the
  `KindCredential` symbol resolution pass). Gateway refuses to start with a
  clear message.
- Credential present, no stored state, no operator action yet → tunnel comes
  up "pending", `Dial` returns the "not connected" error. Dependent endpoints
  fail loudly. Rest of the gateway stays up so the dashboard remains
  reachable.
- tsnet Up errors (network, tailnet revoked the node, tags rejected) →
  bubble the error onto the same Dial path and surface in the dashboard
  integration status.

Reasoning: matches the failure surface every other credential-bound tunnel
uses today.

### Q7. Backwards compatibility

- Tunnels with literal `authkey = "..."` (or env-var fallback) keep working
  unchanged — the credential path is opt-in.
- `{{secret:...}}` template inside the literal `authkey` field still resolves
  through the existing path.
- One iteration of overlap. Future bead: hard-deprecate the literal path
  once enough operators have migrated.

### Q8. Relationship to `gateway { control = "tailscale" }` OAuth (out of scope)

There's a *separate* OAuth path in main.go / onboard.go (`mintTailscaleAuthKey`,
onboard.go) used to mint per-device authkeys for client onboarding via the
Tailscale REST API. It reads `Tailscale.OAuthClientID` /
`OAuthClientSecret` literal fields on the gateway block. That path is
fundamentally about *generating keys for other nodes*; this credential is
about *being a node*. They're disjoint flows that happen to share the
"Tailscale" brand.

Plausible follow-up: introduce a separate `tailscale_admin` (or similar)
credential that wraps OAuth client_id+secret for the onboarder, and migrate
`gateway.tailscale.oauth_client_id/secret` onto it. Not in this iteration —
keeps the change scoped and reviewable.

## Phase 3 — implementation outline (gated on review)

1. **`config/plugins/tailscaleproto/tailscaleproto.go`** — new package:
   `NodeIdentity` interface, `runtime.AcceptCredentialRuntime` registration in
   `init()`. Also exports the small `PendingNodeAuth` registry type used by
   the tunnel→dashboard side-channel.
2. **`config/plugins/credentials/tailscale.go`** — credential plugin (empty
   body). Implements `NodeIdentity.StateStore` returning a sqlite-backed
   `ipn.StateStore` that reads/writes through `runtime.SecretStore`.
   Implements `TailscaleAuthProvider` so the dashboard discovers the connect
   affordance.
3. **`config/plugins/credentials/tailscale_test.go`** — StateStore round-trip
   against an in-memory `SecretStore`; `NodeAuthFlow()` integration surfaces
   the right BeginURL.
4. **`config/plugins/tunnels/tailscale.go`** — `Open` learns the
   credential-driven path: build StateStore from credential, run
   `tsnet.Server.Up` without authkey, capture LoginURL into
   `PendingNodeAuth`, return a tunnel that errors `Dial` until joined.
   `Refs` gains the optional credential entry. Existing literal/env-var path
   unchanged.
5. **`config/plugins/tunnels/tailscale_test.go`** — config load with
   `credential = X` resolves correctly; literal-only path unchanged;
   both-set precedence warning fires; "node not connected" error surfaces
   on Dial.
6. **Dashboard integration walker** — extend the profile-integrations
   resolver so it picks up credentials attached to tunnels (not just
   endpoint-attached). Render `TailscaleAuthProvider` credentials with the
   live-URL Connect flow.
7. **`doc/tailscale.md`** — operator-facing snippet leading with the
   credential shape; literal shape as a "Legacy" block.
8. **`config/plugins/all/all.go`** — import the new packages so the plugins
   register on startup.

## Out of scope

- The `gateway { control = "tailscale" } ... oauth_client_id/secret` path
  used by the onboarder. Separate credential for that is a follow-up bead.
- Multi-node-per-credential: one credential = one tsnet node identity. If an
  operator wants two distinct tailnet identities, they declare two
  credentials.
- Multi-tenant / multi-tailnet from the same credential.
- Replacing the long-lived `tailscale` tunnel's behaviour of caching state in
  `state_dir` for *literal-authkey* deployments. The credential path replaces
  state_dir entirely (state lives in sqlite); the literal-authkey path keeps
  using state_dir until that path is deprecated.
- Authorization-code OAuth flow against Tailscale's REST API for client
  onboarders — different problem, different credential.
