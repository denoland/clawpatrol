# Plugins

Most of the protocols Claw Patrol gates — HTTPS, Postgres, ClickHouse,
SSH, Kubernetes — ship as **built-in** plugins compiled into the
gateway binary. When you need to gate something the binary doesn’t
know about, you can ship an **external** plugin: a separate Go
program the gateway spawns as a subprocess and talks to over gRPC,
modeled on Terraform’s provider design.

External plugins extend exactly the same registry the built-ins use.
They can declare:

- **Endpoint types** (the `endpoint "<type>" "<name>" { … }` block
  in HCL) — own the wire protocol for one upstream class.
- **Credential types** (`credential "<type>" "<name>" { … }`) —
  describe a secret-bearing identity.
- **Tunnel types** (`tunnel "<type>" "<name>" { … }`) — describe
  how the gateway reaches the upstream when it isn’t directly
  routable.
- **Facets** — protocol-family schemas with named fields. A facet
  exposes the variables a CEL rule condition can read
  (`example_smtp.verb`, `acme_webhook.signature`, …) and the
  columns the dashboard renders against the request log. Plugins
  that gate HTTPS reuse the built-in `http` facet; plugins for
  genuinely new protocols ship their own.

## Loading a plugin

Add a `plugin` block to the gateway HCL and reference its types
the same way you reference built-ins:

```hcl
plugin "example" {
  source = "./pluginsdk/example/example"
}

credential "example_magic_token" "demo_token" {}

endpoint "example_smtp" "demo-mail" {
  hosts      = ["mail.invalid:25"]
  credential = example_magic_token.demo_token
}
```

The `name` label (`"example"`) is informational — it’s the local
identifier you’d use to refer to this plugin’s source in tooling.
The names that actually matter are the **type names** and
**facet names** the plugin declares in its manifest. Both are flat
strings living in one global registry per kind (one for endpoint
types, one for credential types, one for tunnel types, one for
facets, each shared with the built-ins). The gateway does **not**
auto-namespace anything.

Plugin authors prefix their own names by convention — the way
Terraform providers do (`aws_iam_role`, `kubernetes_deployment`):
the SMTP endpoint in the example plugin is `example_smtp`,
its credential is `example_magic_token`, its custom facet is
also `example_smtp` (endpoint types and facets live in different
registries, so reusing one name for the matched pair is fine and
often clearer). A plugin that ships a name colliding *within* a
registry — with a built-in (e.g. `https` endpoint type, `http`
facet) or another plugin — fails at validate time with a clear
diagnostic.

## Installing a plugin from GitHub

`source` can be a local path (above) or a GitHub repository. With a
repository, clawpatrol resolves a semver constraint against the repo's
release tags, downloads the build for this host's OS/arch, verifies it,
caches it, and pins the resolved version in the lockfile — the same
model Terraform uses for providers:

```hcl
plugin "customerio" {
  source  = "github.com/denoland/clawpatrol-customerio-plugin"
  version = "~> 1.2"   # newest 1.x ≥ 1.2 ; omit for the newest stable
}
```

`version` is a [`hashicorp/go-version`][gv] constraint (`>= 1.2.0`,
`~> 1.2`, `~> 1.2.0`, `>= 1.0, < 2.0`, an exact `1.2.3`). `~> 1.2`
allows `1.x ≥ 1.2`; `~> 1.2.0` allows `1.2.x`. Pre-release tags are
excluded unless you pin one exactly. `version` is only valid on a
GitHub source.

[gv]: https://github.com/hashicorp/go-version

### install, update, lock

The download is an explicit, reviewable step — the running gateway only
ever loads the **locked** version, and never upgrades on its own:

```
clawpatrol plugins install <config.hcl> [name...]   # download + pin
clawpatrol plugins update  <config.hcl> [name...]   # re-pin to the newest match
clawpatrol plugins lock    <config.hcl> [name...]   # record all platforms' hashes
```

- **install** resolves the constraint (keeping any already-pinned
  version), downloads, caches under `<state_dir>/plugins/…`, and records
  the resolved version, the declared network, and the binary hash in
  `clawpatrol.lock.hcl` beside the config.
- **update** re-resolves to the newest release tag satisfying the
  constraint and re-pins it — the one place an upgrade happens. The new
  version shows up as a lockfile diff for review.
- **lock** records the binary hash of *every* platform build a release
  ships, so one committed lockfile verifies the plugin across a
  mixed-OS team.

The gateway checks GitHub for newer matching releases in the background
and surfaces "update available" on the dashboard's Plugins page, but
**never downloads or upgrades automatically** — you run `update`.

Commit `clawpatrol.lock.hcl`. On a fresh host the gateway downloads
exactly the locked version (verifying it) on first load; if the locked
version no longer satisfies the constraint, or the source changed, it
fails closed and tells you to run `install` / `update`.

### How a plugin must package its releases

So clawpatrol can find and verify the right binary, a plugin's GitHub
release must contain, per platform, an archive named with the Go
`GOOS`/`GOARCH` tokens, plus a checksums file:

```
<repo>_<version>_<os>_<arch>.tar.gz   # one per platform, holds the binary
<repo>_<version>_SHA256SUMS           # sha256 of each archive
```

This is the default [GoReleaser][gr] layout. Only the trailing
`_<os>_<arch>.tar.gz` is load-bearing — clawpatrol selects the archive
by that suffix and reads its checksum from `SHA256SUMS` — so the prefix
is convention, not a hard requirement. Add a build-provenance
attestation with one workflow line so clawpatrol can verify the binary
was built by your repo (see the trust model below):

```yaml
# .github/workflows/release.yml (excerpt)
permissions:
  contents: write
  id-token: write       # for keyless signing
  attestations: write
steps:
  - uses: goreleaser/goreleaser-action@v6
    with: { args: release --clean }
  - uses: actions/attest-build-provenance@v2
    with:
      subject-path: "dist/*.tar.gz"
```

[gr]: https://goreleaser.com

### Verification and trust

Three layers gate a downloaded binary, from least to most powerful:

1. **Checksum.** The archive's sha256 must match the release's
   `SHA256SUMS`.
2. **Trust on first use.** The extracted binary's hash is recorded in
   `clawpatrol.lock.hcl`; every later load re-hashes the cached binary
   and **fails closed** on any mismatch — and a version bump re-runs the
   permission-escalation check (a new release that newly wants `network`
   is blocked until you re-approve it).
3. **Build provenance.** If the release carries a GitHub
   [build-provenance attestation][att], clawpatrol verifies (via
   Sigstore) that the binary was built by *that repo's* GitHub Actions
   workflow — the `github.com/owner/repo` you already named is the trust
   anchor, so there is no key to manage. This closes the first-download
   gap that checksums alone leave open. The attestation also names the
   source **commit** the binary was built from; clawpatrol records it in
   the lockfile (`commit = "..."`) — an immutable reference, since tags
   are mutable — and on a later re-download of the pinned version rejects
   an attestation that names a different commit (a re-pointed tag). A
   repo that publishes no attestation still installs, verified by
   checksum, with a warning; a present-but-invalid attestation always
   fails closed.

[att]: https://docs.github.com/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds

## Sandbox and capability grants

Plugins are **untrusted**. A plugin runs in the gateway process tree
and the gateway holds secrets (the state DB with the CA key and
credential material, WireGuard / Tailscale keys, `CLAWPATROL_SECRET_*`
environment variables). To contain a malicious or compromised plugin,
every plugin subprocess runs inside an OS sandbox by default and with
a scrubbed environment — it inherits **none** of the gateway's
environment, only `PATH`, `HOME`, `TMPDIR` (pointing at a private
scratch dir) and the plugin socket path.

Permissions come from two places, by risk:

- **Network is declared by the plugin** in its manifest (a *leak path*
  the sandbox keeps bounded — see below). The operator doesn't write
  it.
- **Host filesystem access and the sandbox opt-out are operator-only**,
  declared on the `plugin` block, because they can expose every
  credential.

```hcl
plugin "ssh_tools" {
  source = "./plugins/ssh_tools"

  sandbox    = "enforce"     # "enforce" (default) | "off"
  read_paths = ["~/.ssh"]    # extra recursive read-only grants
  # network is NOT written here — the plugin declares it (see below).
  # network = "outbound"     # optional operator override / veto
}
```

### Network: declared by the plugin, recorded in a lockfile

A plugin states its network need in its manifest:

```go
pluginsdk.Run(&pluginsdk.Plugin{
    Name:         "ssh_tools",
    Capabilities: pluginsdk.Capabilities{Network: pluginsdk.NetworkOutbound},
    // …
})
```

`NetworkNone` (the default) cuts the plugin off from the network — its
only channel is the gateway socket, and upstream connections go
through the [brokered dial](#brokered-upstream-dial). `NetworkOutbound`
lets the plugin dial out itself; **tunnel plugins** (they *are* the
upstream transport, e.g. SSH or WireGuard) and credential plugins that
do their own token exchange need it.

On first load the gateway records the plugin's declared network in
**`clawpatrol.lock.hcl`** next to the config (commit it to VCS):

```hcl
plugin "ssh_tools" {
  network = "outbound"
  hashes = [
    "sha256:…", # linux-amd64
    "sha256:…", # darwin-arm64
  ]
}
```

`hashes` is the set of approved binary hashes — one per platform
build — so a single committed lockfile covers a team's different
OS/arch hosts (and a future distribution system can record every
platform's hash for a release at once). A binary is approved iff its
hash is in the set; they all share the same approved permissions.

This is **trust-on-first-use**. A binary whose hash isn't in the set
is re-checked: if it requests no more than the recorded permissions
(a new platform build, or a same-permission version) its hash is
added; if it escalates — say it now asks for `outbound` when the
lockfile recorded `none` — config load **fails closed** with a
loud diagnostic. That is exactly what a compromised plugin update
trying to open an exfiltration path looks like. After an intentional
upgrade, re-approve it:

```
clawpatrol plugins approve <config.hcl> ssh_tools
```

An operator can still set `network` on the `plugin` block to override
the plugin's request (force or veto); the override wins and is what
gets recorded.

### Filesystem and full-trust grants (operator-only)

- **`read_paths`** — extra host paths the plugin may read recursively,
  for plugins that genuinely need host files (an SSH tunnel reading
  `~/.ssh`). Paths are absolute; a leading `~/` expands to the gateway
  user's home. The gateway refuses a path overlapping the state dir
  (the secret store). There is **no host-write grant**: writing an
  active location (`~/.bashrc`, cron, a `$PATH` directory, …) is a
  code-execution-as-the-gateway-user primitive and no denylist of such
  locations can be complete, so a plugin that genuinely needs host
  writes must run with `sandbox = "off"`. Durable plugin storage goes
  through the gateway's blob store, not host files.
- **`sandbox`** — `"enforce"` (the default) runs the plugin inside an
  OS sandbox and **fails config load** if none can be established on
  this host. `"off"` is the single **full-trust** knob: it removes the
  sandbox entirely (full host read, write, and exec — the plugin can
  read every credential in the state DB), so only set it for a plugin
  you fully trust on a host that can't sandbox. The environment is
  scrubbed either way.

Backends, by platform:

| Platform | Backend | Isolation |
| --- | --- | --- |
| Linux | namespaces | user + mount + pid (+ network when `network="none"`) namespaces, a deny-by-default mount tree, dropped capabilities, `no_new_privs` |
| Linux (userns blocked) | Landlock | filesystem deny-by-default; TCP bind/connect denied on kernels with Landlock ABI ≥ 4. Degraded — loads with a warning |
| macOS | seatbelt | `sandbox-exec` deny-default profile |
| other | — | none; the plugin requires `sandbox = "off"` |

On Linux hosts where unprivileged user namespaces are disabled (e.g.
Ubuntu 24.04 with `kernel.apparmor_restrict_unprivileged_userns=1`),
the gateway automatically falls back to Landlock and logs a warning
describing what the fallback does not cover. If neither backend works
and `sandbox` is not `"off"`, the plugin block fails to load with a
diagnostic naming the cause and the opt-out.

Changing a plugin's sandbox or network grants takes effect on the
next gateway restart, not on config hot-reload.

### Brokered upstream dial

An endpoint plugin that needs to reach an upstream service does **not**
open the connection itself — it asks the gateway to:

```go
c, err := conn.DialUpstream(ctx, "tcp", "api.example.com:443",
    &pluginsdk.DialUpstreamOptions{TLS: true})
```

The gateway opens the connection on the plugin's behalf, routes it
through the endpoint's bound tunnel when one is configured,
optionally terminates upstream TLS (real certificate verification —
`TLS: true`), audits the attempt, and hands back a `net.Conn`. This
is what lets endpoint plugins run with `network = "none"`: they
receive credential secrets but cannot exfiltrate them, because they
have no socket of their own.

The gateway only dials targets the operator's HCL sanctions for that
endpoint instance:

1. the exact host:port the agent originally dialed,
2. an entry of the endpoint's `hosts` list, or
3. an entry of the endpoint's `dial` allow-list:

```hcl
endpoint "example_https" "demo-site" {
  hosts    = ["demo.invalid"]
  upstream = "http://10.0.0.5:8000"
  dial     = ["10.0.0.5:8000", "*.internal.svc:443"]
}
```

Any other target is refused and audited (a `dial` / `deny` event on
the dashboard). Plugin-supplied config is never consulted for dial
authorization — only HCL the operator wrote.

`DialUpstream` requires a gateway that supports the brokered-dial
protocol; against an older gateway it returns
`pluginsdk.ErrDialUpstreamUnsupported` immediately (rather than
hanging), and the plugin must fall back to its own `net.Dial` with an
operator-granted `network = "outbound"`.

Brokered dials and the agent connection are multiplexed over one
gRPC stream, so a plugin must keep reading every dial it opens
concurrently with the agent connection. A plugin that opens a dial
and then stops reading it can stall its own connection's other
traffic (other dials, audit events, the agent response). This only
affects the one connection the plugin is handling, but a misbehaving
plugin can wedge itself — drain your dial conns.

## Writing a plugin

Plugins are ordinary Go programs. The author SDK lives at
`github.com/denoland/clawpatrol/pluginsdk`; the canonical example
is `pluginsdk/example/` in the Claw Patrol repo.

```go
package main

import "github.com/denoland/clawpatrol/pluginsdk"

func main() {
    pluginsdk.Run(&pluginsdk.Plugin{
        Name:    "example",
        Version: "0.1",
        Credentials: []pluginsdk.CredentialDef{magicTokenDef()},
        Endpoints:   []pluginsdk.EndpointDef{demoSMTPDef()},
        Facets: []pluginsdk.FacetDef{{
            Name: "example_smtp",
            Fields: []pluginsdk.FacetField{
                {Name: "verb", Kind: pluginsdk.FacetString, Label: "Verb"},
                {Name: "mail_from", Kind: pluginsdk.FacetString, Label: "From", Optional: true},
                {Name: "body", Kind: pluginsdk.FacetStream, Label: "Body", Optional: true},
            },
        }},
    })
}
```

`pluginsdk.Run` blocks the process while the gateway is connected.
Build with `go build` like any Go binary; deploy by setting
`source = "<path>"` in the gateway HCL.

### External credential metadata and HTTPS injection

External credential plugins are trusted gateway components. The
gateway may send them credential secret bytes over the local plugin
RPC channel when a request is about to leave through the built-in
HTTPS endpoint. Only load plugin binaries you trust, and protect the
paths they are loaded from the same way you protect the gateway
binary.

A credential can return `pluginsdk.CredentialBuildResult` from
`Build` to publish dashboard secret slots, env pushdown placeholders,
OAuth flow metadata, and HTTPS injection support while keeping its
canonical config opaque to the gateway:

```go
pluginsdk.CredentialDef{
    TypeName:       "example_bearer",
    Disambiguators: []string{"placeholder"},
    HTTPInject:     true,
    Build: func(req pluginsdk.BuildRequest) (any, error) {
        return pluginsdk.CredentialBuildResult{
            Canonical: map[string]any{},
            Metadata: pluginsdk.CredentialMetadata{
                SecretSlots: []pluginsdk.SecretSlot{{Label: "Bearer token"}},
                EnvVars: []pluginsdk.EnvVar{{
                    Name:  "EXAMPLE_TOKEN",
                    Value: "PH_example",
                }},
                HTTPInject: true,
            },
        }, nil
    },
    InjectHTTP: func(ctx context.Context, req pluginsdk.HTTPInjectRequest) (*pluginsdk.HTTPInjectResponse, error) {
        return &pluginsdk.HTTPInjectResponse{Headers: []pluginsdk.HeaderMutation{{
            Op:     pluginsdk.HeaderSet,
            Name:   "Authorization",
            Values: []string{"Bearer " + string(req.CredentialSecret)},
        }}}, nil
    },
}
```

`Disambiguators` declares which credential/profile attrs are valid
for multi-credential dispatch. For HTTP credentials the conventional
field is `placeholder`: the agent sends a placeholder-looking token,
and the built-in HTTPS endpoint selects the matching credential
before calling `InjectHTTP`. `InjectHTTP` is intentionally
header-only; external credentials cannot rewrite the destination URL
or request body through this hook. Use `HeaderSet` for auth headers
such as `Authorization`; `HeaderAdd` appends and may leave the
agent's placeholder value in place.

At runtime the built-in HTTPS endpoint keeps the privilege split:

1. The wrapped process sees only metadata and placeholders from
   `EnvVars` (for example `EXAMPLE_TOKEN=PH_example`).
2. The gateway resolves the matched credential and fetches its
   gateway-held secret.
3. The gateway calls the external plugin's `InjectHTTP` callback
   with request metadata and that secret.
4. The plugin returns header mutations and any derived strings that
   should be redacted from audit samples.

Redactions are part of the security contract. The gateway automatically
redacts the raw credential secret it fetched, and audit samples also
mask obviously sensitive header names such as `Authorization`. If your
plugin injects any derived secret (for example an exchanged JWT or HMAC
signature), return the exact derived string in `HTTPInjectResponse.Redactions`.
Otherwise a derived value placed in a non-sensitive header such as
`X-Signature` may appear verbatim in request audit samples.

OAuth credentials can set `CredentialMetadata.OAuth` instead of
secret slots. OAuth metadata is intentionally Build-time and
instance-scoped, so two HCL blocks of the same credential type can
select different regions, URLs, scopes, or flows. The gateway owns the
OAuth lifecycle and stores or refreshes tokens under the credential
instance name; the external credential receives the current access
token as `CredentialSecret` when HTTPS injection runs. Dynamic MCP
OAuth providers should set
`Flow: "dynamic_mcp"`; the gateway will use public-client PKCE
exchange and refresh behavior selected by that flow, not by a
hardcoded provider hostname.

`InjectHTTP` is one gateway→plugin RPC round trip per proxied
request. External credentials that need provider-specific exchange
logic (for example exchanging a durable service-account token for a
short-lived JWT) should do that inside `InjectHTTP`, but must cache
the derived token in plugin memory and reuse it until expiry — do
not mint a fresh token on every request. The gateway bounds each
`InjectHTTP` call with a 30s deadline; a plugin that exceeds it is
logged and the request is forwarded without injection. Validate any provider base
URLs before sending long-lived secrets: plugin HCL is operator
configuration, but the plugin process is still the component that
knows which upstream hosts are allowed to receive its secret material.

### Endpoints own the connection

For each accepted agent connection on a plugin endpoint, the
gateway hands the plugin a `*pluginsdk.Conn` — a `net.Conn` plus
the connection’s profile / peer-IP / credential secret context.
The plugin owns the byte stream from there on.

```go
func handleSMTP(ctx context.Context, conn *pluginsdk.Conn) error {
    // ... parse the protocol ...
}
```

For `TLSMode: pluginsdk.TLSTerminate`, the gateway terminates TLS
using its own CA before handing over the `Conn` — the plugin sees
plaintext bytes and just speaks the inner protocol (HTTP, ESMTP,
…). For `pluginsdk.TLSNone` the plugin gets the raw TCP socket.

### Asking the gateway for a verdict

Plugins **must not decide allow/deny themselves.** They build a
structured action and ask the gateway:

```go
verdict, err := conn.Evaluate(ctx, "example_smtp", map[string]any{
    "verb":      "MAIL",
    "mail_from": "alice@example.com",
}, "MAIL FROM:<alice@example.com>")
```

The gateway:

1. Walks the matched endpoint’s compiled rule list with the
   action map bound to the named facet (so a rule like
   `example_smtp.verb == "MAIL"` evaluates).
2. Runs any approve chain (LLM judge, human approver) for rules
   whose outcome is `approve = […]`. Protocol plugins must translate
   denies and timeouts into native failure responses without calling
   upstream.
3. Logs the action onto the dashboard event stream with the
   action map as the facet payload.
4. Returns `verdict.Action` ("allow" / "deny" / "hitl_allow" /
   "hitl_deny") plus reason and matched rule name.

The plugin then translates the verdict into whatever the protocol
needs (250 vs 550 for SMTP, 200 vs 403 for HTTP, etc.).

`Conn.Emit` is for **non-policy** events only — operational
failures, session-open/close milestones, anything where no rule
fired. A hand-rolled `Action: "allow"` via Emit fabricates a
verdict no rule produced; use `Evaluate` instead.

### Stream-typed facet fields

A facet field declared with `Kind: pluginsdk.FacetStream` is a
lazy bytes value. The plugin offers the field as
`pluginsdk.Stream(io.Reader)`:

```go
verdict, err := conn.Evaluate(ctx, "example_smtp", map[string]any{
    "verb": "BODY",
    "body": pluginsdk.Stream(bytes.NewReader(messageBody)),
}, "BODY (4096 bytes)")
```

The gateway pulls bytes only as deeply as needed:

- **No rule on the endpoint reads the field** → the gateway pulls
  ~1 KiB just so the dashboard event log has a recognisable
  prefix, then cancels the stream.
- **At least one rule does** (e.g.
  `example_smtp.body.contains("urgent")`) → the gateway pulls up
  to ~1 MiB so the matcher sees the full value, then cancels.

When the plugin sees the cancel it can drop its source reader.
Bodies that overflow the cap mark the request `Truncated`: the
stream-typed fields become CEL unknowns and any rule whose
condition outcome depends on one is auto-denied (the same
unevaluable fail-close that protects the built-in HTTPS body
buffer).

### Optional facet fields

Fields marked `Optional: true` may be omitted from the action
map. The gateway substitutes the kind-zero value (empty string,
empty list, empty map, 0) before CEL evaluation, so rule
conditions can reference them without `has()` guards.

The zero-fill covers **declared** fields only. Selecting anything
else is a runtime evaluation error, which **fails closed**: the
rule synthesizes a deny instead of silently no-matching (see
"Unevaluable conditions fail closed" in the rules doc). That
includes a typo'd field name, a field the manifest never declared,
and a nested key off a map-shaped value — e.g.
`example_smtp.headers.x_priority` errors whenever the action's
`headers` map lacks that key. Guard nested lookups the same way as
the built-in facets: `'x_priority' in example_smtp.headers && ...`.

### Reusing a built-in facet

A plugin endpoint that gates HTTPS doesn’t need to redeclare a
facet — set `Family: "http"` on the endpoint and shape the action
map with the same keys the built-in `http` facet exposes
(`method`, `path`, `headers`, `body`):

```go
endpoint := pluginsdk.EndpointDef{
    TypeName: "example_https",
    Family:   "http", // bind to the built-in http facet
    TLSMode:  pluginsdk.TLSTerminate,
    HandleConn: func(ctx context.Context, conn *pluginsdk.Conn) error {
        // ... parse one HTTP request from conn ...
        verdict, _ := conn.Evaluate(ctx, "http", map[string]any{
            "method":  req.Method,
            "path":    req.URL.RequestURI(),
            "headers": req.Header,
            "body":    pluginsdk.Stream(req.Body),
        }, req.Method+" "+req.URL.RequestURI())
        // ... act on verdict ...
    },
}
```

Rules attached to this endpoint are written exactly the way they
would be against any in-process HTTPS endpoint:
`http.method == "POST"`, `http.body.contains("…")`, etc.

## Validating a plugin config

`clawpatrol validate` runs the same load path the daemon does, so
every plugin referenced from the HCL is spawned and its manifest
is checked. Beyond the HCL pipeline the validate command also runs
a schema-only pass (`Manager.Verify`) that catches plugin
authoring bugs even when the operator’s HCL doesn’t happen to
exercise them:

- Every declared facet’s CEL env is built eagerly (with a probe
  condition), and facet / field names are checked against the
  CEL identifier regex `[A-Za-z_][A-Za-z0-9_]*` — typos like
  `bad-name` fail validate instead of silently breaking the first
  rule that tries to use them.
- Every plugin endpoint’s `Family` is resolved against the facet
  registry. A typo’d Family that no rule references would
  otherwise just route every request to default-deny at runtime —
  silent policy bypass — and now becomes a clean validate-time
  error.
- Manifests with empty type / facet / field names or empty
  endpoint Family are rejected up front.
- A plugin type or facet whose name collides with a built-in
  (e.g. `https`, `http`) or with another plugin’s registration
  surfaces as a diagnostic instead of a panic.

The success line gains one summary row per loaded plugin so you
can see what came up:

```
ok: gateway.hcl — 7 endpoints across 3 profile(s)
  plugin "example" v0.1: 2 facet(s), 1 credential type(s), 1 tunnel type(s), 3 endpoint type(s)
```

## See also

- [`pluginsdk/example/`](https://github.com/denoland/clawpatrol/tree/main/pluginsdk/example)
  — fully exercised plugin: `example_magic_token` credential,
  `example_passthrough` tunnel, `example_https` endpoint
  (binds to the built-in `http` facet), `example_smtp`
  endpoint + matching `example_smtp` facet (optional + stream
  fields), `example_echo` endpoint + matching `example_echo`
  facet (plain TCP).
- [`pluginsdk/`](https://github.com/denoland/clawpatrol/tree/main/pluginsdk)
  — the author SDK package.
- [`config/extplugin/proto/plugin.proto`](https://github.com/denoland/clawpatrol/tree/main/config/extplugin/proto)
  — gRPC service definitions if you want to bypass the SDK.
- [Rules](rules) — how rule conditions and
  approve chains are evaluated against a request.
- [Config reference](config-reference) — the `plugin` block and
  every other top-level setting.
