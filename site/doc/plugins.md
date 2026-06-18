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
clawpatrol plugins info    <config.hcl> [name...]   # required privileges, no download
```

`plugins info` reads each GitHub plugin's signed static manifest for the
newest release satisfying its constraint and prints the metadata and the
privileges it requires — **without downloading the binary** — so you can
review what an install or upgrade would grant before it happens.

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
<repo>_<version>_SHA256SUMS           # sha256 of each archive (+ manifest)
<repo>_<version>_manifest.json        # static manifest (optional)
```

Only the trailing `_<os>_<arch>.tar.gz` is load-bearing — clawpatrol
selects the archive by that suffix and reads its checksum from
`SHA256SUMS` — so the prefix is convention, not a hard requirement.

The optional **static manifest** is the plugin's own manifest emitted by
its `--print-manifest` mode (the SDK's `pluginsdk.Run` handles the flag).
Publishing it as a release asset — listed in `SHA256SUMS` and covered by
the attestation — lets `clawpatrol plugins info` show a plugin's
metadata and **required privileges before downloading the binary**.

Add a build-provenance attestation with one workflow step so clawpatrol
can verify the binary (and the manifest) was built by your repo (see the
trust model below):

```yaml
# .github/workflows/release.yml (excerpt)
permissions:
  contents: write
  id-token: write       # for keyless signing
  attestations: write
steps:
  - run: |
      VER="${GITHUB_REF_NAME#v}"; REPO="${GITHUB_REPOSITORY##*/}"
      mkdir -p dist
      for pl in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
        GOOS="${pl%_*}" GOARCH="${pl#*_}" CGO_ENABLED=0 \
          go build -trimpath -ldflags "-s -w" -o "$REPO" .
        tar -czf "dist/${REPO}_${VER}_${pl}.tar.gz" "$REPO"; rm "$REPO"
      done
      go build -o "$REPO" . && ./"$REPO" --print-manifest \
        > "dist/${REPO}_${VER}_manifest.json" && rm "$REPO"
      ( cd dist && shasum -a 256 *.tar.gz *_manifest.json \
          > "${REPO}_${VER}_SHA256SUMS" )
  - uses: actions/attest-build-provenance@v2
    with:
      subject-path: |
        dist/*.tar.gz
        dist/*_manifest.json
  - uses: softprops/action-gh-release@v2
    with: { files: dist/* }
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
   an attestation that names a different commit (a re-pointed tag).

   How a *missing* attestation is treated is set per plugin by
   `provenance`:

   ```hcl
   plugin "customerio" {
     source     = "github.com/denoland/clawpatrol-customerio-plugin"
     version    = "~> 1.2"
     provenance = "require"   # "warn" (default) | "require" | "off"
   }
   ```

   - `"warn"` (default) — verify an attestation when present, else
     install checksum-only with a warning, so plugins that have not
     adopted attestations still install.
   - `"require"` — refuse a release that carries no attestation; use it
     for plugins you hold to the higher bar.
   - `"off"` — skip the attestation check (checksum + lockfile pinning
     still apply).

   A present-but-**invalid** attestation always fails closed (every mode
   but `"off"`).

   Provenance is also tracked trust-on-first-use, like the network
   grant: the lockfile records whether the pinned version was attested,
   and a later binary that **loses** provenance — attested before, not
   now — is **blocked** (a re-pointed tag, or an upgrade that drops its
   attestation, looks exactly like a supply-chain attack) until you
   accept it with `clawpatrol plugins approve <name>`. A plugin that was
   never attested keeps installing with a warning; only a *downgrade* is
   blocked.

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

Permissions come from three places, by risk:

- **Network and egress are declared by the plugin** in its manifest
  (*leak paths* the sandbox keeps bounded — see below) and recorded
  trust-on-first-use. The operator doesn't write them.
- **Privileged (sandbox off) is declared by the plugin but never
  trust-on-first-use** — handing a plugin full host access is too
  dangerous to grant silently, so it is held closed until the operator
  approves it explicitly (see below).
- **Extra host filesystem read paths and the operator-forced sandbox
  opt-out are operator-only**, declared on the `plugin` block.

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

### Privileged: declared by the plugin, approved explicitly

Some plugins genuinely cannot run sandboxed — they need to exec
arbitrary helper tools (`ssh`, `kubectl`, `aws`, …) and read the user's
tool configs (`~/.ssh`, `~/.aws`, `~/.kube`). Enumerating which binaries
and paths such a plugin touches is hopeless (a plugin that can run a
shell can run anything), so there is no fine-grained "exec" grant: a
plugin that needs this declares a single coarse **privileged**
capability, which runs it with the **sandbox off** — the same full host
access as the operator's `sandbox = "off"`.

```go
pluginsdk.Run(&pluginsdk.Plugin{
    Name:         "ssh_tools",
    Capabilities: pluginsdk.Capabilities{Privileged: true},
    // …
})
```

Because privileged hands the plugin full host access — it can read every
file the gateway user can, including clawpatrol's own secret store, and
run any command — it is **not** trust-on-first-use like network and
egress. The gateway holds a privileged plugin **closed** until the
operator approves it explicitly:

```
clawpatrol plugins approve <config.hcl> ssh_tools
```

Approval records `privileged = true` in `clawpatrol.lock.hcl`, gated on
the binary hash like every other grant, so a later version re-pends
approval. The dashboard's Plugins page shows the request on the blocked
card (a red **privileged** badge) and offers the same one-click approve.

```hcl
plugin "ssh_tools" {
  network    = "outbound"
  privileged = true
  hashes     = ["sha256:…"]
}
```

`privileged` is the plugin asking for what `sandbox = "off"` grants;
the operator's `sandbox = "off"` on the block is the operator forcing
the same thing directly (and wins outright, no approval needed). Prefer
a narrower capability — `Egress`, a built-in tunnel — whenever one fits;
reach for `privileged` only when the plugin must shell out.

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
  scrubbed either way. A plugin can also *request* the same full host
  access by declaring the [`privileged`](#privileged-declared-by-the-plugin-approved-explicitly)
  capability, which the operator then approves explicitly rather than
  hand-writing `sandbox = "off"`.

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

The gateway only dials targets sanctioned for that endpoint instance:

1. the exact host:port the agent originally dialed,
2. an entry of the endpoint's `hosts` list,
3. an entry of the plugin's **manifest-declared egress** set, or
4. an entry of the endpoint's `dial` allow-list:

```hcl
endpoint "example_https" "demo-site" {
  hosts    = ["demo.invalid"]
  upstream = "http://10.0.0.5:8000"
  dial     = ["10.0.0.5:8000", "*.internal.svc:443"]
}
```

Any other target is refused and audited (a `dial` / `deny` event on
the dashboard). Plugin-supplied *config* is never consulted for dial
authorization.

#### Manifest-declared egress

A plugin that always needs to reach the same upstreams — an AWS plugin
talking to `*.amazonaws.com`, say — declares them in its manifest
rather than making every operator hand-write a `dial` list:

```go
Capabilities: pluginsdk.Capabilities{
    Egress: []string{"*.amazonaws.com:443"},
},
```

Each entry is `host:port` or `*.suffix.tld:port` (the same shape as
`dial`). The gateway records the approved set in `clawpatrol.lock.hcl`
on first load (trust-on-first-use, alongside the network grant) and
merges it into every one of the plugin's endpoints' dial allow-list.
An upgrade that **broadens** egress — a new version that wants a
destination none of the approved entries cover — fails closed until
the operator re-approves it (`clawpatrol plugins approve`), exactly
like a network-grant escalation; a narrower or equal set loads
unchanged. The declared set is verified against the signed static
manifest, so `clawpatrol plugins info` shows a plugin's egress before
any binary is downloaded. The operator's `dial` list still works and
composes with the manifest set — use it for site-specific upstreams
the plugin author can't know.

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
before calling `InjectHTTP`. `InjectHTTP` is header-only by design —
the request body never flows through the plugin — so it stays cheap
for the common case. Use `HeaderSet` for auth headers such as
`Authorization`; `HeaderAdd` appends and may leave the agent's
placeholder value in place. A credential that must rewrite the URL or
body uses `TransformHTTP` instead (below).

#### Rewriting the URL or body: `TransformHTTP`

A credential that signs over the request body (AWS SigV4) or carries
its secret in the URL or body (telegram, discord) sets
`HTTPTransform: true` and implements `TransformHTTP`. The request body
is streamed to the plugin as an `io.Reader`, and the plugin returns the
header/method/URL mutations plus the outgoing body — so **buffering is
the plugin's choice**: read a prefix and stream the rest, or read it
all to sign.

```go
pluginsdk.CredentialDef{
    TypeName:      "example_sigv4",
    HTTPTransform: true,
    TransformHTTP: func(ctx context.Context, req pluginsdk.HTTPTransformRequest) (*pluginsdk.HTTPTransformResponse, error) {
        body, err := io.ReadAll(req.Body) // SigV4 needs the whole body to hash
        if err != nil {
            return nil, err
        }
        sig := sign(req.Method, req.URL, req.Headers, body, req.CredentialSecret)
        return &pluginsdk.HTTPTransformResponse{
            Headers: []pluginsdk.HeaderMutation{
                {Op: pluginsdk.HeaderSet, Name: "Authorization", Values: []string{sig}},
            },
            Redactions: []string{sig},
            Body:       bytes.NewReader(body), // forward the body unchanged
        }, nil
    },
}
```

Set `Response.Body = req.Body` to pass the input straight through (no
buffering — right for a URL-only rewrite). The gateway applies the
returned mutations **before** forwarding, so a body-derived signature
header is finalized first, then pipes the plugin's body upstream. If you
change the body length, set a `Content-Length` header mutation (or leave
it unset to forward with chunked transfer). HTTP trailers (e.g. gRPC's)
are preserved by the gateway across the transform — the plugin does not
handle them. If the plugin fails, the gateway fails the request closed
(the body was already streamed away), rather than forwarding a
half-transformed request.

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

The same applies to **SQL** endpoints. An endpoint that terminates a SQL
wire protocol (postgres, mysql, clickhouse, …) sets `Family: "sql"`,
parses each statement itself, and sends the coarse fields the built-in
`sql` facet exposes — `verb`, `tables`, `functions`, `database`, and
`statement` (which may be a `pluginsdk.Stream` for large queries):

```go
endpoint := pluginsdk.EndpointDef{
    TypeName: "example_sql",
    Family:   "sql", // bind to the built-in sql facet
    TLSMode:  pluginsdk.TLSTerminate,
    HandleConn: func(ctx context.Context, conn *pluginsdk.Conn) error {
        // ... parse one statement from the wire ...
        verdict, _ := conn.Evaluate(ctx, "sql", map[string]any{
            "verb":      "delete",
            "tables":    []string{"tokens"},
            "functions": []string{},
            "database":  db,
            "statement": pluginsdk.Stream(strings.NewReader(stmt)),
        }, stmt)
        // ... act on verdict ...
    },
}
```

Operators then reuse their existing `sql.*` rules verbatim —
`sql.verb == "delete"`, `sets.intersects(sql.tables, ["secrets"])`,
`sql.statement.contains("DROP")` — across any SQL plugin. `sql` is the
one shared built-in family exposed for opt-in (SQL has many engines that
benefit from a portable coarse guardrail); `k8s`, `ssh`, and bespoke
protocols use a plugin-declared facet instead.

### Persistent state

A sandboxed plugin has no writable filesystem of its own. When a plugin
must remember a few bytes across restarts — an SSH endpoint's host key, a
signing keypair, a dynamically registered client id — it uses the
gateway-backed state store rather than touching disk:

```go
const hostKeyName = "host_key"

func ensureHostKey(ctx context.Context) ([]byte, error) {
    st := pluginsdk.State()
    if v, found, err := st.Get(ctx, hostKeyName); err != nil {
        return nil, err
    } else if found {
        return v, nil
    }
    key := generateHostKey()
    return key, st.Put(ctx, hostKeyName, key)
}
```

Reach for `pluginsdk.State()` from a runtime callback — `HandleConn`,
`InjectHTTP`, `OpenTunnel`, or `Dial` — which is where identity like a
host key is actually needed. It is not available during a `Build`
callback on the gateway's first config load: the store lives in the
state dir, which is part of the config being loaded, so it is wired only
once that load finishes. The gateway namespaces every key by the plugin,
so one plugin can never read another's; values are capped at 1 MiB (this
is for identity, not bulk data) and survive restarts. The store is
reached over the plugin connection — no network grant and no `dial`
entry are involved. If the gateway is too old to provide it, the calls
return an error so the plugin can degrade gracefully.

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
  `example_passthrough` tunnel (dials upstream itself),
  `example_socks` tunnel (routes through a SOCKS5 proxy; opens
  its transport via the gateway's brokered dial, so it needs no
  network of its own and can be chained `via` another tunnel —
  TCP via CONNECT, UDP via UDP ASSOCIATE), `example_https`
  endpoint (binds to the built-in `http` facet), `example_smtp`
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
