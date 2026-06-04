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
