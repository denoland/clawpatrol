# Tunnels

A tunnel block tells the gateway how to reach an upstream that
isn't directly routable from its own network namespace. An
[endpoint](/docs/glossary/#endpoint) declares the wire protocol;
a tunnel declares the path the gateway dials over. Operators
write them as top-level blocks in `gateway.hcl`:

```hcl
tunnel "<type>" "<name>" { ... }
```

## When you need a tunnel

The gateway dials upstreams from its own netns by default. If the
upstream is publicly resolvable and the gateway can route to it,
no tunnel block is needed — the endpoint alone is enough. Reach
for a tunnel when:

- **Upstream is in a private VPC or cluster.** RDS behind an EKS
  VPC, an internal API behind a corporate VPN — the gateway needs
  someone else's network presence to reach it.
- **The vendor ships a sidecar proxy.** Cloud SQL's
  `cloud-sql-proxy`, AWS SSM port forwarding, and friends — they
  run locally, expose a port, and encapsulate auth.
- **Upstream lives on a tailnet.** MagicDNS-only hostnames and
  tailnet-internal IPs aren't reachable from the gateway's normal
  netns; embedded tsnet joins the tailnet in-process.
- **The upstream is only reachable from an SSH jump host.** A
  common pattern: a public-facing SSH server (the "bastion") sits
  in front of a private database or service that has no public
  route. The gateway opens one SSH session to the bastion and
  forwards every dial through it (`ssh -L` semantics).

## How endpoints reference a tunnel

`tunnel = <name>` is a framework attribute on the endpoint block,
the same shape as `credential = <name>`:

```hcl
tunnel "local_command" "csql-staging" {
  command = ["cloud-sql-proxy", "--auto-iam-authn",
    "denosr-staging:us-east4:main-pg14?port=5433"]
  listen      = "127.0.0.1:5433"
  ready_probe = "tcp"
}

endpoint "postgres" "pg-staging" {
  host   = "main-pg14.denosr-staging.internal:5432"
  tunnel = local_command.csql-staging
}
```

Three load-time consequences worth knowing:

1. **Tunneled endpoints reach the upstream via DNS-VIP.** The
   gateway intercepts the agent's DNS query for the endpoint's
   hostname and returns an allocated VIP; when the agent dials
   the VIP, the dispatcher routes it into the endpoint runtime,
   which then asks the tunnel to dial. Pure-IP `hosts = [...]`
   on a tunneled endpoint is a compile error — there's no DNS
   for the gateway to intercept. See
   [Architecture › DNS interception → VIP](/docs/architecture/#dns-interception--vip).
2. **The endpoint's `host` is what gets the VIP allocated.**
   Whether the tunnel then dials that address depends on the type.
   `ssh_port_forward` and `tailscale` honour it (the bastion /
   tsnet resolves the upstream from inside the remote network).
   `local_command` and `kubernetes_port_forward` ignore it — they
   already encode the upstream in their own config and dial a
   fixed local listener. The hostname is mandatory regardless, so
   DNS-VIP has a name to allocate against.
3. **One tunnel can serve many endpoints.** A single
   `local_command` running `cloud-sql-proxy` (`share =
   "singleton"`) is shared across every endpoint that names it.
   See [share and keepalive](#share-and-keepalive) below.

## Built-in tunnel types

Each subsection shows one terse HCL example. The full per-field
schema lives in
[Config Reference › tunnel blocks](/docs/config-reference/#tunnel-blocks).

### `local_command` — wrap a vendor proxy

Spawns an arbitrary command that exposes a local listener;
`Tunnel.Dial` always dials the configured `listen` address. Right
fit for cloud-sql-proxy, AWS SSM port forwarding, or any
"we already have a CLI for this upstream" case.

```hcl
tunnel "local_command" "csql-staging" {
  command = [
    "/usr/local/bin/cloud-sql-proxy", "--auto-iam-authn",
    "--credentials-file", "/opt/clawpatrol/secrets/avocet.json",
    "denosr-staging:us-east4:main-pg14?port=5433",
  ]
  listen        = "127.0.0.1:5433"
  ready_probe   = "tcp"
  ready_timeout = "30s"
  share         = "singleton"
  keepalive     = "10m"
}
```

See [config reference](/docs/config-reference/#tunnel-localcommand).

### `kubernetes_port_forward` — kubectl into a cluster

Shells out to `kubectl port-forward` against an existing pod, a
service, a label-selected pod, or a templated jump pod the
gateway creates on demand. Template mode is the workhorse for the
"socat sidecar inside EKS so the gateway can reach RDS in the
VPC" pattern.

```hcl
tunnel "kubernetes_port_forward" "pg-deployng-dev-jump" {
  server       = "https://....eks.amazonaws.com"
  cluster_name = "deployng-dev"
  region       = "us-east-2"
  credential   = aws_credential.avocet-aws
  ca_cert      = "<<file:eks-dev-ca.pem>>"
  port         = 5432
  share        = "singleton"
  keepalive    = "10m"
  template     = <<-EOT
    apiVersion: v1
    kind: Pod
    metadata: { generateName: clawpatrol-rds-jump- }
    spec:
      restartPolicy: Never
      containers:
      - name: socat
        image: alpine/socat:1.8.0.0
        args:
        - TCP-LISTEN:5432,fork,reuseaddr
        - TCP:deployng-dev.<rds-host>.rds.amazonaws.com:5432
        ports: [{ containerPort: 5432 }]
  EOT
}
```

The plugin authenticates to the apiserver in one of two modes:
either kubectl uses whatever the host's `KUBECONFIG` /
`~/.kube/config` selects (with optional `context = ...` to pin a
named context), or — when `server` is set — the plugin writes a
self-contained per-tunnel kubeconfig with a bearer minted from
the bound credential. The second mode is the right one for EKS:
pair it with an `aws_credential` and the plugin re-mints the
short-lived STS-presigned bearer on every kubectl call.

Template-created pods are stamped with `clawpatrol.dev/managed-by`
and `clawpatrol.dev/tunnel=<name>` labels. A startup sweep
deletes any leftover pods carrying those labels (a previous
daemon crash that skipped graceful teardown), so jump pods don't
accumulate. Set `cleanup = "keep"` to opt out.

See [config reference](/docs/config-reference/#tunnel-kubernetesportforward).

### `ssh_port_forward` — through a bastion

Opens one SSH session to a bastion and forwards every
`Tunnel.Dial` through it (`ssh -L` semantics, all in-process).
Multiple concurrent dials share the same session.

```hcl
tunnel "ssh_port_forward" "deploy-bastion" {
  bastion    = "bastion.deploy.example:22"
  user       = "root"
  credential = ssh_key.deploy-bastion
}

endpoint "postgres" "pg-internal" {
  host   = "pg.internal:5432"
  tunnel = ssh_port_forward.deploy-bastion
}
```

The upstream address is resolved on the bastion side — exactly
what you want when the upstream is only reachable from the
bastion's network. Pair with [`via`](#chaining-tunnels-with-via)
to reach a bastion that itself lives behind another tunnel.

See [config reference](/docs/config-reference/#tunnel-sshportforward).

### `tailscale` — embed a tsnet node

Joins the tailnet in-process via `tsnet.Server`; every dial
routes through it, so MagicDNS hostnames and tailnet-internal
IPs resolve correctly. The canonical case is an internal service
published on the tailnet that the gateway can't reach from its
host netns.

```hcl
credential "tailscale_auth" "deno-tailnet" {}

tunnel "tailscale" "deno-tailnet-tunnel" {
  credential = tailscale_auth.deno-tailnet
}

endpoint "clickhouse_native" "clickhouse-o11y" {
  hosts  = ["clickhouse-o11y.tail9a48e.ts.net"]
  tls    = true
  tunnel = tailscale.deno-tailnet-tunnel
}
```

Three auth shapes are supported. A bound `credential
"tailscale_auth"` keeps the node identity in the gateway's secret
store and surfaces a one-time interactive login URL on the
dashboard's Connect button — best fit when you want the tsnet
node to show up under a real user identity. An inline
`authkey = "..."` (with `CLAWPATROL_TUNNEL_<NAME>_AUTHKEY` env
fallback) is the pre-minted-key path. `oauth_client_secret = "..."`
mints fresh short-lived device keys on every join, so nothing
expires out from under you.

See [config reference](/docs/config-reference/#tunnel-tailscale).

## share and keepalive

Two knobs control how many runtime instances of a tunnel block
exist and how long they live. They sit on every tunnel type:

- `share = "singleton"` (default for `local_command`,
  `ssh_port_forward`, `tailscale`): one instance per tunnel name,
  shared across every endpoint and every connection.
- `share = "per_endpoint"` (default for
  `kubernetes_port_forward`): one instance per (tunnel, endpoint)
  pair. Right when each endpoint needs its own ephemeral local
  port — two endpoints can't share one `kubectl port-forward`
  listener.
- `share = "per_conn"`: one instance per inbound connection, torn
  down when the conn closes. Niche; useful when the tunnel's
  state should track a single request.

`keepalive = "<duration>"` is the idle window after refcount hits
zero before the manager calls Close. `keepalive = "always"` pins
the tunnel up for the policy lifetime (no idle teardown). Default
is zero — tear down as soon as the last endpoint goes idle.

## Chaining tunnels with `via`

Set `via = <other-tunnel>` on a tunnel block to route its
underlying TCP connection through another tunnel instead of
dialing directly from the gateway host. The canonical case is
`kubectl port-forward → ssh-server pod → ssh -L to RDS`:

```hcl
tunnel "kubernetes_port_forward" "ssh-jump-pod" {
  context = "..."
  pod     = "ssh-server"
  port    = 22
}

tunnel "ssh_port_forward" "rds-via-jump" {
  user       = "root"
  credential = ssh_key.jump-pod
  via        = kubernetes_port_forward.ssh-jump-pod
  # `bastion` omitted — the via tunnel handles addressing
}
```

The manager opens, refcounts, and tears down the `via` chain
automatically. Cycles in the `via` graph fail at compile time.

## Credentials on tunnels

The `credential = X` attribute on a tunnel block authenticates
the *tunnel's own transport* — the bastion login for
`ssh_port_forward`, the EKS bearer for
`kubernetes_port_forward` with `server` set, the tailnet node
identity for `tailscale`. It's distinct from the credential the
endpoint will inject into the agent's request once the tunnel is
up; that one lives on a separate `credential` block bound to the
endpoint.

So a postgres-behind-EKS deployment carries two credentials in
play: an `aws_credential` on the tunnel (mints the EKS bearer
for kubectl) and a `postgres_credential` on the endpoint (the
SCRAM password the gateway replays to RDS).
