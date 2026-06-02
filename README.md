# clawpatrol

The security firewall for agents.

Claw Patrol sits between your agents and prod, parses their traffic
at the wire, and gates each action against rules you write in HCL.
For example, you can block destructive SQL, or pause `kubectl delete pod`
until a human approves it before the request reaches Kubernetes.

For the full overview see [clawpatrol.dev](https://clawpatrol.dev).

## Install

```
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

From source: `make` (requires Go and Node.js).

## A rule

A real rule from our own production config:

```hcl
rule "k8s-no-secrets" {
  endpoint  = k8s-prod
  condition = "k8s.resource == 'secrets'"
  verdict   = "deny"
  reason    = "Secret values must not leave the cluster via the agent"
}
```

Conditions are CEL expressions over wire-level facts the gateway
extracts per protocol: SQL verbs and table names for Postgres /
ClickHouse, resource / verb / namespace for Kubernetes, method /
path / headers / body for HTTP. The full set of facts lives in the
[config reference](https://clawpatrol.dev/docs/config-reference).

## Run

Three deployment shapes; pick whichever fits.

```
clawpatrol gateway config.hcl   # run the proxy itself
clawpatrol join <gateway-url>   # join a gateway
clawpatrol run claude           # wrap one agent's process tree
```

`clawpatrol run` opens a per-process tunnel on Linux (via netns) or
macOS (via NetworkExtension); only the wrapped command's traffic
goes through the gateway. `clawpatrol join` brings up a WireGuard
tunnel that routes the whole host. `clawpatrol gateway` is the
proxy: a single binary that loads your HCL config and accepts
clients tunneling in via WireGuard or Tailscale.

## Configure

[clawpatrol.dev/docs/getting-started](https://clawpatrol.dev/docs/getting-started)
walks through a first config end-to-end.
[clawpatrol.dev/docs/config-reference](https://clawpatrol.dev/docs/config-reference)
is the auto-generated field reference. See
[`gateway.example.hcl`](examples/gateway.example.hcl) for an
annotated starting template.

## License

MIT. See [LICENSE.md](LICENSE.md).
