# clawpatrol

Clawpatrol is a MITM gateway that sits between your AI agents — `claude`, `codex`, `gh` — and the upstream APIs they talk to. It injects credentials so the agent never sees them, enforces per-endpoint rules, and pulls a human into the loop when something needs explicit approval.

## install

```
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

## gateway

Copy [`gateway.example.hcl`](gateway.example.hcl) onto the gateway host, edit the operational fields (`listen`, `public_url`, `wg_endpoint`, `state_dir`, `dashboard_secret`, `admin_email`), open the firewall ports, and run:

```
clawpatrol gateway /opt/clawpatrol/gateway.hcl
```

Under systemd, drop a unit that runs the same command and `systemctl enable --now` it. The CA is lazy-minted into sqlite under `state_dir` on first boot. See [Getting Started](site/doc/getting-started.md) for the walkthrough.

## device

On every machine you want to route through the gateway, run `clawpatrol join`. You'll get a one-time code; verify it matches in the browser tab that opens, approve, and you're done.

```
clawpatrol join http://gw.example.com:9080

Verify code in browser:

    ABCD-1234

http://gw.example.com:9080/onboard/ABCD-1234

⠧ Waiting for approval
Approved.
├ Joined as 10.55.0.7
├ CA installed in system trust
└ Shell rc: eval "$(clawpatrol env)"

Installed! Try: clawpatrol run claude
```

`clawpatrol run` opens a per-process tunnel: only the wrapped command's traffic routes through the gateway, so your other apps keep using the public network as usual.

```
clawpatrol run claude
clawpatrol run gh pr create
clawpatrol run -- psql 'host=db user=agent'
```

If you'd rather route every packet on the host through the gateway, pass `--whole-machine` to `join`.

## policy

Policy lives in `gateway.hcl`. You declare credentials, the endpoints they unlock, and the rules that decide what's allowed. References are bare names — no quotes, no kind prefix.

The full per-block field reference lives at [`site/doc/config-reference.md`](site/doc/config-reference.md). It is auto-generated from the plugin registry under `config/plugins/`; regenerate after adding a plugin or changing an `hcl:"..."` tag:

```
go generate ./config/plugins/all/
# or directly:
go run ./tools/docgen
```

A `go test ./tools/docgen/...` drift check fails when the committed reference disagrees with the live schema.

```hcl
credential "anthropic_oauth_subscription" "claude" {}
credential "github_oauth"                 "github" {}

endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  credential = claude
}
endpoint "https" "github-api" {
  hosts      = ["api.github.com"]
  credential = github
}

approver "human_approver" "ops" {
  channel = "#agent-ops"
}

rule "github-reads" {
  endpoint  = github-api
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
rule "github-writes" {
  endpoint  = github-api
  condition = "http.method in ['POST', 'PUT', 'PATCH', 'DELETE']"
  approve   = [ops]
}

profile "default" {
  endpoints = [anthropic, github-api]
}
```

For cheap, automated checks you can put an LLM in front of a rule. The proctor reads a policy block, looks at the request, and votes allow or deny.

```hcl
policy "no-secret-columns" {
  text = "Deny if the SELECT touches columns named like secret/token/password."
}

approver "llm_approver" "secret-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = claude
  policy     = no-secret-columns
}

rule "pg-secret-defense" {
  endpoint  = pg-prod
  condition = "sql.verb == 'select' && sql.statement.matches('(?i)\\\\b(secret|token|password)\\\\b')"
  approve   = [secret-judge]
}
```

## modes

Clawpatrol ships two control planes for the gateway-to-device tunnel. Pick one in `gateway.hcl`; `gateway.example.hcl` ships with WireGuard.

The WireGuard mode embeds a userspace WG endpoint inside the gateway. You only have to open one UDP port — there's no daemon, no `wg-quick`, and no kernel module on the gateway host. Devices run `clawpatrol join <gw>` and walk away with a per-machine WG conf.

The Tailscale mode joins the gateway to your existing tailnet as an exit-node. Devices that are already on the tailnet run `clawpatrol login` and pin `clawpatrol` as their exit-node. Use this if you already operate Tailscale and want its ACL and whois plumbing to gate onboarding.

You configure the choice with top-level fields:

```hcl
control = "wireguard"   # or "tailscale"

# tailscale-only:
oauth_client_id     = "{{secret:TS_OAUTH_CLIENT_ID}}"
oauth_client_secret = "{{secret:TS_OAUTH_CLIENT_SECRET}}"
tailscale_tags      = ["tag:client"]

# wireguard-only:
wg_endpoint    = "gw.example.com:51820"
wg_subnet_cidr = "10.55.0.0/24"
```
