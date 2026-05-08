# clawpatrol

Clawpatrol is a MITM gateway that sits between your AI agents — `claude`, `codex`, `gh` — and the upstream APIs they talk to. It injects credentials so the agent never sees them, enforces per-endpoint rules, and pulls a human into the loop when something needs explicit approval.

## install

```
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

## gateway

Stand up a gateway with one command. It generates a CA, writes a config, opens the firewall ports, and drops a systemd unit.

```
clawpatrol gateway init

Detected public IP: gw.example.com
├ Generated CA at /etc/clawpatrol/ca/ca.crt
├ Wrote /etc/clawpatrol/gateway.hcl
├ Opened udp/51820 + tcp/9080
└ Wrote /etc/systemd/system/clawpatrol-gateway.service

Dashboard: http://gw.example.com:9080
Join command: clawpatrol join http://gw.example.com:9080
```

```
systemctl enable --now clawpatrol-gateway
```

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

rule "http_rule" "github-reads" {
  endpoint = github-api
  match    = { method = ["GET", "HEAD"] }
  verdict  = "allow"
}
rule "http_rule" "github-writes" {
  endpoint = github-api
  match    = { method = ["POST", "PUT", "PATCH", "DELETE"] }
  approve  = [ops]
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

rule "sql_rule" "pg-secret-defense" {
  endpoint = pg-prod
  match    = { verb = "select", statement_regex = "(?i)\\b(secret|token|password)\\b" }
  approve  = [secret-judge]
}
```

## modes

Clawpatrol ships two control planes for the gateway-to-device tunnel. Pick one when you run `gateway init`; the default is WireGuard.

The WireGuard mode embeds a userspace WG endpoint inside the gateway. You only have to open one UDP port — there's no daemon, no `wg-quick`, and no kernel module on the gateway host. Devices run `clawpatrol join <gw>` and walk away with a per-machine WG conf.

The Tailscale mode joins the gateway to your existing tailnet as an exit-node. Devices that are already on the tailnet run `clawpatrol login` and pin `clawpatrol` as their exit-node. Use this if you already operate Tailscale and want its ACL and whois plumbing to gate onboarding.

You configure the choice with the `gateway` block:

```hcl
gateway {
  control = "wireguard"   # or "tailscale"

  # tailscale-only:
  oauth_client_id     = "{{secret:TS_OAUTH_CLIENT_ID}}"
  oauth_client_secret = "{{secret:TS_OAUTH_CLIENT_SECRET}}"
  tags                = ["tag:client"]

  # wireguard-only:
  wg_endpoint    = "gw.example.com:51820"
  wg_subnet_cidr = "10.55.0.0/24"
}
```
