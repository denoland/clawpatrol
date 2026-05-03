# clawpatrol

MITM gateway for AI agents. Sits between `claude` / `codex` / `gh` and the upstream API. Injects credentials, enforces rules, prompts a human for the dangerous stuff.

## install

```
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

## gateway

```
clawpatrol gateway init

Detected public IP: gw.example.com
├ Generated CA at /etc/clawpatrol/ca/ca.crt
├ Wrote /etc/clawpatrol/gateway.hcl
├ Opened udp/51820 + tcp/9080
└ Wrote /etc/systemd/system/clawpatrol-gateway.service

Dashboard: http://gw.example.com:9080
Join command: clawpatrol join --url http://gw.example.com:9080
```

```
systemctl enable --now clawpatrol-gateway
```

## device

```
clawpatrol join --url http://gw.example.com:9080

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

`clawpatrol run` per-process tunnel — only the wrapped command routes via the gateway. No host-wide route table changes.

```
clawpatrol run claude
clawpatrol run gh pr create
clawpatrol run -- psql 'host=db user=agent'
```

For host-wide routing pass `--whole-machine` to `join`.

## policy

`gateway.hcl` declares credentials, endpoints, rules. Bare-name refs throughout.

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

LLM proctor for cheap automated checks:

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

## operator

Dashboard at `public_url`. Live request stream, paste OAuth tokens, approve/deny pending HITL. Slack delivery: drop a `slack_tokens` credential block + reference it from a `human_approver` — interactive approve/deny buttons land in the configured channel.

## modes

Two control planes. Pick at `gateway init` time (default WireGuard).

**wireguard** (default) — gateway runs an embedded userspace WG endpoint. Operator only opens one UDP port. No daemon, no `wg-quick`, no kernel module on the gateway. Devices `clawpatrol join --url <gw>` and get a per-machine WG conf.

**tailscale** — gateway joins your tailnet as an exit-node. Devices already on the tailnet `clawpatrol login` and pin `clawpatrol` as their exit-node. Useful when you already run Tailscale + want the existing ACL/whois plumbing to gate onboarding.

```hcl
tailscale {
  control = "tailscale"   # or "wireguard"
  # tailscale-only:
  oauth_client_id     = "{{secret:TS_OAUTH_CLIENT_ID}}"
  oauth_client_secret = "{{secret:TS_OAUTH_CLIENT_SECRET}}"
  tags                = ["tag:client"]
  # wireguard-only:
  wg_endpoint    = "gw.example.com:51820"
  wg_subnet_cidr = "10.55.0.0/24"
}
```
