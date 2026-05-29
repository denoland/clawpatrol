# Block destructive SQL on prod
rule "no-prod-drops" {
  endpoint  = postgres.pg-prod
  condition = "sql.verb in ['drop', 'truncate', 'alter']"
  verdict   = "deny"
}

# Slack-approve any GitHub write
rule "github-writes" {
  endpoint  = http.github-api
  condition = "http.method in ['POST', 'PUT', 'DELETE']"
  approve   = [human_approver.ops]
}

# ===== harness =====

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "postgres" "pg-prod" {
  host = "pg-prod.example:5432"
}

endpoint "http" "github-api" {
  hosts = ["api.github.com"]
}

credential "postgres_credential" "pg" {
  endpoint = postgres.pg-prod
  user     = "agent"
}
credential "bearer_token" "github-pat" { endpoint = http.github-api }
credential "slack_tokens" "slack-bot" {}

approver "human_approver" "ops" {
  channel    = "#agent-ops"
  credential = slack_tokens.slack-bot
}

profile "default" { credentials = [postgres_credential.pg, bearer_token.github-pat] }
