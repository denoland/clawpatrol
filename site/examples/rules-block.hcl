# Block destructive SQL on prod
rule "no-prod-drops" {
  endpoint  = postgres.pg-prod
  condition = "sql.verb in ['drop', 'truncate', 'alter']"
  verdict   = "deny"
}

# Slack-approve any GitHub write
rule "github-writes" {
  endpoint  = https.github-api
  condition = "http.method in ['POST', 'PUT', 'DELETE']"
  approve   = [human_approver.ops]
}

# ===== harness =====

admin_email = "ops@example.com"

credential "postgres_credential" "pg-cred"    { user = "agent" }
credential "bearer_token"        "github-pat" {}
credential "slack_tokens"        "slack-bot"  {}

endpoint "postgres" "pg-prod" {
  host       = "pg-prod.example:5432"
  credential = postgres_credential.pg-cred
}

endpoint "https" "github-api" {
  hosts      = ["api.github.com"]
  credential = bearer_token.github-pat
}

approver "human_approver" "ops" {
  channel    = "#agent-ops"
  credential = slack_tokens.slack-bot
}

profile "default" { endpoints = [postgres.pg-prod, https.github-api] }
