# Block destructive SQL on prod
rule "no-prod-drops" {
  endpoint  = postgres.prod
  condition = "sql.verb in ['drop', 'truncate', 'alter']"
  verdict   = "deny"
}

# Slack-approve any GitHub write
rule "github-writes" {
  endpoint  = https.github
  condition = "http.method in ['POST', 'PUT', 'DELETE']"
  approve   = [human_approver.ops]
}

# ===== harness =====

admin_email = "ops@example.com"

endpoint "postgres" "prod" {
  host = "pg-prod.example:5432"
}

endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "postgres_credential" "pg" {
  endpoint = postgres.prod
  user     = "agent"
}
credential "bearer_token" "github-pat" { endpoint = https.github }
credential "slack_tokens" "bot" {}

approver "human_approver" "ops" {
  channel    = "#agent-ops"
  credential = slack_tokens.bot
}

profile "default" { credentials = [postgres_credential.pg, bearer_token.github-pat] }
