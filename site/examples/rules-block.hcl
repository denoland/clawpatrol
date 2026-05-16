# Block destructive SQL on prod
rule "no-prod-drops" {
  endpoint  = pg-prod
  condition = "sql.verb in ['drop', 'truncate', 'alter']"
  verdict   = "deny"
}

# Slack-approve any GitHub write
rule "github-writes" {
  endpoint  = github-api
  condition = "http.method in ['POST', 'PUT', 'DELETE']"
  approve   = [ops]
}

# Hand sensitive reads to an LLM judge
approver "llm_approver" "secret-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic-key
  policy     = secret-policy
}

# ===== harness =====

admin_email = "ops@example.com"

policy "secret-policy" {
  text = "Reject any SELECT that projects secret-bearing columns."
}

credential "anthropic_manual_key" "anthropic-key" {}
credential "postgres_credential"  "pg-cred"      { user = "agent" }
credential "bearer_token"         "github-pat"   {}
credential "slack_tokens"         "slack-bot"    {}

endpoint "postgres" "pg-prod" {
  host       = "pg-prod.example:5432"
  credential = pg-cred
}

endpoint "https" "github-api" {
  hosts      = ["api.github.com"]
  credential = github-pat
}

approver "human_approver" "ops" {
  channel    = "#agent-ops"
  credential = slack-bot
}

profile "default" { endpoints = [pg-prod, github-api] }
