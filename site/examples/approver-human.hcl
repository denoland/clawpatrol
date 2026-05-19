approver "human_approver" "ops" {
  channel    = "#agent-ops"
  credential = slack_tokens.slack-bot
  timeout    = 600
}

# ===== harness =====

admin_email = "ops@example.com"

credential "slack_tokens" "slack-bot" {}
credential "bearer_token" "noop" {}

endpoint "https" "anchor" {
  hosts      = ["example.com"]
  credential = bearer_token.noop
}

profile "default" { endpoints = [https.anchor] }
