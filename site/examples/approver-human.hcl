approver "human_approver" "ops" {
  channel    = "#agent-ops"
  credential = slack-bot
  timeout    = 600
}

# ===== harness =====

admin_email = "ops@example.com"

credential "slack_tokens" "slack-bot" {}
credential "bearer_token" "noop" {}

endpoint "https" "anchor" {
  hosts      = ["example.com"]
  credential = noop
}

profile "default" { endpoints = [anchor] }
