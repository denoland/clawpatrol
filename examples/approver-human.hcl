approver "human_approver" "ops" {
  channel    = "#agent-ops"
  credential = slack_tokens.slack-bot
  timeout    = 600
}

# ===== harness =====

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "http" "anchor" {
  hosts = ["example.com"]
}

credential "slack_tokens" "slack-bot" {}
credential "bearer_token" "noop" { endpoint = http.anchor }

profile "default" { credentials = [bearer_token.noop] }
