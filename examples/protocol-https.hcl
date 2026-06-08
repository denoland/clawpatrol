# User-visible messages sent from the agent are scanned by an LLM
# judge before they go out: catches unsafe content, missing context,
# and markdown that should not ship.

rule "message-send-content-check" {
  endpoint = https.messaging-api
  condition = <<-CEL
    http.method == 'POST'
    && http.path == '/v1/messages/send'
  CEL
  approve = [llm_approver.message-content-judge]
}

# ===== harness =====

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "messaging-api" {
  hosts = ["api.example.test"]
}

credential "anthropic_manual_key" "anthropic-key" {}
credential "bearer_token" "messaging-api" { endpoint = https.messaging-api }

approver "llm_approver" "message-content-judge" {
  model      = "claude-sonnet-4-6"
  credential = anthropic_manual_key.anthropic-key
  policy     = <<-EOT
    The JSON body has a body field containing a user-visible
    message. Deny if it contains markdown formatting, missing
    required context, or unsafe content.
  EOT
}

profile "default" { credentials = [bearer_token.messaging-api] }
