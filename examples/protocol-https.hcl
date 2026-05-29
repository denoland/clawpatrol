# Customer-support replies sent from the agent are scanned by an LLM
# judge before they go out: catches offensive content, missing
# salutations, and markdown that shouldn't ship.

rule "support-reply-on-behalf" {
  endpoint = http.deno-deploy
  condition = <<-CEL
    http.method == 'POST'
    && http.path == '/api/admin.supportTickets.replyOnBehalf'
  CEL
  approve = [llm_approver.reply-content-judge]
}

# ===== harness =====

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "http" "deno-deploy" {
  hosts = ["app.example.com"]
}

credential "anthropic_manual_key" "anthropic-key" {}
credential "bearer_token" "deno-deploy" { endpoint = http.deno-deploy }

approver "llm_approver" "reply-content-judge" {
  model      = "claude-sonnet-4-6"
  credential = anthropic_manual_key.anthropic-key
  policy     = <<-EOT
    The JSON body has a body field containing a customer support
    reply. Deny if it contains markdown formatting, missing
    salutations, or offensive content.
  EOT
}

profile "default" { credentials = [bearer_token.deno-deploy] }
