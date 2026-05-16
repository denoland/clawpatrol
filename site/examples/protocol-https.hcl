# Customer-support replies sent from the agent are scanned by an LLM
# judge before they go out: catches offensive content, missing
# salutations, and markdown that shouldn't ship.
rule "support-reply-on-behalf" {
  endpoint = deno-deploy
  condition = <<-CEL
    http.method == 'POST'
    && http.path == '/api/admin.supportTickets.replyOnBehalf'
  CEL
  approve = [reply-content-judge]
}

# ===== harness =====

admin_email = "ops@example.com"

policy "reply-content" {
  text = <<-EOT
    The JSON body has a body field containing a customer support
    reply. Deny if it contains markdown formatting, missing
    salutations, or offensive content.
  EOT
}

credential "anthropic_manual_key" "anthropic-key" {}
credential "bearer_token" "deno-deploy-cred" {}

approver "llm_approver" "reply-content-judge" {
  model      = "claude-sonnet-4-6"
  credential = anthropic-key
  policy     = reply-content
}

endpoint "https" "deno-deploy" {
  hosts      = ["app.deno.com"]
  credential = deno-deploy-cred
}

profile "default" { endpoints = [deno-deploy] }
