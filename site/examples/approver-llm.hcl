approver "llm_approver" "secret-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic_manual_key.anthropic-key
  policy     = policy.secret-policy
}

policy "secret-policy" {
  text = "Reject any SELECT that projects secret-bearing columns."
}

# ===== harness =====

admin_email = "ops@example.com"

endpoint "https" "anchor" {
  hosts = ["example.com"]
}

credential "anthropic_manual_key" "anthropic-key" {}
credential "bearer_token" "noop" { endpoint = https.anchor }

profile "default" { credentials = [bearer_token.noop] }
