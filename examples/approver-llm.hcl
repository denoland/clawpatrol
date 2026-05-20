approver "llm_approver" "secret-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic_manual_key.anthropic-key
  policy     = "Reject any SELECT that projects secret-bearing columns."
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

credential "anthropic_manual_key" "anthropic-key" {}
credential "bearer_token" "noop" { endpoint = http.anchor }

profile "default" { credentials = [bearer_token.noop] }
