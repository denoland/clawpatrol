rule "github-no-repo-delete" {
  endpoint  = github-api
  condition = "http.method == 'DELETE' && http.path.startsWith('/repos/')"
  verdict   = "deny"
  reason    = "deleting repos is not allowed"
}

# ===== harness =====

admin_email = "ops@example.com"

credential "bearer_token" "github-pat" {}

endpoint "https" "github-api" {
  hosts      = ["api.github.com"]
  credential = github-pat
}

profile "default" { endpoints = [github-api] }
