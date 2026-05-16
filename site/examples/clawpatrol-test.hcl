# A tiny policy that allows GitHub reads and denies writes.
# Paired with fixture JSON files, it's the input to `clawpatrol test`.

rule "github-reads" {
  endpoint  = github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = github
  condition = "http.method in ['POST', 'PATCH', 'PUT', 'DELETE']"
  verdict   = "deny"
  reason    = "writes go through PR review"
}

# ===== harness =====

admin_email = "you@example.com"

credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = github-pat
}

profile "default" { endpoints = [github] }
