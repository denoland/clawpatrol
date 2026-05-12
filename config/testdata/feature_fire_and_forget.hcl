credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

approver "human_approver" "ops" {
  channel = "#ops"
}

# Low-risk reads: auto-allow without waiting on a human. The rule still
# carries an `approve` chain so the dashboard's audit lane records who
# *would* have been asked.
rule "github-reads-fast" {
  endpoint        = github
  condition       = "http.method in ['GET', 'HEAD']"
  approve         = [ops]
  fire_and_forget = true
  reason          = "read-only, low-risk"
}

# Plain allow + fire_and_forget — no approver chain at all. Useful for
# whitelisted ops where the operator wants the auto-allow audit lane
# but never needed human review.
rule "github-status" {
  endpoint        = github
  condition       = "http.path.startsWith('/status')"
  verdict         = "allow"
  fire_and_forget = true
}

profile "default" {
  endpoints = [github]
}
