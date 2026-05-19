listen     = "0.0.0.0:8443"

unknown_host  = "passthrough"
llm_fail_mode = "closed"

credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com", "github.com"]
  credential = github-pat
}

approver "human_approver" "ops" {
  channel = "#agent-ops"
  timeout = 600
}

rule "github-reads" {
  endpoint  = github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = github
  condition = "http.method in ['POST', 'PATCH', 'DELETE']"
  approve   = [ops]
}

profile "default" {
  endpoints = [github]
}
