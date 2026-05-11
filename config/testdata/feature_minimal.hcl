listen     = "0.0.0.0:8443"
ca_dir     = "/opt/clawpatrol/ca"

defaults {
  unknown_host  = "passthrough"
  llm_fail_mode = "closed"
}

credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com", "github.com"]
  credential = github-pat
}

approver "human_approver" "ops" {
  channel = "#agent-ops"
  timeout = 600
}

rule "http_rule" "github-reads" {
  endpoint  = github
  condition = "method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "http_rule" "github-writes" {
  endpoint  = github
  condition = "method in ['POST', 'PATCH', 'DELETE']"
  approve   = [ops]
}

profile "default" {
  endpoints = [github]
}
