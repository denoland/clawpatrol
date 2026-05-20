listen     = "0.0.0.0:8443"

unknown_host  = "passthrough"
llm_fail_mode = "closed"

credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com", "github.com"]
  credential = bearer_token.github-pat
}

approver "human_approver" "ops" {
  channel = "#agent-ops"
  timeout = 600
}

rule "github-reads" {
  endpoint  = https.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = https.github
  condition = "http.method in ['POST', 'PATCH', 'DELETE']"
  approve   = [human_approver.ops]
}

profile "default" {
  endpoints = [https.github]
}
