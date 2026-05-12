listen     = "0.0.0.0:8443"
ca_dir     = "/opt/clawpatrol/ca"

unknown_host  = "passthrough"
llm_fail_mode = "closed"

credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = github-pat
}

approver "human_approver" "ops" {
  channel = "#agent-ops"
  timeout = 600
}

# Bare key sugar — same as method_any.
rule "reads" {
  endpoint = github
  match    = { method = ["GET", "HEAD"] }
  verdict  = "allow"
}

# Compound predicate: positive list + negation on the same key, AND
# a glob on a separate unary blob.
rule "writes" {
  endpoint = github
  match = {
    method_any  = ["POST", "PUT", "PATCH", "DELETE"]
    method_none = ["TRACE"]
    path_none   = ["/admin/*"]
  }
  approve = [ops]
}

profile "default" {
  endpoints = [github]
}
