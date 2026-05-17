listen     = "0.0.0.0:8443"
state_dir  = "/opt/clawpatrol"

unknown_host  = "passthrough"
llm_fail_mode = "closed"

env_pushdown {
  OPENAI_API_KEY    = { secret = "openai_key", description = "OpenAI SDKs" }
  AWS_ACCESS_KEY_ID = { secret = "aws_access" }
  AWS_REGION        = { value  = "us-east-1" }
}

credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com", "github.com"]
  credential = github-pat
}

rule "github-reads" {
  endpoint  = github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

profile "default" {
  endpoints = [github]
}
