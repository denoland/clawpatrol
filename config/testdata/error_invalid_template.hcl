credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

approver "human_approver" "ops" {
  channel = "#ops"
}

# Template must evaluate to a string. A bool expression must be
# rejected at policy load with a clear diagnostic.
rule "github-writes" {
  endpoint = github
  approve  = [ops]
  template = "http.method == 'POST'"
}

profile "default" {
  endpoints = [github]
}
