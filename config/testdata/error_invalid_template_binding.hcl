credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

approver "human_approver" "ops" {
  channel = "#ops"
}

# Template references an unknown CEL binding — must be rejected at
# policy load via the facet env's type checker.
rule "github-writes" {
  endpoint = github
  approve  = [ops]
  template = "'msg ' + http.no_such_field"
}

profile "default" {
  endpoints = [github]
}
