credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = github-pat
}

approver "human_approver" "ops" {
  channel = "#ops"
}

# CEL template renders the approval message — same bindings as the
# matcher; output must be a string.
rule "github-writes" {
  endpoint = github
  approve  = [ops]
  template = "'agent wants ' + http.method + ' ' + http.path"
}

profile "default" {
  endpoints = [github]
}
