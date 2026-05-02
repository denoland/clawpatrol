credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

# A k8s_rule cannot target an https endpoint.
rule "k8s_rule" "wrong-family" {
  endpoint = github
  match    = { resource = "pods" }
  verdict  = "allow"
}

profile "default" {
  endpoints = [github]
}
