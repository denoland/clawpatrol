credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

# fire_and_forget on a catch-all (no condition) is rejected — auto-
# allowing every request to an endpoint defeats the gateway.
rule "github-firehose" {
  endpoint        = github
  verdict         = "allow"
  fire_and_forget = true
}

profile "default" {
  endpoints = [github]
}
