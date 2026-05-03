credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

# Typo'd match key — should be "method", not "methood".
# Without the per-family known-keys check this rule would silently
# never fire.
rule "http_rule" "typo" {
  endpoint = github
  match    = { methood = "GET" }
  verdict  = "allow"
}

profile "default" {
  endpoints = [github]
}
