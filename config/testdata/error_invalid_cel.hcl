credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

# Syntactically invalid CEL — unbalanced quote.
# The compile step must surface the parse error.
rule "http_rule" "broken" {
  endpoint  = github
  condition = "method == 'GET"
  verdict   = "allow"
}

profile "default" {
  endpoints = [github]
}
