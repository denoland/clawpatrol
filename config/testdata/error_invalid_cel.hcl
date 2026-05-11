credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

# Syntactically invalid CEL — unbalanced quote.
# The compile step must surface the parse error.
rule "broken" {
  endpoint  = github
  condition = "http.method == 'GET"
  verdict   = "allow"
}

profile "default" {
  endpoints = [github]
}
