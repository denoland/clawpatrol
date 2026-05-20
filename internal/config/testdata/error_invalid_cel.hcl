endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "pat" {
  endpoint = https.github
}

# Syntactically invalid CEL — unbalanced quote.
# The compile step must surface the parse error.
rule "broken" {
  endpoint  = https.github
  condition = "http.method == 'GET"
  verdict   = "allow"
}

profile "default" {
  credentials = [bearer_token.pat]
}
