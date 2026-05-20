endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "pat" {
  endpoint = https.github
}

# References an undeclared endpoint name.
rule "broken" {
  endpoint  = mystery
  condition = "http.method == 'GET'"
  verdict   = "allow"
}

profile "default" {
  credentials = [bearer_token.pat]
}
