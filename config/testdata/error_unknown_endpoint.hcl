credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

# References an undeclared endpoint name.
rule "broken" {
  endpoint  = mystery
  condition = "http.method == 'GET'"
  verdict   = "allow"
}

profile "default" {
  endpoints = [github]
}
