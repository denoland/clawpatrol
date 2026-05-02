credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

# References an undeclared endpoint name.
rule "http_rule" "broken" {
  endpoint = mystery
  match    = { method = "GET" }
  verdict  = "allow"
}

profile "default" {
  endpoints = [github]
}
