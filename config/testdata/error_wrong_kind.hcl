credential "bearer_token" "shared-creds" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = shared-creds
}

# `endpoint = shared-creds` references the credential, not the
# endpoint. The diagnostic should disambiguate by pointing at the
# credential's declaration site.
rule "http_rule" "broken" {
  endpoint = shared-creds
  match    = { method = "GET" }
  verdict  = "allow"
}

profile "default" {
  endpoints = [github]
}
