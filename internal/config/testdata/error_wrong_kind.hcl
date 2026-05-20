endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "shared" {
  endpoint = https.github
}

# `endpoint = shared` references the credential, not the
# endpoint. The diagnostic should disambiguate by pointing at the
# credential's declaration site.
rule "broken" {
  endpoint  = bearer_token.shared
  condition = "http.method == 'GET'"
  verdict   = "allow"
}

profile "default" {
  credentials = [bearer_token.shared]
}
