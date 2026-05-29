gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

endpoint "http" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "shared" {
  endpoint = http.github
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
