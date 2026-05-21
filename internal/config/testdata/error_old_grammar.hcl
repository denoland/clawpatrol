gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

# Old (pre-inversion) grammar: endpoint carries `credential = X` and
# profile carries `endpoints = [...]`. Under the inverted grammar
# the credential→endpoint binding lives on the credential, profiles
# list credentials, and endpoints are bare network targets. Loading
# the old shape must fail rather than silently succeed.

credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = bearer_token.pat
}

profile "default" {
  endpoints = [https.github]
}
