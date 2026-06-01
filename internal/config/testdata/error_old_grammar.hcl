gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

# Old (pre-inversion) grammar: endpoint carries `credential = X`.
# The credential→endpoint binding lives on the credential, so loading
# the old endpoint-side credential shape must fail rather than
# silently succeed. `profile.endpoints` is valid for direct rule-only
# endpoint membership, but it does not grant credentials.

credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = bearer_token.pat
}

profile "default" {
  endpoints = [https.github]
}
