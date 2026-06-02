gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

# Old (pre-inversion) grammar: endpoint carries `credential = X`.
# Under the inverted grammar the credential→endpoint binding lives on
# the credential, and profiles list credentials. Loading the old shape
# must fail rather than silently succeed. `credentials` is still a
# required profile argument, so omitting it is an error too.
#
# (A profile MAY now also carry an `endpoints = [...]` list to claim
# credential-less endpoints directly — that grammar is valid and is
# covered by compile_test.go, so it is intentionally absent here.)

credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = bearer_token.pat
}

profile "default" {
}
