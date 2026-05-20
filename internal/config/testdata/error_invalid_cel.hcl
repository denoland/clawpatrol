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

credential "bearer_token" "pat" {
  endpoint = http.github
}

# Syntactically invalid CEL — unbalanced quote.
# The compile step must surface the parse error.
rule "broken" {
  endpoint  = http.github
  condition = "http.method == 'GET"
  verdict   = "allow"
}

profile "default" {
  credentials = [bearer_token.pat]
}
