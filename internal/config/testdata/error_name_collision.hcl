gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

credential "bearer_token" "shared" {}

# Same kind and name — forbidden.
credential "header_token" "shared" {}
