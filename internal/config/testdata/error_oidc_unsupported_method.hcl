gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.com"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

enrollment "saml" "ci" {
  profile = "ci"
}
