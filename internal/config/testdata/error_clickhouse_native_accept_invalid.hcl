gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

endpoint "clickhouse_native" "bad-accept-invalid" {
  hosts                      = ["ch.example.com"]
  accept_invalid_certificate = true
}

credential "clickhouse_credential" "ch" {
  endpoint = clickhouse_native.bad-accept-invalid
}
