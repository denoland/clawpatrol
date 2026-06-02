# At least one of `wireguard {}` or `tailscale {}` must be declared
# inside the `gateway {}` block. Block presence selects which
# transports the gateway exposes; an empty gateway block leaves no
# way for clients to connect.

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
}
