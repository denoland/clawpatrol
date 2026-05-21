# tailscale.operators entries must be "user@domain" or "*@domain".
# A bare username or a misshapen wildcard ("foo*@bar") would either
# silently fail to match the intended whois login or match too
# broadly, so the loader refuses it instead of warning.

gateway {
  dashboard_listen = "127.0.0.1:8080"
  state_dir        = "/opt/clawpatrol"
  public_url       = "https://gw.example.test"

  tailscale {
    authkey   = "tskey-test"
    operators = ["bert"]
  }
}
