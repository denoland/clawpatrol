# control = "local": same-host agent and gateway, listeners bound to
# loopback only. ::1 + dashboard secret keep the config valid.

listen           = "127.0.0.1:8443"
info_listen      = "[::1]:8080"
state_dir        = "/var/lib/clawpatrol"
dashboard_secret = "x"

control = "local"

credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = github-pat
}

profile "default" {
  endpoints = [github]
}
