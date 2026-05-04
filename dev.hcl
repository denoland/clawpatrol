listen      = "0.0.0.0:8443"
info_listen = "0.0.0.0:8080"
public_url  = "http://localhost:8080"
admin_email = "dj.srivastava23@gmail.com"
ca_dir      = "/tmp/dev-ca"
oauth_dir   = "/tmp/dev-oauth"
insecure_no_dashboard_secret = true

gateway {
  control        = "wireguard"
  wg_endpoint    = "127.0.0.1:51820"
  wg_subnet_cidr = "10.55.0.0/24"
}

defaults { unknown_host = "passthrough" }
profile "default" { endpoints = [] }
