# control = "local" requires both listen and info_listen to bind only
# to a loopback interface. A bare ":port" or 0.0.0.0 reaches the LAN
# and defeats the local-mode security model (doc: "Local mode").

listen           = "0.0.0.0:8443"
info_listen      = "192.168.1.10:8080"
state_dir        = "/var/lib/clawpatrol"
dashboard_secret = "x"

control = "local"
