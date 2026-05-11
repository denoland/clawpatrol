# control accepts "wireguard" or "tailscale" (or omitted). Typos
# like "kubernetes" used to silently pass — the gateway would boot
# in a degraded fallback mode.

listen = "0.0.0.0:8443"
ca_dir = "/opt/clawpatrol/ca"

control = "kubernetes"
