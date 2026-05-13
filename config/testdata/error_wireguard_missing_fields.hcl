# control = "wireguard" requires a client dial target — either
# public_url, or wg_endpoint with a non-wildcard host. wg_subnet_cidr
# and wg_endpoint are otherwise optional (defaults 10.55.0.0/24 and
# 0.0.0.0:51820).

listen = "0.0.0.0:8443"

control = "wireguard"
