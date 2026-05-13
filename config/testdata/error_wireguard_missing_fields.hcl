# control = "wireguard" requires wg_subnet_cidr, plus a client dial
# target (either public_url or wg_endpoint with a non-wildcard host).
# Without them StartWGServer fails at boot (subnet) or onboarding
# clients dial an unknown endpoint.

listen = "0.0.0.0:8443"

control = "wireguard"
