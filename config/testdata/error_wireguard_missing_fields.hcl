# control = "wireguard" requires wg_subnet_cidr and wg_endpoint.
# Without them StartWGServer log.Fatals at boot (subnet) or onboarding
# clients dial an unknown endpoint.

listen = "0.0.0.0:8443"
ca_dir = "/opt/clawpatrol/ca"

control = "wireguard"
