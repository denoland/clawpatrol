# The `wireguard {}` block requires subnet_cidr, plus a client dial
# target (either gateway.public_url or wireguard.endpoint with a
# non-wildcard host). Without them StartWGServer fails at boot
# (subnet) or onboarding clients dial an unknown endpoint.

gateway {
  state_dir = "/opt/clawpatrol"

  wireguard {}
}
