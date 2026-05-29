# Minimal policy used by the Docker e2e harness. Pinned to localhost
# binds so the gateway is reachable only from inside its container plus
# the agent on the shared compose network (`gateway:8080`).
#
# Shape mirrors examples/gateway.example.hcl but with the surface area
# trimmed to what the tests under test/docker/tests/*.sh assert against.

gateway {
  dashboard_listen = "0.0.0.0:8080"
  state_dir        = "/var/lib/clawpatrol"

  wireguard {
    listen_port = 51820
    subnet_cidr = "10.55.0.0/24"
    # Agent dials the gateway by its compose service name. Validator
    # rejects a config without either public_url or wireguard.endpoint
    # because clients need somewhere to dial; pin it explicitly here
    # since the harness's gateway runs without a public_url.
    endpoint = "gateway:51820"
  }
}

# One MITM-able HTTPS endpoint so 01-https-mitm.sh has somewhere to dial.
endpoint "https" "echo" {
  hosts = ["echo.example.test"]
}

# One SSH endpoint declared at the policy root so 03-vip-passthrough.sh
# exercises the orchid#184 fix: VIP is allocated for the host, but the
# `e2e` profile below excludes the endpoint, which used to silently RST
# every TCP connection to the VIP on port 22.
endpoint "ssh" "ssh-stub" {
  hosts = ["ssh.example.test:22"]
}

credential "bearer_token" "echo-pat" {
  endpoint = https.echo
}

profile "e2e" {
  # Deliberately omits ssh-stub: that's the policy condition that
  # 03-vip-passthrough.sh asserts the gateway no longer drops.
  credentials = [bearer_token.echo-pat]
}
