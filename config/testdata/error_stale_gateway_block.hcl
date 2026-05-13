# Pre-flatten config form: `gateway {}` was a block, now its fields
# are top-level attrs. The loader should reject this rather than
# silently drop the block.

listen = "0.0.0.0:8443"

gateway {
  control     = "wireguard"
  wg_endpoint = "10.0.0.1:51820"
}
