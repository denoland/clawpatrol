# Pre-flatten config form: `defaults {}` was a block, now its fields
# are top-level attrs. The loader should reject this rather than
# silently drop the block.

listen = "0.0.0.0:8443"
ca_dir = "/opt/clawpatrol/ca"

defaults {
  unknown_host  = "passthrough"
  llm_fail_mode = "closed"
}
