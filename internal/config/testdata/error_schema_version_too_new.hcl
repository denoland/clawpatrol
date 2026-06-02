# schema_version higher than this binary supports. Loading must fail
# with a single "upgrade clawpatrol" error — NOT the wall of
# "Unsupported argument" diagnostics the strict decode would emit for
# the (hypothetical) newer-grammar syntax below. The lenient version
# pre-pass reads the version and short-circuits before the decode.
schema_version = 999

gateway {
  state_dir = "/opt/clawpatrol"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }

  # Pretend this is a future-grammar attribute the current binary
  # doesn't know. It must not surface as a decode error, because the
  # version gate fires first.
  some_future_attr = "from a newer grammar"
}
