#!/bin/sh
# Tiny TCP banner service used by 03-vip-passthrough.sh. The gateway
# resolves ssh.example.test through Docker DNS and should bridge the
# agent's VIP connection here when the profile excludes the SSH endpoint.

set -eu

handler=/tmp/clawpatrol-ssh-stub-handler.sh
cat >"$handler" <<'EOF'
#!/bin/sh
printf 'SSH-2.0-clawpatrol-e2e\r\n'
sleep 1
EOF
chmod +x "$handler"

exec socat TCP-LISTEN:22,reuseaddr,fork EXEC:"$handler"
