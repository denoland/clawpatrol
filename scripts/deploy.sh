#!/usr/bin/env bash
# Rerunnable deploy: builds linux gateway, ships to TARGET, sets up Tailscale
# exit node + nftables REDIRECT + systemd service. Idempotent.
#
# Order matters: kernel netfilter modules must be present before tailscaled
# starts, otherwise tailscaled bails on iptables init.
#
# Usage:
#   TS_AUTHKEY=tskey-auth-...  ./scripts/deploy.sh
#   TARGET=user@host PORT=8443 ./scripts/deploy.sh

set -euo pipefail

if [[ -f "$(dirname "$0")/../.env" ]]; then
  set -a; source "$(dirname "$0")/../.env"; set +a
fi

TARGET="${TARGET:-bot0-linux@vm.littledivy.com}"
PORT="${PORT:-8443}"
REMOTE_DIR="${REMOTE_DIR:-/opt/clawpatrol}"
HOSTNAME_TAG="${HOSTNAME_TAG:-clawpatrol}"

cd "$(dirname "$0")/.."
mkdir -p dist

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
SSH_OPTS=(-o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o ConnectTimeout=10)
remote() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }

# scp (legacy proto -O for visible progress) + atomic rename. Skips if
# remote sha256 matches local. Atomic rename avoids "Text file busy"
# when overwriting a running binary.
SCP=(scp -O -C "${SSH_OPTS[@]}")

ship_if_changed() {
  local src="$1" dst="$2"
  local lsha rsha
  lsha=$(shasum -a 256 "$src" | awk '{print $1}')
  rsha=$(remote "shasum -a 256 ${dst} 2>/dev/null | awk '{print \$1}'" 2>/dev/null || echo "")
  if [[ "$lsha" == "$rsha" ]]; then
    printf '  -- skip %s (sha match)\n' "$dst"
    return
  fi
  "${SCP[@]}" "$src" "$TARGET:${dst}.new"
  remote "mv ${dst}.new ${dst}"
}

# --- 0. build dashboard (TSX → www/dist) ---------------------------------
if [[ -d www && -f www/package.json ]]; then
  say "build dashboard (vite)"
  if [[ ! -d www/node_modules ]]; then
    (cd www && npm install --silent)
  fi
  (cd www && npm run build --silent)
fi

# --- 1. local build -------------------------------------------------------
say "build linux/amd64 (stripped)"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o dist/gateway-linux-amd64 .
ls -lh dist/gateway-linux-amd64 | awk '{print "  -- size:",$5}'

# --- 2. ensure CA ---------------------------------------------------------
if [[ ! -f ca/ca.crt ]]; then
  say "init local CA"
  go run . -init-ca ./ca
fi

# --- 3. render config + scripts ------------------------------------------
# Default PUBLIC_URL prefers the funnel hostname (https://<host>.<tailnet>.ts.net).
# Fall back to the raw IP only if funnel isn't enabled. We learn the
# tailnet hostname after `tailscale up` so this is computed lazily on
# the remote side later — set a placeholder here.
PUBLIC_URL="${PUBLIC_URL:-https://${HOSTNAME_TAG}.tailnet.ts.net}"

# Pick control-plane: tailscale (default, SaaS) or wireguard (self-host).
# Configurable via env for CI; falls back to a TTY prompt otherwise.
CONTROL="${CONTROL:-}"
if [[ -z "$CONTROL" && -t 0 ]]; then
  printf 'control plane (tailscale | wireguard) [tailscale]: '
  read -r CONTROL
fi
CONTROL="${CONTROL:-tailscale}"

case "$CONTROL" in
  tailscale)
    TS_BLOCK=$(cat <<HCL
gateway {
  control             = "tailscale"
  oauth_client_id     = "{{secret:TS_OAUTH_CLIENT_ID}}"
  oauth_client_secret = "{{secret:TS_OAUTH_CLIENT_SECRET}}"
  tags                = ["tag:client"]
}
HCL
)
    ;;
  wireguard)
    # Embedded userspace WG: gateway IS the WG endpoint, no kernel
    # module / wg-quick / /etc/wireguard / iptables MASQUERADE. Operator
    # only needs UDP port open on the host firewall.
    WG_PORT="${WG_PORT:-51820}"
    WG_SUBNET_CIDR="${WG_SUBNET_CIDR:-10.42.0.0/24}"
    WG_PUBLIC_HOST="${WG_PUBLIC_HOST:-$(echo "$TARGET" | awk -F@ '{print $2}')}"
    WG_ENDPOINT="${WG_PUBLIC_HOST}:${WG_PORT}"

    say "remote: opening udp/${WG_PORT} for embedded wireguard"
    remote "iptables -C INPUT -p udp --dport ${WG_PORT} -j ACCEPT 2>/dev/null \
            || iptables -I INPUT -p udp --dport ${WG_PORT} -j ACCEPT"

    TS_BLOCK=$(cat <<HCL
gateway {
  control        = "wireguard"
  wg_endpoint    = "${WG_ENDPOINT}"
  wg_subnet_cidr = "${WG_SUBNET_CIDR}"
}
HCL
)
    ;;
  *)
    echo "unknown control-plane: $CONTROL (tailscale|wireguard)" >&2
    exit 2
    ;;
esac

cat > dist/gateway.hcl <<EOF
listen       = "0.0.0.0:${PORT}"
info_listen  = "0.0.0.0:8080"
public_url   = "${PUBLIC_URL}"
ca_dir       = "${REMOTE_DIR}/ca"
oauth_dir    = "${REMOTE_DIR}/oauth"
integrations = ["claude", "codex", "github"]

${TS_BLOCK}
EOF

cat > dist/remote-modules.sh <<'EOSSH'
#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
KREL="$(uname -r)"
if lsmod | grep -q nf_tables; then
  echo "  -- nf_tables already loaded"
  exit 0
fi
echo "  -- installing kernel modules (${KREL}, ~150MB, slow first run)"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  linux-modules-${KREL} linux-modules-extra-${KREL} || true
modprobe nf_tables nf_nat nft_chain_nat nft_redir 2>/dev/null || true
modprobe nf_tables 2>/dev/null || { echo "  -- FATAL: nf_tables unavailable"; exit 3; }
echo "  -- modules loaded"
EOSSH

cat > dist/remote-nft.sh <<EOSSH
#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
if ! ip link show tailscale0 >/dev/null 2>&1; then
  echo "  -- ERROR: tailscale0 iface missing (tailscale not up yet)"
  exit 5
fi
echo "  -- redirect tailscale0:tcp/443 -> 127.0.0.1:${PORT}, drop tailscale0:udp/443 (no QUIC bypass)"
nft list table ip clawpatrol >/dev/null 2>&1 && nft delete table ip clawpatrol
nft -f - <<NFT
table ip clawpatrol {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iif "tailscale0" tcp dport 443 redirect to :${PORT}
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        iif "tailscale0" udp dport 443 drop
    }
}
NFT
# Open dashboard/onboard port (8080) on the public iface — needed for
# brand-new clients running \`clawpatrol join --url ...\` since they
# aren't on the tailnet yet. The tailnetGate middleware in web.go
# restricts non-tailnet callers to /api/onboard/* + /info anyway.
if ! iptables -C INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null; then
  iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
fi
echo "  -- nft active (8080 open for onboarding)"
EOSSH

cat > dist/remote-up.sh <<'EOSSH'
#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
if ! command -v tailscale >/dev/null 2>&1; then
  echo "  -- installing tailscale"
  curl -fsSL https://tailscale.com/install.sh | sh
else
  echo "  -- tailscale present: $(tailscale version | head -1)"
fi

# fresh start: previous failures may have left service in failed state
systemctl reset-failed tailscaled 2>/dev/null || true
systemctl enable --now tailscaled
for i in 1 2 3 4 5 6 7 8 9 10; do
  [[ -S /var/run/tailscale/tailscaled.sock ]] && break
  sleep 1
done

if ! systemctl is-active --quiet tailscaled; then
  echo "  -- tailscaled failed to start"
  journalctl -u tailscaled -n 20 --no-pager
  exit 4
fi

need_up=0
if ! tailscale status --self >/dev/null 2>&1; then need_up=1; fi
if ! tailscale status --json 2>/dev/null | grep -q '"AdvertiseRoutes":\[.*"0.0.0.0/0".*\]'; then need_up=1; fi
cur_host=$(tailscale status --json 2>/dev/null | grep -o '"HostName":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")
if [[ "${cur_host}" != "${HOSTNAME_TAG}" ]]; then
  echo "  -- hostname mismatch: current=${cur_host} want=${HOSTNAME_TAG}, re-up"
  need_up=1
fi

if [[ $need_up -eq 1 ]]; then
  if [[ -z "${TS_AUTHKEY:-}" ]]; then
    echo "  -- ERROR: tailscale not up + advertising exit node, and TS_AUTHKEY not provided"
    exit 2
  fi
  echo "  -- tailscale up --advertise-exit-node --hostname=${HOSTNAME_TAG}"
  tailscale up --authkey="${TS_AUTHKEY}" --advertise-exit-node --hostname="${HOSTNAME_TAG}" --accept-dns=false --reset
else
  echo "  -- tailscale already up + advertising exit node"
fi

echo "  -- enable ip forwarding"
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
echo "  -- tailnet IP: $(tailscale ip -4 | head -1)"

# Tailscale Funnel: expose port 8080 publicly via the tailnet's
# magic DNS hostname (https://<host>.<tailnet>.ts.net). Avoids
# distributing raw IPs in `clawpatrol join --url` commands. Requires
# `nodeAttrs: [funnel]` on this node in the tailnet ACL.
echo "  -- enabling tailscale funnel for :8080"
tailscale funnel reset 2>/dev/null || true
tailscale serve reset 2>/dev/null || true
tailscale funnel --bg 8080 2>&1 | sed 's/^/     /' || \
  echo "     (funnel not enabled — visit https://login.tailscale.com/admin/dns and turn on HTTPS + Funnel)"
EOSSH

cat > dist/clawpatrol-gateway.service <<EOF
[Unit]
Description=clawpatrol gateway
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${REMOTE_DIR}
EnvironmentFile=-${REMOTE_DIR}/secrets.env
ExecStart=${REMOTE_DIR}/gateway gateway -config ${REMOTE_DIR}/gateway.hcl
Restart=on-failure
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# --- 4. ship (skip identical via rsync checksum; temp-file-rename handles
#         the running-binary "Text file busy" trap automatically) --------
say "ship to ${TARGET}:${REMOTE_DIR}"
remote "mkdir -p ${REMOTE_DIR}/ca"
ship_if_changed dist/gateway-linux-amd64 "${REMOTE_DIR}/gateway"
remote "chmod +x ${REMOTE_DIR}/gateway"
ship_if_changed ca/ca.crt "${REMOTE_DIR}/ca/ca.crt"
ship_if_changed ca/ca.key "${REMOTE_DIR}/ca/ca.key"
ship_if_changed dist/gateway.hcl "${REMOTE_DIR}/gateway.hcl"
ship_if_changed dist/remote-modules.sh "${REMOTE_DIR}/remote-modules.sh"
ship_if_changed dist/remote-nft.sh "${REMOTE_DIR}/remote-nft.sh"
ship_if_changed dist/remote-up.sh "${REMOTE_DIR}/remote-up.sh"
ship_if_changed dist/clawpatrol-gateway.service /etc/systemd/system/clawpatrol-gateway.service
remote "chmod +x ${REMOTE_DIR}/remote-modules.sh ${REMOTE_DIR}/remote-nft.sh ${REMOTE_DIR}/remote-up.sh"

# --- 5. kernel modules (must precede tailscaled — it bails w/o iptables) -
say "remote: kernel modules"
remote "${REMOTE_DIR}/remote-modules.sh"

# --- 6. tailscale install + up (creates tailscale0 iface) ----------------
say "remote: tailscale install + up"
remote "TS_AUTHKEY='${TS_AUTHKEY:-}' HOSTNAME_TAG='${HOSTNAME_TAG}' ${REMOTE_DIR}/remote-up.sh"

# --- 7. nft REDIRECT rule (needs tailscale0 to exist) --------------------
say "remote: nftables redirect"
remote "${REMOTE_DIR}/remote-nft.sh"

# --- 8. systemd unit + start ---------------------------------------------
say "remote: systemd unit"
remote "
  set -e; exec 2>&1
  [[ -f ${REMOTE_DIR}/secrets.env ]] || touch ${REMOTE_DIR}/secrets.env
  chmod 600 ${REMOTE_DIR}/secrets.env
  systemctl daemon-reload
  systemctl enable clawpatrol-gateway.service >/dev/null
  systemctl restart clawpatrol-gateway.service
  sleep 1
  echo '  -- service:' \$(systemctl is-active clawpatrol-gateway.service)
"

# --- 8. report -----------------------------------------------------------
say "status"
remote '
  echo "  tailnet IP: $(tailscale ip -4 | head -1)"
  echo "  gateway:    $(systemctl is-active clawpatrol-gateway)"
  echo "  recent log:"
  journalctl -u clawpatrol-gateway -n 5 --no-pager | sed "s/^/    /"
'

say "done."
echo "  client mac:  tailscale set --exit-node=${HOSTNAME_TAG}"
echo "  trust CA:    sudo security add-trusted-cert -d -p ssl -k /Library/Keychains/System.keychain ca/ca.crt"
