# clawpatrol — WireGuard mode

WireGuard as the primary control plane. No Tailscale account, no
kernel module, no `wg-quick` lifecycle on the gateway, no systemd
unit for the WG interface, no `/etc/hosts` pinning on clients. The
clawpatrol binary IS the WG endpoint and the L3 forwarder.

## How it works

The gateway runs an embedded **wireguard-go** + a **gVisor netstack**
in promiscuous mode — same shape as unclaw's `boringtun` + `smoltcp`
(`set_any_ip`) setup, just in Go.

1. wireguard-go decrypts UDP off the wire, hands inner packets to a
   custom `netTun` (`wgnet.go:newNetTUN`).
2. `netTun` injects into a gVisor stack built with **`HandleLocal:
   false`** (the upstream `tun/netstack.CreateNetTUN` hardcodes
   `HandleLocal: true`, which combined with promiscuous mode causes
   the IP layer to drop every packet as "InvalidSource"). NIC has
   `SetPromiscuousMode + SetSpoofing`, IP layer accepts ANY dst.
3. `tcp.NewForwarder` + `udp.NewForwarder` register as the stack's
   default transport handlers. Every TCP/UDP session to ANY dst IP
   reaches `EnablePromiscuousForwarder`'s callback.
4. Callback dispatches by port:
   - `:443` → `g.handle` (SNI peek → MITM or splice)
   - `:<info_listen>` → dashboard mux
   - else → `wgRelay` / `relayUDP` to real upstream
5. Clients route `0.0.0.0/0` through the tunnel. Agents resolve real
   hostnames via public DNS (UDP/53 forwarded by the gateway), open
   real public IPs, gateway intercepts at L3.

## What works (verified end-to-end on vultr)

- `clawpatrol gateway -config gateway.hcl` boots WG endpoint on
  UDP 51820, dashboard + MITM ride the same forwarder.
- Server keypair persisted at `<oauth_dir>/wg-server.key`. Pubkey
  derived via curve25519 at boot. Peer (pubkey → IP) map persisted
  at `<oauth_dir>/wg-peers.json`, replayed on every restart so
  existing clients survive gateway redeploys.
- `clawpatrol join --url <gw>` runs once: prints user-code, opens
  dashboard URL, server mints a fresh keypair, allocates a /32 from
  the configured subnet, registers the peer with wireguard-go,
  hands back a `wg-quick` conf. Server **auto-claims** the peer
  IP for the approver at mint time — no client-side claim
  round-trip (which used to race against the new default route).
- `wg-quick up` writes `/etc/wireguard/clawpatrol.conf` and brings the
  tunnel up. PostUp swaps `/etc/resolv.conf` to `1.1.1.1` (no
  `resolvconf` dependency — backed up + restored on PostDown).
  Default route via wg, fwmark 51820 keeps WG handshakes themselves
  off the tunnel. SSH stays alive (fwmark 51820 + ip rule trick).
- Agents (`claude`, `gh`, `codex`) run unmodified. `eval "$(clawpatrol
  env)"` exports placeholder tokens + CA bundle. Outbound HTTPS to
  `api.anthropic.com` resolves to a real public IP, routes through
  WG to the gateway, TCP forwarder catches the SYN, port-443
  dispatch fires `g.handle`, SNI matches, MITM injects real OAuth,
  forwards to real upstream, response returns through the tunnel.

## vs Tailscale mode

- Dashboard auth in WG mode falls back to `admin_email` for every
  approval. Multi-user setups need an auth proxy
  (Cloudflare Access, basic auth, etc.) that fills
  `X-Forwarded-User` / `X-Forwarded-Email` (~10 LoC to teach
  `ownerForCaller` to read those).
- Both endpoints behind the same NAT egress IP can't establish a
  WG handshake (UDP hairpin drop). Same constraint as plain unclaw
  remote mode. Use a real public-IP VPS for the gateway.

## Operator setup

```bash
# on the gateway VM (real public IP needed)
curl -fsSL https://denoland.github.io/clawpatrol/install.sh | sh

cat > /etc/clawpatrol/gateway.hcl <<'EOF'
listen       = "0.0.0.0:8443"
info_listen  = "0.0.0.0:8080"
public_url   = "http://your-gw.example.com:8080"
admin_email  = "you@example.com"
ca_dir       = "/opt/clawpatrol/ca"
log_path     = "/opt/clawpatrol/gateway.log"
oauth_dir    = "/opt/clawpatrol/oauth"
integrations = ["claude", "codex", "github"]

tailscale {
  control        = "wireguard"
  wg_endpoint    = "your-gw.example.com:51820"
  wg_subnet_cidr = "10.55.0.0/24"
}
EOF

mkdir -p /opt/clawpatrol
clawpatrol init-ca /opt/clawpatrol/ca

iptables -I INPUT -p udp --dport 51820 -j ACCEPT
iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
clawpatrol gateway -config /etc/clawpatrol/gateway.hcl
```

Connect Claude / GitHub / Codex via the dashboard at
`http://your-gw.example.com:8080`. Per-user OAuth credentials land
in `/opt/clawpatrol/oauth/`.

## Client setup

```bash
curl -fsSL https://denoland.github.io/clawpatrol/install.sh | sh
clawpatrol join --url http://your-gw.example.com:8080
# approve at the displayed URL, done — claude/gh/codex just work
```
