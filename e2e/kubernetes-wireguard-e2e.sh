#!/usr/bin/env bash
# Kubernetes WireGuard enrollment e2e against a local kind cluster.
#
# Builds the workspace into a kind-loaded image, applies the e2e kustomize
# overlay (examples base + *-e2e isolation), and drives the full lifecycle:
# enroll -> handoff -> restricted-agent contract -> tunnel data path ->
# wg_peers enrollment row -> rx_bytes liveness -> deregister/reap ->
# peer revocation.
#
# The manifests are the source of truth (examples/kubernetes/kustomization +
# e2e/kubernetes-wireguard-e2e-overlay); this script only builds the image,
# applies the overlay, and asserts. It does not template YAML.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OVERLAY="${ROOT}/e2e/kubernetes-wireguard-e2e-overlay"
DOCKERFILE="${ROOT}/Dockerfile"

CLUSTER_NAME="${CLAWPATROL_E2E_CLUSTER:-kind}"
KUBE_CONTEXT="${CLAWPATROL_E2E_CONTEXT:-kind-${CLUSTER_NAME}}"
TIMEOUT="${CLAWPATROL_E2E_TIMEOUT:-180s}"
SKIP_BUILD="${CLAWPATROL_E2E_SKIP_BUILD:-0}"
KEEP_RESOURCES="${CLAWPATROL_E2E_KEEP_RESOURCES:-0}"
CHECK_LIVENESS="${CLAWPATROL_E2E_CHECK_LIVENESS:-1}"
CHECK_EXPIRY="${CLAWPATROL_E2E_CHECK_EXPIRY:-0}"
CHECK_ESCALATION="${CLAWPATROL_E2E_CHECK_ESCALATION:-1}"
GOARCH_OVERRIDE="${CLAWPATROL_E2E_GOARCH:-}"

# These are fixed by the overlay (images: transformer, namespaces, RBAC
# names, gateway.hcl). Keep them in sync with the overlay if you change it.
IMAGE="clawpatrol-kind-e2e:dev"
GATEWAY_NS="clawpatrol-e2e"
AGENTS_NS="agents-e2e"
CLUSTER_ROLE_NAME="clawpatrol-tokenreview-e2e"
E2E_POD="clawpatrol-agent-example"
E2E_HTTP="clawpatrol-e2e-http"

KUBECTL=(kubectl --context "${KUBE_CONTEXT}")
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/clawpatrol-k8s-e2e.XXXXXX")"

# PEER_TTL is read from the overlay config (in preflight, after the files
# are confirmed to exist) so the liveness/reap waits stay in sync with what
# the gateway actually enforces.
PEER_TTL="30s"

usage() {
  cat <<'USAGE'
Run the Kubernetes WireGuard enrollment e2e against a local kind cluster.

  ./e2e/kubernetes-wireguard-e2e.sh

Environment knobs:
  CLAWPATROL_E2E_CLUSTER         kind cluster name, default: kind
  CLAWPATROL_E2E_CONTEXT         kubectl context, default: kind-${cluster}
  CLAWPATROL_E2E_TIMEOUT         kubectl wait timeout, default: 180s
  CLAWPATROL_E2E_SKIP_BUILD      set 1 to skip go/docker build + kind load
  CLAWPATROL_E2E_KEEP_RESOURCES  set 1 to skip final namespace cleanup
  CLAWPATROL_E2E_CHECK_LIVENESS  set 0 to skip the rx_bytes liveness check
  CLAWPATROL_E2E_CHECK_EXPIRY    set 1 to test reap cleanup (force-delete sidecar)
  CLAWPATROL_E2E_CHECK_ESCALATION set 0 to skip the sidecar self-heal check
                                 (gateway → 0 → ICMP probe fails → sidecar fails
                                 closed and re-enrolls in process with a fresh
                                 key, no container restart)
  CLAWPATROL_E2E_GOARCH          override node arch for the Linux build

Image tag, namespaces, peer TTL, and RBAC names live in the overlay
(e2e/kubernetes-wireguard-e2e-overlay); edit there, not here.
USAGE
}

log() { printf '[e2e] %s\n' "$*"; }
fail() {
  printf '[e2e] error: %s\n' "$*" >&2
  exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"; }

seconds_from_duration() {
  case "$1" in
    *s) printf '%s\n' "${1%s}" ;;
    *m) printf '%s\n' "$(( ${1%m} * 60 ))" ;;
    *h) printf '%s\n' "$(( ${1%h} * 3600 ))" ;;
    *) printf '30\n' ;;
  esac
}

wait_until() {
  local desc="$1" timeout_s="$2"
  shift 2
  local deadline=$((SECONDS + timeout_s))
  until "$@"; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 2
  done
  log "${desc}"
}

cleanup_cluster() {
  "${KUBECTL[@]}" delete clusterrolebinding "${CLUSTER_ROLE_NAME}" --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete clusterrole "${CLUSTER_ROLE_NAME}" --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete namespace "${AGENTS_NS}" "${GATEWAY_NS}" --ignore-not-found --wait=true --timeout="${TIMEOUT}" >/dev/null 2>&1 || true
}

on_exit() {
  local status=$?
  [[ "${KEEP_RESOURCES}" == "1" ]] || cleanup_cluster
  rm -rf "${WORKDIR}"
  exit "${status}"
}
trap on_exit EXIT

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${ROOT}"

need kubectl
need kind
need sed
if [[ "${SKIP_BUILD}" != "1" ]]; then
  need go
  need docker
fi
[[ -f "${OVERLAY}/kustomization.yaml" ]] || fail "e2e overlay not found: ${OVERLAY}"
[[ -f "${OVERLAY}/gateway.hcl" ]] || fail "e2e gateway config not found: ${OVERLAY}/gateway.hcl"
[[ -f "${DOCKERFILE}" ]] || fail "Dockerfile not found: ${DOCKERFILE}"

# Keep the liveness/reap waits in sync with the window the gateway enforces.
# Liveness is derived: keepalive_interval × keepalive_reap_count.
KEEPALIVE_INTERVAL="$(sed -n 's/.*keepalive_interval[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${OVERLAY}/gateway.hcl" | head -1)"
KEEPALIVE_REAP_COUNT="$(sed -n 's/.*keepalive_reap_count[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "${OVERLAY}/gateway.hcl" | head -1)"
KEEPALIVE_INTERVAL="${KEEPALIVE_INTERVAL:-10s}"
KEEPALIVE_REAP_COUNT="${KEEPALIVE_REAP_COUNT:-3}"
PEER_TTL="$(( $(seconds_from_duration "${KEEPALIVE_INTERVAL}") * KEEPALIVE_REAP_COUNT ))s"

if ! kind get clusters | grep -Fxq "${CLUSTER_NAME}"; then
  fail "kind cluster ${CLUSTER_NAME} not found"
fi
if ! "${KUBECTL[@]}" get nodes >/dev/null; then
  fail "kubectl context ${KUBE_CONTEXT} is not reachable"
fi

log "cleaning previous e2e resources in ${GATEWAY_NS}/${AGENTS_NS}"
cleanup_cluster

NODE_ARCH="$("${KUBECTL[@]}" get node -o jsonpath='{.items[0].status.nodeInfo.architecture}')"
GOARCH="${GOARCH_OVERRIDE:-${NODE_ARCH}}"
case "${GOARCH}" in
  amd64|arm64) ;;
  *) fail "unsupported node architecture ${GOARCH}; set CLAWPATROL_E2E_GOARCH" ;;
esac

if [[ "${SKIP_BUILD}" != "1" ]]; then
  log "building Linux/${GOARCH} clawpatrol binary"
  CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" make build
  cp "${ROOT}/clawpatrol" "${WORKDIR}/clawpatrol"

  log "building image ${IMAGE}"
  DOCKER_BUILDKIT=0 docker build --platform "linux/${GOARCH}" -f "${DOCKERFILE}" -t "${IMAGE}" "${WORKDIR}"

  log "loading image ${IMAGE} into kind cluster ${CLUSTER_NAME}"
  kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"
else
  log "skipping image build/load; expecting ${IMAGE} to exist in kind"
fi

log "applying e2e overlay into ${GATEWAY_NS}/${AGENTS_NS}"
"${KUBECTL[@]}" apply -k "${OVERLAY}"
"${KUBECTL[@]}" -n "${GATEWAY_NS}" rollout restart statefulset/clawpatrol-gateway

log "waiting for gateway rollout"
"${KUBECTL[@]}" -n "${GATEWAY_NS}" rollout status statefulset/clawpatrol-gateway --timeout="${TIMEOUT}"
"${KUBECTL[@]}" -n "${GATEWAY_NS}" wait --for=condition=Ready pod -l app=clawpatrol-gateway --timeout="${TIMEOUT}"

# Recreate the agent after the gateway rollout so the enrollment assertions
# start from a clean sidecar session without startup retries.
log "recreating agent pod against the ready gateway"
"${KUBECTL[@]}" -n "${AGENTS_NS}" delete pod "${E2E_POD}" --ignore-not-found --wait=true >/dev/null
"${KUBECTL[@]}" apply -k "${OVERLAY}"

"${KUBECTL[@]}" -n "${AGENTS_NS}" wait --for=condition=Ready "pod/${E2E_HTTP}" --timeout="${TIMEOUT}"

GATEWAY_POD="$("${KUBECTL[@]}" -n "${GATEWAY_NS}" get pod -l app=clawpatrol-gateway -o jsonpath='{.items[0].metadata.name}')"
HTTP_CLUSTER_IP="$("${KUBECTL[@]}" -n "${AGENTS_NS}" get svc "${E2E_HTTP}" -o jsonpath='{.spec.clusterIP}')"

agent_exec() { "${KUBECTL[@]}" -n "${AGENTS_NS}" exec "${E2E_POD}" -c agent -- "$@"; }
gateway_exec() { "${KUBECTL[@]}" -n "${GATEWAY_NS}" exec "${GATEWAY_POD}" -c gateway -- "$@"; }
sqlite_query() { gateway_exec sqlite3 -cmd '.timeout 5000' /opt/clawpatrol/clawpatrol.db "$1"; }

# Enrollment state lives on the wg_peers row (enrolled = 1); there is no
# separate lease table. The reaper only ever touches enrolled rows.
enrolled_count() { sqlite_query "SELECT count(*) FROM wg_peers WHERE enrolled = 1 AND display_name = '${AGENTS_NS}/${E2E_POD}';" 2>/dev/null; }
enrolled_present() { [[ "$(enrolled_count || printf '0')" -ge 1 ]]; }
enrolled_absent() { [[ "$(enrolled_count || printf '1')" -eq 0 ]]; }

log "waiting for sidecar handoff files"
wait_until "sidecar wrote ready/env/ca files" 120 \
  agent_exec sh -lc 'test -f /clawpatrol/ready && test -s /clawpatrol/env && test -s /clawpatrol/ca.crt'

log "checking handoff content (fresh CA is present in the pushed combined bundle)"
# The sidecar writes the gateway CA and an env file the workload sources; the
# CA-path pushdown must use the combined system+gateway bundle created after
# ca.crt is written. NODE_EXTRA_CA_CERTS remains pointed at the gateway CA.
agent_exec sh -lc 'head -1 /clawpatrol/ca.crt | grep -q "^-----BEGIN CERTIFICATE-----"'
agent_exec sh -lc '. /clawpatrol/env; test "$SSL_CERT_FILE" = /clawpatrol/ca-bundle.crt; test -s "$SSL_CERT_FILE"; test "$(grep -c "^-----BEGIN CERTIFICATE-----" "$SSL_CERT_FILE")" -gt 1; lines="$(wc -l < /clawpatrol/ca.crt)"; tail -n "$lines" "$SSL_CERT_FILE" | cmp - /clawpatrol/ca.crt'
agent_exec sh -lc '. /clawpatrol/env; test "$NODE_EXTRA_CA_CERTS" = /clawpatrol/ca.crt'

log "checking restricted agent container contract"
agent_exec sh -lc 'test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token'
agent_exec sh -lc 'test ! -e /var/run/secrets/tokens/clawpatrol-token'
agent_exec sh -lc 'test ! -e /dev/net/tun'
agent_exec sh -lc 'test "$(awk "/CapEff:/ {print \$2}" /proc/self/status)" = "0000000000000000"'
agent_exec sh -lc '! ip route add blackhole 198.51.100.0/24 2>/tmp/route.err'
agent_exec sh -lc '! sh -c "printf x >/clawpatrol/agent-write-test" 2>/tmp/write.err'
agent_exec sh -lc "! grep -R -i -E 'api_token|private_key|wireguard_private' /clawpatrol 2>/dev/null"
agent_exec sh -lc 'ip route show default | grep -q "dev clawpatrol0"'

log "checking tunnel route and a relayed TCP request"
agent_exec sh -lc "ip route get '${HTTP_CLUSTER_IP}' | grep -q 'dev clawpatrol0'"
agent_exec sh -lc "test \"\$(curl -sS --max-time 10 'http://${HTTP_CLUSTER_IP}:8081/')\" = 'ok'"

log "checking the gateway path is pinned off the tunnel"
# The sidecar pins the gateway API (+ WG endpoint) to the pod's original
# default route before flipping the default to clawpatrol0, so enroll /
# env-pushdown / deregister don't loop back through the tunnel. The API
# ClusterIP must therefore NOT route via clawpatrol0.
API_CLUSTER_IP="$("${KUBECTL[@]}" -n "${GATEWAY_NS}" get svc clawpatrol-api -o jsonpath='{.spec.clusterIP}')"
[[ -n "${API_CLUSTER_IP}" ]] || fail "could not resolve clawpatrol-api ClusterIP"
agent_exec sh -lc "! ip route get '${API_CLUSTER_IP}' | grep -q 'dev clawpatrol0'"
# The control-plane pins carry the clawpatrol route protocol (111) so an
# in-process reconnect (or a genuine restart) can recover the underlay gateway
# from them when there is no default route. The gateway API pin must show that tag.
agent_exec sh -lc "ip route show proto 111 | grep -q '${API_CLUSTER_IP}'"
# The pod's resolver is pinned to the underlay with the same tag, so DNS keeps
# working across a reconnect (the gateway is resolved by name; SNI/Host stay
# correct). Read the agent's actual nameserver and require it be pinned.
AGENT_DNS_IP="$(agent_exec sh -lc "awk '/^nameserver/{print \$2; exit}' /etc/resolv.conf" | tr -d '[:space:]')"
[[ -n "${AGENT_DNS_IP}" ]] || fail "agent has no resolv.conf nameserver"
agent_exec sh -lc "ip route show proto 111 | grep -q '${AGENT_DNS_IP}'"

log "checking enrolled peer row and WireGuard peer tables"
gateway_exec sh -lc 'command -v sqlite3 >/dev/null'
wait_until "enrolled peer row is present" 60 enrolled_present
PEER_IP="$(sqlite_query "SELECT ip FROM wg_peers WHERE enrolled = 1 AND display_name = '${AGENTS_NS}/${E2E_POD}' LIMIT 1;")"
[[ -n "${PEER_IP}" ]] || fail "enrolled peer row did not include an ip"
sqlite_query "SELECT count(*) FROM wg_peers WHERE ip = '${PEER_IP}';" | grep -qx '1'
log "enrolled peer ${PEER_IP}"

if [[ "${CHECK_LIVENESS}" == "1" ]]; then
  # No app-level heartbeat: the gateway drives liveness from WireGuard
  # rx_bytes movement (persistent-keepalive every keepalive_interval). A live
  # tunnel must keep its enrolled row past peer_ttl without being reaped.
  TTL_SECONDS="$(seconds_from_duration "${PEER_TTL}")"
  SLEEP_SECONDS=$(( TTL_SECONDS + 30 ))
  log "waiting ${SLEEP_SECONDS}s (> peer_ttl) to confirm keepalive liveness holds the peer"
  sleep "${SLEEP_SECONDS}"
  enrolled_present || fail "live peer was reaped despite an active tunnel (rx_bytes liveness regressed)"
  log "live peer survived past peer_ttl"
fi

if [[ "${CHECK_ESCALATION}" == "1" ]]; then
  # Client self-heal, in-process. Scale the gateway to 0 so the sidecar's
  # liveness probe (ICMP echo to the gateway tunnel IP) fails. The sidecar
  # rekeys, then tears the tunnel down and re-enrolls — all WITHOUT exiting the
  # container (a native-sidecar restart lands in the same pod sandbox and buys
  # nothing a device rebuild doesn't). While the gateway is down it stays
  # fail-closed: clawpatrol0 is gone, so there is no default route (general
  # egress is blocked, not leaking untunnelled) while the tagged control-plane
  # pins survive on the underlay. When the gateway returns it re-enrolls in
  # place with a fresh key, reusing its peer IP — and the container restart
  # count never moves.
  sidecar_restarts() {
    "${KUBECTL[@]}" -n "${AGENTS_NS}" get pod "${E2E_POD}" \
      -o jsonpath='{.status.initContainerStatuses[?(@.name=="clawpatrol-bridge")].restartCount}' 2>/dev/null
  }
  BEFORE_RESTARTS="$(sidecar_restarts)"
  BEFORE_RESTARTS="${BEFORE_RESTARTS:-0}"
  BEFORE_PUBKEY="$(sqlite_query "SELECT pubkey FROM wg_peers WHERE enrolled = 1 AND display_name = '${AGENTS_NS}/${E2E_POD}' LIMIT 1;")"
  BEFORE_PEER_IP="${PEER_IP}"

  log "severing liveness: scaling gateway to 0 so the sidecar's ICMP probe fails"
  "${KUBECTL[@]}" -n "${GATEWAY_NS}" scale statefulset/clawpatrol-gateway --replicas=0 >/dev/null
  "${KUBECTL[@]}" -n "${GATEWAY_NS}" rollout status statefulset/clawpatrol-gateway --timeout="${TIMEOUT}" >/dev/null 2>&1 || true

  # The sidecar escalates to an in-process reconnect: it tears clawpatrol0 down
  # (so the default route disappears) and cannot re-enroll while the gateway is
  # down, so it holds fail-closed. Wait for that torn-down state, then assert
  # the control-plane pins survive and — crucially — the container has NOT
  # restarted (recovery is in-process, not a kubelet restart).
  wait_until "sidecar tore the tunnel down and failed closed (no default route)" 150 \
    agent_exec sh -lc '! ip route show default | grep -q .'
  log "checking fail-closed gap: no default route, control-plane pins intact, no container restart"
  agent_exec sh -lc "ip route show proto 111 | grep -q '${API_CLUSTER_IP}'"
  [[ "$(sidecar_restarts)" == "${BEFORE_RESTARTS}" ]] ||
    fail "sidecar container restarted during the gap (was ${BEFORE_RESTARTS}); recovery must be in-process"

  log "restoring gateway"
  "${KUBECTL[@]}" -n "${GATEWAY_NS}" scale statefulset/clawpatrol-gateway --replicas=1 >/dev/null
  "${KUBECTL[@]}" -n "${GATEWAY_NS}" rollout status statefulset/clawpatrol-gateway --timeout="${TIMEOUT}"
  "${KUBECTL[@]}" -n "${GATEWAY_NS}" wait --for=condition=Ready pod -l app=clawpatrol-gateway --timeout="${TIMEOUT}"
  GATEWAY_POD="$("${KUBECTL[@]}" -n "${GATEWAY_NS}" get pod -l app=clawpatrol-gateway -o jsonpath='{.items[0].metadata.name}')"

  # The gateway's DB persists across the scale, so it re-seeds the OLD peer row
  # on startup — enrolled_present alone would be satisfied by that stale row
  # before the sidecar re-enrolls. Wait for the pubkey to actually change,
  # which only the fresh in-process enrollment (new ephemeral key) produces.
  peer_reenrolled() {
    local pk
    pk="$(sqlite_query "SELECT pubkey FROM wg_peers WHERE enrolled = 1 AND display_name = '${AGENTS_NS}/${E2E_POD}' LIMIT 1;" 2>/dev/null)"
    [[ -n "${pk}" && "${pk}" != "${BEFORE_PUBKEY}" ]]
  }
  wait_until "sidecar re-enrolled in-process with a fresh WireGuard key" 180 peer_reenrolled
  PEER_IP="$(sqlite_query "SELECT ip FROM wg_peers WHERE enrolled = 1 AND display_name = '${AGENTS_NS}/${E2E_POD}' LIMIT 1;")"

  # Recovery stayed in-process: the container restart count must be unchanged.
  [[ "$(sidecar_restarts)" == "${BEFORE_RESTARTS}" ]] ||
    fail "sidecar container restarted during recovery (was ${BEFORE_RESTARTS}, now $(sidecar_restarts)); recovery must be in-process"

  # Same-subject renewal reuses the peer IP: the fresh enrollment swaps the
  # WireGuard key but the gateway hands the identity back its prior slot.
  [[ "${PEER_IP}" == "${BEFORE_PEER_IP}" ]] ||
    fail "self-heal did not reuse the peer IP (was ${BEFORE_PEER_IP}, got ${PEER_IP})"

  wait_until "tunnel restored after self-heal" 60 \
    agent_exec sh -lc "test \"\$(curl -sS --max-time 10 'http://${HTTP_CLUSTER_IP}:8081/')\" = 'ok'"
  log "sidecar self-healed in-process: 0 container restarts, re-enrolled ${PEER_IP} with a fresh key"
fi

if [[ "${CHECK_EXPIRY}" == "1" ]]; then
  TTL_SECONDS="$(seconds_from_duration "${PEER_TTL}")"
  log "force deleting sidecar pod to test rx_bytes reap cleanup"
  "${KUBECTL[@]}" -n "${AGENTS_NS}" delete pod "${E2E_POD}" --force --grace-period=0 --wait=true
  wait_until "enrolled peer went stale and was reaped" "$((TTL_SECONDS + 90))" enrolled_absent
else
  log "deleting e2e pod and checking graceful deregistration"
  "${KUBECTL[@]}" -n "${AGENTS_NS}" delete pod "${E2E_POD}" --wait=true --timeout=60s
  wait_until "enrolled peer removed" 45 enrolled_absent
fi

sqlite_query "SELECT count(*) FROM wg_peers WHERE ip = '${PEER_IP}';" | grep -qx '0'
log "WireGuard peer ${PEER_IP} was revoked"
log "e2e passed"
