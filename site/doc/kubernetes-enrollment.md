# Kubernetes Enrollment

Claw Patrol can run inside Kubernetes with one long-lived gateway pod and
stateless agent pods that appear only for the lifetime of a job. Each agent
pod self-enrolls as a transient WireGuard peer using a projected Kubernetes
ServiceAccount token, so it does not need a pre-created peer or human approval.

This mode is for same-cluster deployments where:

- the gateway runs in Kubernetes,
- agent pods are created on demand,
- the agent container must remain restricted, and
- a networking sidecar with `NET_ADMIN` is acceptable outside the agent container.

## Architecture

The deployment has three parts:

- **Gateway pod:** Runs `clawpatrol gateway`, the dashboard/API, and the
  userspace WireGuard server. It can create Kubernetes TokenReviews and read
  allowed agent Pods.
- **Clawpatrol bridge:** Runs `clawpatrol bridge` as a restartable native
  sidecar under `initContainers`. It owns the projected token, `/dev/net/tun`,
  `NET_ADMIN`, enrollment, and pod routing.
- **Agent container:** Runs the workload without a Kubernetes token,
  `/dev/net/tun`, or added capabilities. It receives only a read-only handoff
  volume from the bridge.

The bridge startup probe checks `/clawpatrol/ready`. Kubernetes does not start
the agent container until tunnel setup and the environment/CA handoff have
succeeded.

## Gateway configuration

Enrollment uses a top-level
`enrollment "kubernetes_token_review" "<name>"` block alongside `profile` and
`credential` blocks. It requires a `wireguard` block, which is the only
supported enrollment transport in v1.

```hcl
gateway {
  dashboard_listen = "0.0.0.0:8080"
  state_dir        = "/opt/clawpatrol"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
    listen_port = 51820
    endpoint    = "clawpatrol-wg.clawpatrol.svc:51820"
  }
}

enrollment "kubernetes_token_review" "agents" {
  audience = "clawpatrol"

  match {
    namespace       = "agents"
    service_account = "agent-runner"
    profile_label   = "clawpatrol.dev/profile"
    profiles        = ["default"]
  }

  keepalive_interval   = "25s"
  keepalive_reap_count = 3
}

profile "default" {
  credentials = []
}
```

The enrollment configuration follows these rules:

- **Authorizer:** The two block labels specify the authorizer type and instance
  name. Together, they form the `--authorizer <type>/<name>` value used by the
  bridge.
- **Identity matching:** Each `match` block allows one Kubernetes namespace
  and ServiceAccount pairing.
- **Profile selection:** The gateway reads the profile from the live Pod label
  named by `profile_label`, which defaults to
  `clawpatrol.dev/profile`. The value must appear in the match's `profiles`
  allowlist. The client cannot select its own profile.
- **Additional identities:** Add more `match` blocks to authorize other
  namespace and ServiceAccount pairings.
- **Capacity:** Each live Pod holds one address from `subnet_cidr`. A `/24`
  gives 253 peer addresses (`.2` to `.254`; `.1` is the gateway), shared with
  onboarded devices. A replaced Pod releases its address at once. A Pod that
  stops sending releases it after the liveness window.
- **Registration load:** The gateway runs at most 4 registrations at a time
  past the request checks. Each one sends a TokenReview and a Pod read to the
  apiserver. Extra requests get HTTP 429, and the bridge retries with backoff.

The complete standalone example is
[`examples/wireguard-enrollment-kubernetes.hcl`](https://github.com/denoland/clawpatrol/blob/main/examples/wireguard-enrollment-kubernetes.hcl).

## Security boundary

The gateway uses userspace WireGuard and does not need kernel WireGuard
privileges.

The projected ServiceAccount token must be bound to the enrolling Pod. The
gateway verifies its configured audience and bound Pod name and UID through
TokenReview, then confirms the same UID and ServiceAccount on the live Pod.

The bridge owns all privileged and enrollment-sensitive state:

- the projected Kubernetes token,
- the WireGuard private key and peer API token in memory,
- `/dev/net/tun` and `NET_ADMIN`, and
- pod routing.

The agent container receives only:

- `/clawpatrol/env`,
- `/clawpatrol/ca.crt`,
- `/clawpatrol/ready`, and
- the network namespace configured by the bridge.

The WireGuard private key and peer API token are never written to the shared
volume.

### Transport security for enrollment

The bridge sends the projected ServiceAccount token to the gateway when it
registers, and the peer API token when it fetches the environment. The gateway
returns the CA that the workload will trust. The example `--gateway-url` is the
in-cluster Service over plain HTTP, which is for development and tests: anyone
on the network path can read the tokens, replay the ServiceAccount token
within its lifetime, or replace the CA.

For production, set `--gateway-url` to the gateway's `public_url` behind a TLS
ingress or load balancer that you operate:

- The ingress must pass the `Authorization` header, POST and DELETE requests,
  and request bodies to the gateway's `dashboard_listen` port.
- The bridge sends this traffic on the underlay, not through the tunnel, so
  the Pod network must reach the ingress address (an in-cluster ingress
  controller Service, or a load balancer that allows hairpin traffic). Allow
  that path in any egress or ingress NetworkPolicy.
- The WireGuard endpoint is separate (UDP). When `wireguard.endpoint` is not
  set, the gateway advertises the host of `public_url`.
- If the ingress certificate comes from a private CA, set `SSL_CERT_FILE` (or
  `SSL_CERT_DIR`) on the bridge container to a bundle that contains it, for
  example from a mounted ConfigMap. The bundle replaces the system roots for
  the bridge.

```yaml
# Overlay patch for the bridge container in agent.yaml.
args:
  - bridge
  - --gateway-url=https://clawpatrol.example.com
  # ... other bridge arguments unchanged
env:
  - name: SSL_CERT_FILE
    value: /etc/clawpatrol-ca/ca.crt
volumeMounts:
  - name: clawpatrol-ingress-ca
    mountPath: /etc/clawpatrol-ca
    readOnly: true
```

The bridge logs a warning at startup when `--gateway-url` uses `http://`.

## Gateway RBAC

The gateway ServiceAccount needs:

- `create` on `tokenreviews.authentication.k8s.io`, and
- `get` on Pods in namespaces that can run enrolled agents.

The example RBAC grants only those permissions.

## Agent pod contract

The bridge needs:

- `NET_ADMIN`,
- `/dev/net/tun`,
- a projected ServiceAccount token using the configured audience,
- Downward API values for `POD_NAME`, `POD_NAMESPACE`, `POD_UID`, and
  `NODE_NAME`, and
- read-write access to a shared `emptyDir` mounted at `/clawpatrol`.

The agent container should:

- omit the Kubernetes token and `/dev/net/tun`,
- drop all Linux capabilities (`drop: ["ALL"]`). With `NET_ADMIN` or
  `NET_RAW` it could set the bridge's socket mark and send traffic around the
  tunnel,
- mount `/clawpatrol` read-only, and
- source `/clawpatrol/env` before starting the workload.

Do not run the bridge in a Pod with `hostNetwork: true`. The Pod then shares
the node's network namespace, and the bridge replaces the node's default
route. The admission policy example skips host-network Pods.

```yaml
initContainers:
  - name: clawpatrol-bridge
    restartPolicy: Always
    image: ghcr.io/denoland/clawpatrol:latest
    args:
      - bridge
      - --gateway-url=http://clawpatrol-api.clawpatrol.svc:8080
      - --authorizer=kubernetes_token_review/agents
      - --kubernetes-token-path=/var/run/secrets/tokens/clawpatrol-token
      - --env-out=/clawpatrol/env
      - --ca-out=/clawpatrol/ca.crt
      - --ready-file=/clawpatrol/ready
    startupProbe:
      exec:
        command: ["test", "-f", "/clawpatrol/ready"]
      periodSeconds: 1
      failureThreshold: 120
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        add: ["NET_ADMIN"]
```

The complete Pod spec is in
[`examples/kubernetes/kustomization`](https://github.com/denoland/clawpatrol/tree/main/examples/kubernetes/kustomization).

## Runtime compatibility

The bridge needs a network namespace that it can change with `NET_ADMIN`, a
TUN device from the hostPath `/dev/net/tun`, and `nf_tables` for its egress
filter.

| Runtime | Status |
|---------|--------|
| runc (containerd, CRI-O) | Tested by the kind e2e |
| Kata Containers | Not tested yet |
| gVisor | Not tested yet |

Kata runs the Pod in a guest kernel, and gVisor has its own network stack, so
check these before you rely on either:

- the bridge can open `/dev/net/tun` and create `clawpatrol0`,
- `NET_ADMIN` lets it change routes and policy rules in the Pod,
- the egress filter loads (or start the bridge with `--egress-filter=off`),
  and
- the ICMP liveness probe can open a socket (see "Liveness probe
  permissions").

The bridge's error messages for a missing TUN device and a filter that cannot
load point to this section.

### Pod Security

The Pod Security "baseline" and "restricted" levels do not allow `hostPath`
volumes or the `NET_ADMIN` capability, so the workload namespace needs the
"privileged" level:

```bash
kubectl label namespace agents pod-security.kubernetes.io/enforce=privileged
```

The agent container itself stays restricted: no capabilities, no token, and a
read-only handoff volume.

## Deploy the example

The Kustomize example creates:

- the `clawpatrol` gateway namespace,
- the `agents` workload namespace,
- the gateway StatefulSet and services,
- TokenReview and Pod-read RBAC, and
- a restricted sample agent Pod with the bridge sidecar.

Set the dashboard password before you apply the example. The gateway listens
on `0.0.0.0:8080` for the enrollment API and the dashboard, and until a
password exists the dashboard serves an open first-run form. The gateway sets
the password at startup from `--set-dashboard-password`, so pass it from a
Secret in your overlay:

```bash
kubectl -n clawpatrol create secret generic clawpatrol-dashboard \
  --from-literal=password="$(openssl rand -base64 24)"
```

```yaml
# Overlay patch for the gateway container in gateway-statefulset.yaml.
args:
  - gateway
  - --set-dashboard-password=$(DASHBOARD_PASSWORD)
  - /etc/clawpatrol/gateway.hcl
env:
  - name: DASHBOARD_PASSWORD
    valueFrom:
      secretKeyRef:
        name: clawpatrol-dashboard
        key: password
```

Then apply the example:

```bash
kubectl apply -k examples/kubernetes/kustomization
```

The example advertises the WireGuard endpoint through same-cluster Service
DNS:

```hcl
endpoint = "clawpatrol-wg.clawpatrol.svc:51820"
```

## Startup and recovery

On startup, the bridge:

1. authenticates the Pod through the configured enrollment authorizer,
2. receives its WireGuard peer configuration,
3. brings up the tunnel and routes Pod traffic through it,
4. waits for a WireGuard handshake and a reply from the gateway's tunnel
   address (up to 20 seconds, then it retries the whole bring-up),
5. fetches the environment and CA handoff, and
6. writes `/clawpatrol/ready`.

When tunnel connectivity is lost, the bridge first attempts a local tunnel
rebuild. If connectivity remains unavailable, it re-enrolls without exiting
the container. Traffic fails closed while the tunnel is unavailable, and a
re-enrolling bridge keeps its peer IP when it represents the same subject.

Recovery does not increment the container restart count. Use the bridge
lifecycle logs to observe local rebuilds and re-enrollment.

When the gateway refuses a registration, the bridge log shows
`enrollment denied (ref <id>)`. The reply does not say which check failed.
Find the gateway log line `enrollment: denied ref=<id>` for the reason.

### Liveness probe permissions

The bridge checks the tunnel with an ICMP echo to the gateway's tunnel
address. It opens the probe socket once per session:

1. It first tries an unprivileged ICMP socket. This needs the Pod sysctl
   `net.ipv4.ping_group_range` to include the bridge's GID. The example Pod
   and the admission policy set it to `"0 2147483647"`. Kubernetes treats this
   sysctl as safe. containerd 2.0 and later set it by default; earlier
   containerd versions and some CRI-O setups do not.
2. If that is not allowed, it tries a raw ICMP socket, which needs the
   `NET_RAW` capability on the bridge container.
3. If neither is allowed, the bridge logs a warning and checks the age of the
   last WireGuard handshake instead. A healthy tunnel re-handshakes at least
   every three minutes, so this mode detects a dead tunnel in about five
   minutes instead of about one.

## Reaper

Kubernetes Pod peers are transient. The bridge sends WireGuard keepalives, and
the gateway uses them as the peer's liveness signal. There is no separate
application heartbeat.

### Behavior

- A newly enrolled peer receives a full liveness window before it can be
  reaped.
- Normal Pod shutdown triggers best-effort deregistration immediately.
- If a Pod disappears without deregistering, the gateway revokes it after the
  liveness window expires.
- Only self-enrolled peers are reaped. Devices added through normal onboarding
  are never reaped.

One case can reap a working peer. WireGuard resets the keepalive timer on
received traffic too, so a Pod that only receives data for longer than the
liveness window (for example a one-way UDP stream from the gateway, with no
reply traffic) sends no keepalives. The gateway then sees no receive progress
and reaps the peer, and the bridge re-enrolls. TCP flows are not affected,
because the Pod sends acknowledgements.

### Tuning

| Setting | Default | Behavior |
|---|---|---|
| `keepalive_interval` | `25s` | How often the bridge signals liveness. Minimum `10s`; no maximum. |
| `keepalive_reap_count` | `3` | Number of missed keepalives allowed before the peer is revoked and the bridge re-enrolls. Set to `0` to disable reaping and liveness recovery. |
| `--local-reset-missed` | `2` | Number of failed liveness checks before the bridge attempts a local tunnel rebuild. Set to `0` to skip this stage. A value at or above `keepalive_reap_count` also skips it because re-enrollment happens first. |

The effective liveness window is:

```text
keepalive_interval × keepalive_reap_count
```

### Disable the reaper

Set `keepalive_reap_count = 0` on each enrollment authorizer for which reaping
should be disabled:

```hcl
enrollment "kubernetes_token_review" "agents" {
  # ...
  keepalive_reap_count = 0
}
```

Graceful Pod shutdown still triggers best-effort deregistration. However, the
gateway will not remove peers left behind by abrupt Pod termination, and the
bridge will not automatically rebuild or re-enroll a failed tunnel. A stale
peer remains until the same workload identity replaces it or reaping is
enabled again.

## Dashboard

Enrolled peers appear in the Devices list alongside normally onboarded
devices. Their device page shows:

- enrollment authorizer and subject,
- enrollment time,
- assigned profile,
- keepalive and liveness window,
- last liveness check and missed-interval count, and
- live or stale status.

The profile is read-only because it comes from the Pod label. Manual deletion
is hidden because enrolled peers are managed by deregistration and the reaper.

Request history is keyed by peer IP. The gateway assigns addresses next-fit,
so an address that a Pod releases is reused only after the rest of the subnet.
A new Pod that gets a reused address can still see the earlier Pod's history.

## Deployment hardening

### Admission-based injection

An explicit Pod spec is the supported baseline and requires no extra
controllers. A `MutatingAdmissionPolicy` or mutating webhook can inject the
bridge as an optional ergonomic layer.

A ready-to-adapt policy and binding are in
[`examples/kubernetes/agent-bridge-mutatingadmissionpolicy.yaml`](https://github.com/denoland/clawpatrol/blob/main/examples/kubernetes/agent-bridge-mutatingadmissionpolicy.yaml).
Its header lists the namespace, selector, service, image, authorizer, and
volume assumptions that must be reviewed before applying it.

### Restrict Pod egress (recommended)

The bridge already fails closed at the routing layer, and its nftables filter
drops Pod traffic that would leave outside the tunnel through CNI link or
subnet routes. The filter needs `nf_tables` in the node kernel and the
runtime; start the bridge with `--egress-filter=off` where it is not
available. For a cluster-enforced layer as well, use a NetworkPolicy that
permits only:

- the gateway API and WireGuard endpoint, and
- cluster DNS.

A ready-to-adapt example is
[`examples/kubernetes/agent-egress-networkpolicy.yaml`](https://github.com/denoland/clawpatrol/blob/main/examples/kubernetes/agent-egress-networkpolicy.yaml).
It is optional defense-in-depth and only takes effect on a CNI that enforces
NetworkPolicy.

### Restrict gateway ingress (recommended)

Limit who can reach the gateway with a NetworkPolicy that permits only the
agent namespace on the gateway API (TCP 8080) and the WireGuard endpoint
(UDP 51820). A ready-to-adapt example is
[`examples/kubernetes/gateway-ingress-networkpolicy.yaml`](https://github.com/denoland/clawpatrol/blob/main/examples/kubernetes/gateway-ingress-networkpolicy.yaml).
Agent pods still reach the dashboard on the same port, so keep the dashboard
password set.

## Local e2e

The repository includes a kind-based validation flow:

```bash
./e2e/kubernetes-wireguard-e2e.sh
```

It builds the current workspace image, deploys the Kustomize example, checks
the restricted agent contract and tunneled traffic, exercises reaping and
in-process recovery, and verifies cleanup.

## Limitations

- v1 assumes the gateway and agents run in the same Kubernetes cluster.
- v1 assumes a single active gateway replica with persistent state.
- Enrollment is currently implemented only for WireGuard.
- Peer capacity is bounded by the configured WireGuard IPv4 subnet.
- The bridge needs Pod-network privileges; the agent container should remain
  restricted.
- Replies to inbound connections (kubelet `httpGet` and `tcpSocket` probes,
  Services that point at agent Pods) follow the Pod's routes. They leave on
  the underlay only when the client address matches a CNI route that is more
  specific than the default route; otherwise they go into the tunnel and are
  lost. This depends on the CNI. Where it fails, for example when kubelet
  probes come from the node IP and the Pod has only a link route to its
  gateway, use exec probes.
