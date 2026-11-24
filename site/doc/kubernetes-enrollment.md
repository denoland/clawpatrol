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

# Optional: let agents reach in-cluster Services through the gateway.
# Use your cluster's Service and Pod CIDRs.
defaults {
  relay_allow_cidrs = ["10.96.0.0/12", "10.244.0.0/16"]
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
- **In-cluster destinations:** Traffic that follows the default route, DNS
  included, goes through the tunnel, and the gateway dials the destination for
  it. By default (`defaults.relay_destinations = "public"`) the gateway
  refuses private addresses, which include cluster Service and Pod IPs. To let
  agents reach in-cluster Services through the gateway, list the cluster's
  Service and Pod CIDRs in `defaults.relay_allow_cidrs`. To send them through
  the CNI instead, see "Split tunnel".
- **Registration load:** The gateway runs at most 4 registrations at a time
  past the request checks. Each one sends a TokenReview and a Pod read to the
  apiserver. Extra requests get HTTP 429, and the bridge retries with backoff.

The complete standalone example is
[`examples/wireguard-enrollment-kubernetes.hcl`](https://github.com/denoland/clawpatrol/blob/main/examples/wireguard-enrollment-kubernetes.hcl).

## Split tunnel

The bridge replaces only the Pod's default route with `clawpatrol0`. It
leaves every other route in place: the CNI's link and subnet routes, and
routes that processes add later, such as `docker0`. Traffic on those routes
does not go through the tunnel.

Set `tunnel_split_cidrs` on the enrollment to send Pod and Service traffic
outside the tunnel. The bridge routes each listed range through the Pod's
original default gateway. Use it for cluster ranges that the CNI does not
route, for example on Cilium, which gives the Pod a /32 address and a
default route through the Cilium gateway. It also works for other ranges,
such as the Service range on flannel or a VPC range:

```hcl
enrollment "kubernetes_token_review" "agents" {
  tunnel_split_cidrs = ["10.244.0.0/16", "10.96.0.0/12"]
  # ...
}
```

- **Additive:** the list adds routes. It does not remove or limit the routes
  the CNI installs. A CNI route for the same prefix takes priority.
- **Next hop:** the bridge uses the Pod's original default route of the same
  address family. With several default routes, it uses the first one. IPv6
  entries need an IPv6 default route.
- **Service range:** a Pod routes a Service IP before kube-proxy translates
  it, so list the Service range for Service traffic to skip the tunnel.
  Cilium socket-level load balancing translates the address in the Pod, so
  there the Pod range is enough.
- **Reconnects:** the routes stay while the tunnel reconnects, so traffic to
  the listed ranges continues. Other traffic fails closed.
- **Not an enforcement control:** the list only changes routing. Traffic to
  the listed ranges, and on the CNI's own routes, does not reach clawpatrol
  and is not audited. Use NetworkPolicy to restrict it (see "Restrict Pod
  egress" and "Lock down Pod egress"). `defaults.relay_allow_cidrs` is
  needed only for in-cluster traffic that still goes through the tunnel.
- **Workload DNS:** the Pod's DNS server is usually a Service IP. A listed
  Service range sends workload DNS to it around the tunnel, unless a strict
  egress policy blocks it.
- **Inbound clients:** replies follow normal routing. A client outside the
  listed ranges and the CNI's routes, for example behind a LoadBalancer with
  `externalTrafficPolicy: Local`, gets its replies through the tunnel, and
  they fail. Add those ranges to the list.

The gateway rejects a `/0` and any range that overlaps
`wireguard.subnet_cidr` or its IPv6 tunnel range.

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

### Redirects to another gateway

The bridge resolves two names: the `--gateway-url` host and the WireGuard
endpoint host from the enrollment response. A name without a `--resolve`
entry uses the Pod's DNS configuration. The workload shares that
configuration: all containers in the Pod use the same `/etc/hosts` and
`/etc/resolv.conf`, and a workload that runs as root can change them. A
workload that can redirect the bridge can make it send its ServiceAccount
token to a fake gateway.

`--resolve` is a convenience, not a security control. Limit this exposure
outside the Pod:

- restrict the register endpoint with the gateway ingress policy (see
  "Restrict gateway ingress"),
- use TLS with a verified certificate, so that a fake gateway cannot
  complete the handshake (see "Transport security for enrollment"),
- keep the token lifetime short (`expirationSeconds` on the projected
  token), and
- run workload containers as non-root (see "Agent pod contract").

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
- run as non-root (`runAsNonRoot: true`). The workload namespace uses the
  "privileged" Pod Security level (see "Pod Security"), which does not
  enforce it. A root workload can change the Pod's shared `/etc/hosts` and
  `/etc/resolv.conf`, which the bridge also reads (see "Redirects to another
  gateway"),
- mount `/clawpatrol` read-only, and
- source `/clawpatrol/env` before starting the workload.

Do not set `shareProcessNamespace: true` on the Pod. The workload could then
send signals to the bridge.

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
    readinessProbe:
      exec:
        command: ["test", "-f", "/clawpatrol/ready"]
      periodSeconds: 1
      failureThreshold: 3
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        add: ["NET_ADMIN"]
```

The complete Pod spec is in
[`examples/kubernetes/kustomization`](https://github.com/denoland/clawpatrol/tree/main/examples/kubernetes/kustomization).

## WireGuard MTU

The gateway and enrolled bridges default to an inner MTU of 1420 bytes.
If the network path needs a smaller MTU, set `mtu` inside the gateway's
existing `wireguard` block. For example, add `mtu = 1404`.

Values from 1280 through 65475 are valid. IPv6 needs at least 1280 bytes.
Choose an MTU that leaves room for IP, UDP, and WireGuard headers on the
underlay path.

The gateway applies the value to its WireGuard TUN when it starts. A config
reload that changes `mtu` logs a message and has no effect until the gateway
restarts. New bridge enrollments and bridge reconnects use the gateway's
running MTU. An active bridge keeps its MTU until it re-enrolls, so restart the
workload Pods after you lower the MTU. The bridge's `--mtu` flag provides a
fallback when an enrollment response omits the MTU or sends a value outside
the valid range.

The setting applies only to the gateway and enrolled bridges. `clawpatrol run`
and the macOS client always use 1420. Manually configured WireGuard clients set
their interface MTU separately.

## Runtime compatibility

The bridge needs a network namespace that it can change with `NET_ADMIN` and
a TUN device from the hostPath `/dev/net/tun`.

| Runtime | Status |
|---------|--------|
| runc (containerd, CRI-O) | Tested by the kind e2e |
| Kata Containers | Not tested yet |
| gVisor | Not tested yet |

Kata runs the Pod in a guest kernel, and gVisor has its own network stack, so
check these before you rely on either:

- the bridge can open `/dev/net/tun` and create `clawpatrol0`,
- `NET_ADMIN` lets it change routes and policy rules in the Pod, and
- the ICMP liveness probe can open a socket (see "Liveness probe
  permissions").

The bridge's error message for a missing TUN device points to this section.

### Pod Security

The Pod Security "baseline" and "restricted" levels do not allow `hostPath`
volumes or the `NET_ADMIN` capability, so the workload namespace needs the
"privileged" level:

```bash
kubectl label namespace agents pod-security.kubernetes.io/enforce=privileged
```

The agent container itself stays restricted: no capabilities, no token, and a
read-only handoff volume. The "privileged" level does not enforce this, so set
it in the Pod spec, including `runAsNonRoot: true`.

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
rebuild. If connectivity remains unavailable, it clears the readiness marker
and re-enrolls without exiting the container. The readiness probe marks the
Pod unready during this gap. On a container restart, the bridge also clears
any marker left in the shared volume and writes it again after the new
tunnel passes its health checks. Traffic through the tunnel fails closed
during the gap, and a re-enrolling bridge keeps its peer IP for the same
subject.

After a restart of only the bridge container, its startup probe runs again.
The bridge must enroll and pass its health checks within the startup budget
(120 s with `periodSeconds: 1` and `failureThreshold: 120`), or the kubelet
restarts it again.

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

The sysctl is optional; without it the bridge uses step 2 or 3. It applies
to the whole Pod network namespace, so the workload container can also open
unprivileged ICMP echo sockets. That is the same as the containerd 2.0
default for every container. The examples use `"0 2147483647"` to match that
default. The stock image runs the bridge as root (GID 0), so `"0 0"` is
enough. A bridge image that runs as another user needs that GID in the range.

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

For each Pod it admits, the policy:

- adds the bridge as a native sidecar, with its volumes, startup and
  readiness probes, and a read-only `/clawpatrol` mount in every
  application container;
- adds the default profile label when the Pod does not select a profile;
- adds the `net.ipv4.ping_group_range` sysctl to `spec.securityContext`,
  and keeps other sysctls and a `ping_group_range` value the Pod already
  sets;
- skips `hostNetwork` Pods, Pods annotated `clawpatrol.dev/inject: "false"`,
  and Pods that already have a `clawpatrol-bridge` container.

### Restrict Pod egress (recommended)

The bridge replaces only the Pod's default route. Traffic on other routes,
for example a CNI subnet route, a `tunnel_split_cidrs` range, or a `docker0`
bridge inside the sandbox, does not go through the tunnel. Use a
NetworkPolicy to control in-cluster egress.
For agents that may reach only clawpatrol, permit only:

- the gateway API and WireGuard endpoint, and
- cluster DNS.

A ready-to-adapt example is
[`examples/kubernetes/agent-egress-networkpolicy.yaml`](https://github.com/denoland/clawpatrol/blob/main/examples/kubernetes/agent-egress-networkpolicy.yaml).
It takes effect only on a CNI that enforces NetworkPolicy. Its DNS rule also
lets the workload query kube-dns Pods directly, outside the tunnel. To remove
the DNS rule, see "Lock down Pod egress".

### Lock down Pod egress

For an egress policy without a DNS rule, the bridge must reach the gateway
without DNS. The Kustomize component in
[`examples/kubernetes/lockdown`](https://github.com/denoland/clawpatrol/tree/main/examples/kubernetes/lockdown)
does this:

1. It pins the ClusterIPs of the gateway API Service `clawpatrol-api` (TCP
   8080) and the WireGuard Service `clawpatrol-wg` (UDP 51820).
2. It maps each Service name to its pinned address with the bridge flag
   `--resolve=<host>=<ip>`, one entry for each name. A name with a
   `--resolve` entry does not use DNS, at enrollment and at each reconnect.
3. It adds an egress policy that allows only the gateway Pods on TCP 8080
   and UDP 51820.

Add the component to an overlay of the base:

```yaml
resources:
  - ../kustomization
components:
  - ../lockdown
```

With this policy, agent traffic outside the tunnel is blocked: CNI routes
other than the default, `tunnel_split_cidrs` ranges, and direct queries to
kube-dns Pods. Workload DNS still works, because it goes through the tunnel
and the gateway answers it. Replies to inbound connections, such as kubelet
probes, still pass, because NetworkPolicy is stateful.

Review these points:

- **CNI:** the policy takes effect only on a CNI that enforces NetworkPolicy.
  Without it, `--resolve` still works, but traffic outside the tunnel is not
  blocked.
- **Gateway config:** the component does not change `gateway.hcl`. Keep
  `wireguard.endpoint` set to the `clawpatrol-wg` Service name, which has a
  `--resolve` entry.
- **Pinned addresses:** use two free addresses in the cluster's Service CIDR,
  and set each one in its Service and in its `--resolve` argument.
  `spec.clusterIP` is immutable, so delete an existing Service before you pin
  it. Any stable address works, for example a LoadBalancer IP.
- **Logs:** the bridge logs each `--resolve` entry at startup. When it has
  entries, it logs `resolving <host> through DNS (no --resolve entry)` once
  for each other name. In a locked-down Pod, that line shows the missing
  entry.
- **TLS:** `--resolve` changes only the address that the bridge connects to.
  TLS SNI, certificate verification, and the `Host` header use the name, so
  the certificate needs no IP SAN. With `--gateway-url` set to a
  `public_url` behind an ingress, map the ingress name to the ingress
  address, and allow the ingress in the policy instead of the gateway Pods.
- **Gateway DNS:** the gateway Pod still needs cluster DNS. It resolves the
  workload's A and AAAA queries with its own resolver, and relays other query
  types to their original destination.
- **Gateway ports:** NetworkPolicy cannot tell the bridge from the workload,
  because both use the Pod IP. The workload can also reach the gateway Pods
  on the two allowed ports: the dashboard, behind its password, and the
  register endpoint, which needs a token.

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

It builds the current workspace image, deploys the Kustomize example with the
lockdown component, checks the restricted agent contract and tunneled traffic,
exercises reaping and in-process recovery, and verifies cleanup.

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
