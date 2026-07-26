# Kubernetes Enrollment

Claw Patrol can run inside Kubernetes with one long-lived gateway pod and
stateless agent pods that appear only for the lifetime of a job. Each agent
pod self-enrolls as a transient WireGuard peer using a projected Kubernetes
ServiceAccount token, so it does not need a pre-created peer or human approval.

This mode is for same-cluster deployments where:

- the gateway runs in Kubernetes,
- agent pods are created on demand,
- the agent container must remain restricted, and
- a privileged networking sidecar is acceptable outside the agent container.

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
- add no Linux capabilities,
- mount `/clawpatrol` read-only, and
- source `/clawpatrol/env` before starting the workload.

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

## Deploy the example

The Kustomize example creates:

- the `clawpatrol` gateway namespace,
- the `agents` workload namespace,
- the gateway StatefulSet and services,
- TokenReview and Pod-read RBAC, and
- a restricted sample agent Pod with the bridge sidecar.

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
4. fetches the environment and CA handoff, and
5. writes `/clawpatrol/ready`.

When tunnel connectivity is lost, the bridge first attempts a local tunnel
rebuild. If connectivity remains unavailable, it re-enrolls without exiting
the container. Traffic fails closed while the tunnel is unavailable, and a
re-enrolling bridge keeps its peer IP when it represents the same subject.

Recovery does not increment the container restart count. Use the bridge
lifecycle logs to observe local rebuilds and re-enrollment.

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

The bridge already fails closed at the routing layer. For a second,
cluster-enforced layer, use a NetworkPolicy that permits only:

- the gateway API and WireGuard endpoint, and
- cluster DNS.

A ready-to-adapt example is
[`examples/kubernetes/agent-egress-networkpolicy.yaml`](https://github.com/denoland/clawpatrol/blob/main/examples/kubernetes/agent-egress-networkpolicy.yaml).
It is optional defense-in-depth and only takes effect on a CNI that enforces
NetworkPolicy.

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
