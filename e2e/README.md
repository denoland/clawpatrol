# End-to-end tests

This directory contains repo-level end-to-end validation flows. The
Kubernetes WireGuard enrollment test is the main one today.

## Kubernetes WireGuard enrollment

Run from the repo root:

```bash
./e2e/kubernetes-wireguard-e2e.sh
```

The test expects a local kind cluster named `kind` and a reachable
`kind-kind` kubectl context. It builds the current workspace binary,
packages it with the root `Dockerfile`, loads the image into kind, and
applies the checked-in overlay at
`e2e/kubernetes-wireguard-e2e-overlay`.

The overlay reuses the example base at
`examples/kubernetes/kustomization` with the lockdown component at
`examples/kubernetes/lockdown`, and changes it to use:

- `clawpatrol-e2e` and `agents-e2e` namespaces,
- the pinned ClusterIPs `10.96.200.20` for `clawpatrol-api` and
  `10.96.200.21` for `clawpatrol-wg`, and the agent's `--resolve` entries,
- the local `clawpatrol-kind-e2e:dev` image,
- a short liveness window (a small `keepalive_interval`),
- an e2e HTTP target used to prove tunneled data-path traffic.

The script validates:

- gateway rollout,
- workload enrollment through the authorizer,
- env and CA handoff from the sidecar,
- restricted agent container contract,
- tunnel routing through the WireGuard interface,
- a TCP request through the tunnel,
- the enrolled `wg_peers` row and WireGuard peer state,
- rx_bytes liveness (a live tunnel holds its peer past the liveness window),
- sidecar self-heal (a severed tunnel drives in-process re-enrollment with a
  fresh key at the reused peer IP and no container restart),
- rule loss: without the bridge's rule 91, a marked packet is unreachable
  and does not loop into the tunnel; the bridge reconnects and restores the
  rule (part of the self-heal check),
- the reaper: the bridge is stopped with SIGSTOP from the kind node, so it
  cannot deregister; the gateway reaps the peer, and after SIGCONT the bridge
  re-enrolls in-process (set `CLAWPATROL_E2E_CHECK_EXPIRY=0` to skip),
- `tunnel_split_cidrs`: a listed Service IP routes through the CNI
  and answers, an unlisted one still routes through the tunnel,
- the lockdown component: the agent bridge uses its `--resolve` entries for
  both gateway names and no DNS. With the strict egress policy, the agent cannot reach the echo pod on
  its CNI route, the `tunnel_split_cidrs` Service, or a kube-dns pod
  directly. Workload DNS, inbound replies, and the readiness probe still
  work, and self-heal re-enrolls without DNS (set
  `CLAWPATROL_E2E_CHECK_LOCKDOWN=0` to skip; skipped when the CNI does not
  enforce NetworkPolicy),
- bridge variants: the raw ICMP socket fallback, the handshake-age watchdog
  when no ICMP socket opens, with no reconnect on a healthy tunnel (set
  `CLAWPATROL_E2E_CHECK_VARIANTS=0` to skip),
- the example MutatingAdmissionPolicy, applied from
  `examples/kubernetes/` with the e2e namespace, gateway, and image: it
  injects the bridge and the `ping_group_range` sysctl, keeps existing
  sysctls, skips hostNetwork and opted-out Pods, and an injected Pod enrolls
  (set `CLAWPATROL_E2E_CHECK_ADMISSION=0` to skip; skipped when the cluster
  does not serve `MutatingAdmissionPolicy` v1),
- graceful deregistration and peer revocation.

By default the script deletes the e2e namespaces and cluster-scoped RBAC
objects at both start and exit so each run starts from fresh cluster
state.

## Prerequisites

- `go`
- `docker`
- `kind`
- `kubectl`
- a running kind cluster named `kind`
- access to Docker and the kind Kubernetes API from the current shell

The script uses `make build` for the Linux binary and then runs
`docker build` against the root `Dockerfile`.

## Useful knobs

```bash
CLAWPATROL_E2E_CLUSTER=kind-dev ./e2e/kubernetes-wireguard-e2e.sh
CLAWPATROL_E2E_CONTEXT=kind-kind-dev ./e2e/kubernetes-wireguard-e2e.sh
CLAWPATROL_E2E_SKIP_BUILD=1 ./e2e/kubernetes-wireguard-e2e.sh
CLAWPATROL_E2E_KEEP_RESOURCES=1 ./e2e/kubernetes-wireguard-e2e.sh
CLAWPATROL_E2E_CHECK_LIVENESS=0 ./e2e/kubernetes-wireguard-e2e.sh
CLAWPATROL_E2E_CHECK_EXPIRY=0 ./e2e/kubernetes-wireguard-e2e.sh
CLAWPATROL_E2E_GOARCH=arm64 ./e2e/kubernetes-wireguard-e2e.sh
```

`CLAWPATROL_E2E_SKIP_BUILD=1` assumes `clawpatrol-kind-e2e:dev` is
already loaded into the kind cluster. `CLAWPATROL_E2E_KEEP_RESOURCES=1`
keeps namespaces and RBAC objects around for debugging; clean them up
manually afterward.

Image tag, namespace names, RBAC names, and enrollment keepalive tuning are
owned by the overlay files, not by the shell script.
