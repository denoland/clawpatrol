# Kubernetes enrollment implementation design

This note documents the implementation and invariants behind transient
Kubernetes workload enrollment. It is for contributors changing the config
compiler, gateway, WireGuard transport, bridge, dashboard, or tests.

For deployment instructions, supported configuration, manifests, tuning, and
operator-visible behavior, use the
[public Kubernetes Enrollment guide](https://clawpatrol.dev/docs/kubernetes-enrollment/)
and the examples under [`examples/kubernetes/`](../examples/kubernetes/).

## Scope and invariants

- Enrollment currently provisions only WireGuard peers.
- The gateway and enrolled workloads are expected to share a Kubernetes
  cluster.
- One active gateway owns the WireGuard device and peer-address pool.
- The client never submits its profile. The gateway derives it from the live
  Pod and the configured allowlist.
- The agent container never receives the projected ServiceAccount token,
  WireGuard private key, or peer API token.
- Reaping is limited to peers explicitly marked as enrolled; normally
  onboarded devices are never reaped.
- Registration, replacement, cleanup, and reaping serialize through the
  gateway enrollment lock.

## Configuration model

The in-tree `kubernetes_token_review` enrollment plugin is registered as
`KindEnrollment` in
[`internal/config/k8s_enrollment.go`](../internal/config/k8s_enrollment.go).
Its build output contains:

- the TokenReview audience,
- one or more namespace and ServiceAccount match rules,
- the Pod label used to select a profile,
- the profile allowlist, and
- raw keepalive and reap settings.

Validation requires an audience, at least one complete match, and declared
profiles. Gateway-level validation also requires a `wireguard` block whenever
an enrollment block exists.

[`internal/config/k8s_compile.go`](../internal/config/k8s_compile.go) lowers
the plugin body into `CompiledK8sEnrollment` and indexes authorizers by
instance name. Keepalive settings are compiled separately into the common
`EnrollmentLivenessByName` map so registration and reaping do not need a
Kubernetes-specific type switch.

[`internal/config/enrollment_liveness.go`](../internal/config/enrollment_liveness.go)
owns the shared defaults and validation:

- default keepalive: 25 seconds,
- minimum keepalive: 10 seconds,
- default reap count: 3,
- minimum non-zero reap count: 2, and
- reap count 0: reaping and client liveness recovery disabled.

The liveness window is always derived as keepalive multiplied by reap count.

## Registration and authorization

The bridge gathers claims from the Downward API and reads the projected
ServiceAccount token in
[`cmd/clawpatrol/enrollment_client.go`](../cmd/clawpatrol/enrollment_client.go).
It sends:

- transport and authorizer name,
- its newly generated WireGuard public key,
- Pod name, namespace, UID, and node name, and
- a request for the authorizer's resolved liveness settings.

The registration handler and Kubernetes authorizer live in
[`cmd/clawpatrol/enrollment.go`](../cmd/clawpatrol/enrollment.go). Authorization
is fail-closed:

1. Resolve the named authorizer from the compiled policy.
2. Submit the projected token to Kubernetes TokenReview with the configured
   audience.
3. Require the TokenReview response to include that audience and the bound Pod
   name and UID.
4. Require a `system:serviceaccount:<namespace>:<name>` identity.
5. Require the token namespace and bound Pod identity to match the submitted
   claims.
6. Read the live Pod with the gateway ServiceAccount.
7. Require the live Pod UID and ServiceAccount to match the verified token.
8. Read the configured profile label from the live Pod.
9. Require that profile to appear in the matching rule's allowlist and in the
   compiled policy.

The normalized identity uses:

- subject key: `kubernetes:<namespace>:<pod UID>`,
- replacement key: `kubernetes:<namespace>:<pod name>`,
- display name: `<namespace>/<pod name>`, and
- owner: `system:serviceaccount:<namespace>:<service account>`.

The subject key identifies one Pod instance. The replacement key identifies
the logical workload name across Pod recreation.

## Peer allocation and persistence

Enrollment and dashboard onboarding share one allocator. A process-wide mutex
holds address selection, WireGuard programming, and `wg_peers` persistence in
one critical section so concurrent callers cannot claim the same address.

The allocator reads all addresses in `wg_peers`, walks the configured IPv4
subnet from the first client address, and skips:

- the network address,
- the gateway address at offset 1, and
- the broadcast address.

The first unused address is returned. A database read failure must not be
treated as an empty allocation set; doing so can select an occupied address
and displace its peer.

Registration handles existing peers as follows:

- **Same subject, new public key:** Reuse the existing IP and replace the
  transport key.
- **Same replacement key, new subject:** Retire the old Pod instance before
  provisioning the replacement.
- **Same public key, different subject:** Reject with a conflict.
- **No match:** Allocate the next free address.

`WGServer.AddPeer` installs the public key and IPv4/IPv6 allowed addresses in
wireguard-go and persists `(pubkey, ip, added_ns)` in `wg_peers`. Migration
[`0020_wg_peer_enrollment.sql`](../cmd/clawpatrol/migrations/sqlite/0020_wg_peer_enrollment.sql)
adds the enrollment marker, identity keys, display metadata, profile,
authorizer, and arbitrary metadata to that row.

After the peer is installed, registration rotates its peer API token, stamps
the enrollment metadata, seeds the device/agent registries, and returns the
client configuration and CA bundle. Any failure before the enrollment row is
committed rolls back the transport peer and token.

## Gateway liveness and reaping

The bridge is the only persistent-keepalive sender. The gateway deliberately
does not keepalive back: wireguard-go rearms a peer's keepalive timer after
authenticated traffic in either direction. If both peers send keepalives,
one direction can continually postpone the other and make receive progress an
ambiguous liveness signal.

The gateway reaper:

1. samples WireGuard peer receive counters every 20 seconds,
2. seeds a new or restored peer with a full grace window,
3. advances `lastProgress` whenever its receive counter increases, and
4. revokes an enrolled peer once receive progress has been quiet longer than
   its authorizer's derived liveness window.

The in-memory tracker is keyed by WireGuard public key. Reap count 0 produces
a zero window and is never reaped. If a persisted peer's authorizer no longer
exists in the compiled policy, the reaper uses a 75-second fallback so
orphaned peers still drain.

Cleanup removes the WireGuard peer, database row, peer API tokens, device
ownership/profile entry, agent registry entry, and liveness tracker.

## Bridge recovery and fail-closed routing

The Linux implementation is in
[`cmd/clawpatrol/bridge_linux.go`](../cmd/clawpatrol/bridge_linux.go) and
[`cmd/clawpatrol/bridge_watchdog.go`](../cmd/clawpatrol/bridge_watchdog.go).

Before replacing the Pod's default route, the bridge:

- discovers the original IPv4 route and optional IPv6 route,
- resolves the gateway API and WireGuard endpoint,
- reads the current DNS resolvers, and
- pins those control-plane destinations to the underlay using route protocol
  111 by default.

The pinned routes keep enrollment, DNS, and the WireGuard handshake reachable
after all normal Pod traffic is default-routed through the TUN device.

The bridge watchdog samples its receive counter every 5 seconds. Because an
idle tunnel may have no inbound traffic, receive silence alone is not treated
as failure. After one keepalive interval of silence, the watchdog probes the
gateway's tunnel address:

- successful traffic or a successful probe resets the failure count,
- `--local-reset-missed` failed probes rebuild the peer configuration in
  place, and
- failures reaching the server-provided reap count close the session and
  trigger in-process re-enrollment.

Re-enrollment creates a new keypair and registration but keeps the IP for the
same authenticated subject. The bridge re-reads resolver and underlay state on
each attempt and reconciles its tagged routes.

The process does not exit during recovery. Closing the TUN removes the Pod's
default route, so general egress fails closed until the next session is ready.
The environment, CA, and ready handoff are written only after the first
successful bring-up; subsequent sessions reuse the same workload handoff.

On SIGTERM, the bridge performs a bounded best-effort deregistration before
closing the session.

## Restart and policy reload

`WGServer.loadPeers` restores persisted WireGuard peers when the gateway
starts. `reconcileEnrolledPeers` then restores their profile, owner, hostname,
agent registry entry, and a fresh liveness grace window.

The reaper starts whenever the WireGuard server starts, even if enrollment is
currently absent from the policy. This allows persisted enrolled peers to
drain after enrollment is removed or temporarily disabled.

Registration resolves the authorizer and liveness settings from the current
compiled policy, so config reloads affect new registrations immediately.
Existing peers use their stored authorizer name to resolve the current
liveness settings on each reap cycle.

## Dashboard data path

`listEnrolledPeerViews` joins persisted enrollment metadata with current
WireGuard stats and the reaper's in-memory liveness snapshot. The view is
included in `/api/state` as `enrolled_peers`.

The dashboard joins an enrolled peer to its existing Agent entry by peer IP.
It then:

- replaces profile editing with the server-assigned profile,
- hides manual deletion,
- renders authorizer and subject metadata, and
- derives the liveness window and missed-interval display from the returned
  keepalive, reap count, and last receive-progress time.

The dedicated dashboard endpoint `/api/enrollment/peers` exposes the same
operator view.

## Tests

Focused unit coverage lives in:

- [`enrollment_test.go`](../cmd/clawpatrol/enrollment_test.go): registration,
  replacement, rollback, reaping, reconciliation, and HTTP guards;
- [`k8s_registration_test.go`](../cmd/clawpatrol/k8s_registration_test.go):
  key normalization, ServiceAccount matching, profile allowlists, identity,
  and cleanup;
- [`enrollment_client_test.go`](../cmd/clawpatrol/enrollment_client_test.go):
  request/response and claim gathering;
- [`bridge_test.go`](../cmd/clawpatrol/bridge_test.go): bridge flag and
  authorizer parsing;
- [`bridge_watchdog_test.go`](../cmd/clawpatrol/bridge_watchdog_test.go): receive
  progress, probes, escalation, and disabled recovery; and
- [`internal/config/compile_test.go`](../internal/config/compile_test.go):
  enrollment validation and liveness compilation.

The kind-based
[`kubernetes-wireguard-e2e.sh`](../e2e/kubernetes-wireguard-e2e.sh) validates
the explicit Pod contract, tunneled traffic, liveness, in-process recovery,
fail-closed routing, and cleanup.
