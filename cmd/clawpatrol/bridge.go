package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// kubernetesDefaultTokenPath is the projected ServiceAccount token the
// kubernetes_token_review provider presents by default.
const kubernetesDefaultTokenPath = "/var/run/secrets/tokens/clawpatrol-token"

// bridgeOptions configures `clawpatrol bridge`: a resident, foreground,
// privileged data plane that self-enrolls through an authorizer, hosts a
// userspace WireGuard tunnel, and routes the whole network namespace through
// the gateway — bridging the netns to the gateway. It stays up for the netns
// lifetime (the userspace device dies with the process) and deregisters
// best-effort on SIGTERM. The execution workload runs in a sibling,
// unprivileged container that shares this netns and reads the handoff files
// below.
type bridgeOptions struct {
	GatewayURL string

	// AuthorizerType/Name mirror the gateway's two-label enrollment block
	// `enrollment "<type>" "<name>"`. Type selects the client-side claims
	// provider (how identity is gathered); Name is what's sent on the wire
	// to pick the server authorizer.
	AuthorizerType string
	AuthorizerName string

	// KubeTokenPath is the kubernetes_token_review provider's credential.
	// Provider-scoped on purpose — not every authorizer authenticates with
	// a token file.
	KubeTokenPath string

	// Sibling-handoff outputs: files the unprivileged workload container
	// reads off the shared volume once the tunnel is up.
	EnvOut    string
	CAOut     string
	ReadyFile string

	Iface string
	MTU   int

	// LocalResetMisses is how many missed keepalives trigger an in-place
	// tunnel rebuild before the server-dictated reconnect horizon. A
	// client-side knob — the reap horizon comes from the gateway, but how
	// eagerly to attempt a cheap local recovery first is the sidecar's call.
	// Capped below the reconnect horizon; 0 disables the local rebuild.
	LocalResetMisses int

	// RouteProto is the rt_proto tag stamped on the underlay routes the bridge
	// installs in its routing table. Escape hatch: override only if the
	// default collides with a route protocol another component already uses
	// in the netns.
	RouteProto string

	// FWMark is the socket mark on the bridge's own control-plane traffic, and
	// the ID of the routing table that holds the underlay default route (see
	// bridge_route.go).
	FWMark int

	// EgressFilter loads the nftables output filter (bridge_nft_linux.go).
	// Off is an escape hatch for runtimes without nf_tables.
	EgressFilter bool
}

// defaultRouteProto is the rt_proto the bridge tags its underlay routes with
// by default (overridable via --route-proto). Arbitrary and unregistered; it
// only has to be stable and unlikely to collide with the CNI's own routes.
const defaultRouteProto = "111"

// runBridge parses the `clawpatrol bridge` flags and dispatches to the
// platform implementation. Kept cross-platform (no wireguard imports) so
// the flag surface and validation errors are identical everywhere; bridgeRun
// is linux-only.
func runBridge(args []string) {
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	var (
		authorizer string
		opt        bridgeOptions
	)
	fs.StringVar(&opt.GatewayURL, "gateway-url", "", "gateway API URL, e.g. https://clawpatrol.clawpatrol.svc:8443")
	fs.StringVar(&authorizer, "authorizer", "", "enrollment authorizer to register through, as <type>/<name> (e.g. kubernetes_token_review/agents)")
	fs.StringVar(&opt.KubeTokenPath, "kubernetes-token-path", kubernetesDefaultTokenPath, "kubernetes_token_review: projected ServiceAccount token path")
	fs.StringVar(&opt.EnvOut, "env-out", "/clawpatrol/env", "path to write shell exports for the workload container")
	fs.StringVar(&opt.CAOut, "ca-out", "/clawpatrol/ca.crt", "path to write the gateway CA bundle")
	fs.StringVar(&opt.ReadyFile, "ready-file", "/clawpatrol/ready", "path to touch after network and env setup succeed")
	fs.StringVar(&opt.Iface, "iface", "clawpatrol0", "TUN interface name")
	fs.IntVar(&opt.MTU, "mtu", enrollmentDefaultMTU, "TUN MTU")
	fs.IntVar(&opt.LocalResetMisses, "local-reset-missed", bridgeWatchdogDefaultResetMisses,
		"missed keepalives before an in-place tunnel rebuild; 0 disables it, and a value at or above the gateway's reconnect threshold skips directly to re-enrollment")
	fs.StringVar(&opt.RouteProto, "route-proto", defaultRouteProto,
		"rt_proto tag for the underlay routes in the bridge's routing table; override only if it collides with another component's routes")
	egressFilter := fs.String("egress-filter", "on",
		"on: load an nftables filter that lets pod traffic leave only through the tunnel, and bring-up fails if it cannot load; off: skip it")
	fs.IntVar(&opt.FWMark, "fwmark", defaultBridgeFwmark,
		"socket mark for the bridge's own gateway, DNS, and WireGuard traffic, and the ID of the routing table that sends it to the underlay")
	_ = fs.Parse(args)

	if len(fs.Args()) > 0 {
		fail("clawpatrol bridge does not take a command; the workload runs in a sibling container sharing this netns")
	}
	if strings.TrimSpace(opt.GatewayURL) == "" {
		fail("clawpatrol bridge: --gateway-url is required")
	}
	if err := validateRouteProto(opt.RouteProto); err != nil {
		fail("clawpatrol bridge: %v", err)
	}
	if err := validateBridgeFwmark(opt.FWMark); err != nil {
		fail("clawpatrol bridge: %v", err)
	}
	switch *egressFilter {
	case "on":
		opt.EgressFilter = true
	case "off":
	default:
		fail("clawpatrol bridge: --egress-filter must be on or off, got %q", *egressFilter)
	}
	if gatewayURLIsPlaintext(opt.GatewayURL) {
		log.Printf("bridge: WARNING: --gateway-url %s is plain HTTP; the ServiceAccount token and the peer API token cross the network unencrypted. Use the gateway's public_url behind TLS.", opt.GatewayURL)
	}
	typ, name, err := parseBridgeAuthorizer(authorizer)
	if err != nil {
		fail("%v", err)
	}
	opt.AuthorizerType, opt.AuthorizerName = typ, name

	if err := bridgeRun(context.Background(), opt); err != nil {
		log.Printf("bridge: %v", err)
		os.Exit(1)
	}
}

// preferV4 returns the first IPv4 address (unmapped), falling back to the
// first address of any family when there is no IPv4. The IPv4 underlay route
// is always present, and the gateway WireGuard endpoint is reached over IPv4
// in typical clusters; the IPv6 underlay is optional.
func preferV4(ips []netip.Addr) (netip.Addr, bool) {
	if len(ips) == 0 {
		return netip.Addr{}, false
	}
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			return ip.Unmap(), true
		}
	}
	return ips[0].Unmap(), true
}

// validateRouteProto checks the --route-proto value. iproute2 accepts either
// a numeric rt_proto (1–255) or a name defined in /etc/iproute2/rt_protos; we
// only reject the clearly invalid cases (empty, or a number out of range) and
// leave name resolution to `ip` at runtime.
func validateRouteProto(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("--route-proto must not be empty")
	}
	if n, err := strconv.Atoi(p); err == nil && (n < 1 || n > 255) {
		return fmt.Errorf("--route-proto %q must be in 1..255 (or an rt_protos name)", p)
	}
	return nil
}

// gatewayURLIsPlaintext reports whether the bridge would send its credentials
// to the gateway without TLS.
func gatewayURLIsPlaintext(gatewayURL string) bool {
	u, err := url.Parse(strings.TrimSpace(gatewayURL))
	return err == nil && strings.EqualFold(u.Scheme, "http")
}

// parseBridgeAuthorizer splits the `--authorizer <type>/<name>` value,
// mirroring the gateway's `enrollment "<type>" "<name>"` block. The type
// selects the client claims provider; the name is sent on the wire.
func parseBridgeAuthorizer(s string) (typ, name string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("--authorizer is required (form: <type>/<name>, e.g. kubernetes_token_review/agents)")
	}
	typ, name, ok := strings.Cut(s, "/")
	typ, name = strings.TrimSpace(typ), strings.TrimSpace(name)
	if !ok || typ == "" || name == "" {
		return "", "", fmt.Errorf("--authorizer %q must be <type>/<name>, e.g. kubernetes_token_review/agents", s)
	}
	if typ != enrollmentAuthorizerKubernetesTokenRev {
		return "", "", fmt.Errorf("unsupported authorizer type %q (supported: %s)", typ, enrollmentAuthorizerKubernetesTokenRev)
	}
	return typ, name, nil
}
