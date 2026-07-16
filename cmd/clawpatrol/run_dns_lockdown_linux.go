//go:build linux

package main

// DNS lockdown for the `clawpatrol run` child namespace.
//
// Tunnel-backed endpoints (kubernetes_port_forward, local_command,
// postgres) are reachable ONLY via DNS-VIP interception: the compiler
// excludes them from real-IP routing (internal/config/runtime/
// conn_route.go), so a name lookup answered by the host resolver
// returns the raw upstream IP and the connection black-holes at the
// gateway's relay-verbatim branch. The child's DNS therefore must
// always be answered by the gateway's dnsvip allocator (#765).
//
// glibc can leak a lookup past the bind-mounted resolv.conf in three
// ways, each closed by one layer here:
//
//   - the `dns` module reading the host resolv.conf
//     → bind-mount a gateway-pointing resolv.conf (fatal on failure);
//   - the `resolve` / `mdns*` modules answering ahead of `dns` —
//     nss-resolve talks to host systemd-resolved over the varlink
//     socket /run/systemd/resolve/io.systemd.Resolve, which the mnt
//     namespace does NOT hide
//     → bind-mount a sanitized nsswitch.conf (fatal on failure) AND
//       mask that socket with an empty regular file, so even a
//       stale/racing nsswitch cannot reach the host resolver
//       (connect(2) on a regular file fails ENOTSOCK, the module
//       reports unavailable, and the lookup falls through to `dns`).
//       Only the socket is masked — never the directory: on Ubuntu
//       /etc/resolv.conf is a symlink to stub-resolv.conf in that
//       same directory, and hiding the directory behind a tmpfs
//       would sever the symlink and break resolution outright;
//   - the `files` module reading the host /etc/hosts, where a stray
//     entry for a tunneled name yields a literal IP
//     → bind-mount a minimal synthetic /etc/hosts.
//
// Queries that do reach the TUN are safe regardless of resolver IP:
// both gateway transports intercept UDP/53 to any destination (WG
// promiscuous forwarder; tsnet GetUDPHandlerForFlow catch-all).
//
// CLAWPATROL_RUN_KEEP_RESOLV=1 is the single escape hatch: it skips
// every layer above, restoring host DNS behavior (and with it the
// unreachability of tunnel-backed endpoints).
//
// Residual, accepted: nss-resolve's D-Bus fallback rides
// /run/dbus/system_bus_socket, which stays reachable (masking the
// system bus would break far too much) — it only matters if the
// now-fatal nsswitch rewrite was somehow bypassed. Likewise a
// varlink socket created *after* the namespace is set up (resolved
// restarting mid-run) is not masked; the sanitized nsswitch never
// consults it.
//
// The planner (computeDNSLockdown) is pure so the per-distro matrix is
// unit-testable; applyDNSLockdown performs the mounts.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// etcOverride is one file bind-mounted over its target in the child's
// mount namespace via bindOverEtc.
type etcOverride struct {
	Target  string // absolute path to mount over, e.g. /etc/resolv.conf
	Pattern string // temp-file pattern handed to os.CreateTemp
	Body    string
}

// dnsLockdown is the mount plan for the child namespace.
type dnsLockdown struct {
	Overrides []etcOverride
	Masks     []string // paths hidden behind an empty regular file
}

// dnsLockdownInputs is everything computeDNSLockdown needs from the
// environment, gathered up front so the planner stays pure.
type dnsLockdownInputs struct {
	KeepResolv          bool   // CLAWPATROL_RUN_KEEP_RESOLV=1
	ResolvBody          string // childResolvConf()
	NsswitchRaw         string // /etc/nsswitch.conf contents ("" on error)
	NsswitchErr         error  // nil | fs.ErrNotExist (musl) | other (fatal)
	HostsExists         bool   // /etc/hosts present
	Hostname            string // os.Hostname(), "" if unknown
	VarlinkSocketExists bool   // resolvedVarlinkSocket present
}

// resolvedVarlinkSocket is where nss-resolve reaches the host's
// systemd-resolved.
const resolvedVarlinkSocket = "/run/systemd/resolve/io.systemd.Resolve"

// minimalHostsFile is the synthetic /etc/hosts the child sees: just
// loopback plus the machine's own name (Debian's 127.0.1.1
// convention, keeps sudo and self-lookups working). Host-local
// entries are deliberately absent — the client can't know which names
// the policy tunnels, so any host entry could shadow a VIP.
func minimalHostsFile(hostname string) string {
	body := "127.0.0.1 localhost\n" +
		"::1 localhost ip6-localhost ip6-loopback\n"
	if hostname != "" {
		body += "127.0.1.1 " + hostname + "\n"
	}
	return body
}

// computeDNSLockdown builds the mount plan for the child namespace.
// A missing nsswitch.conf is normal (musl/Alpine has no NSS;
// getaddrinfo reads resolv.conf directly); any other read error is
// fatal, since it likely leaves a host-resolver short-circuit in
// place and would otherwise become a silent black hole for
// tunnel-backed endpoints.
func computeDNSLockdown(in dnsLockdownInputs) (dnsLockdown, error) {
	if in.KeepResolv {
		return dnsLockdown{}, nil
	}
	var plan dnsLockdown
	plan.Overrides = append(plan.Overrides, etcOverride{
		Target:  "/etc/resolv.conf",
		Pattern: "clawpatrol-resolv-*",
		Body:    in.ResolvBody,
	})
	if in.NsswitchErr != nil {
		if !errors.Is(in.NsswitchErr, fs.ErrNotExist) {
			return dnsLockdown{}, fmt.Errorf("read /etc/nsswitch.conf: %w", in.NsswitchErr)
		}
	} else if body, changed := rewriteHostsLine(in.NsswitchRaw); changed {
		plan.Overrides = append(plan.Overrides, etcOverride{
			Target:  "/etc/nsswitch.conf",
			Pattern: "clawpatrol-nsswitch-*",
			Body:    body,
		})
	}
	if in.HostsExists {
		plan.Overrides = append(plan.Overrides, etcOverride{
			Target:  "/etc/hosts",
			Pattern: "clawpatrol-hosts-*",
			Body:    minimalHostsFile(in.Hostname),
		})
	}
	if in.VarlinkSocketExists {
		plan.Masks = append(plan.Masks, resolvedVarlinkSocket)
	}
	return plan, nil
}

// gatherDNSLockdownInputs collects the planner's inputs from the
// child's view of the filesystem (pre-mount, so it sees host state).
func gatherDNSLockdownInputs() dnsLockdownInputs {
	raw, err := os.ReadFile("/etc/nsswitch.conf")
	hostname, _ := os.Hostname()
	_, hostsErr := os.Stat("/etc/hosts")
	_, sockErr := os.Stat(resolvedVarlinkSocket)
	return dnsLockdownInputs{
		KeepResolv:          os.Getenv("CLAWPATROL_RUN_KEEP_RESOLV") == "1",
		ResolvBody:          childResolvConf(),
		NsswitchRaw:         string(raw),
		NsswitchErr:         err,
		HostsExists:         hostsErr == nil,
		Hostname:            hostname,
		VarlinkSocketExists: sockErr == nil,
	}
}

// applyDNSLockdown performs the plan's mounts in the calling mount
// namespace. Any failure is returned to the caller, which aborts the
// run: a partially applied plan can leave a resolver leak open, and
// for tunnel-backed endpoints a leaked lookup is indistinguishable
// from a hung connection. Masks reuse bindOverEtc with an empty body
// — a bind-mount only requires the directory-ness of source and
// target to match, so an empty regular file cleanly shadows a unix
// socket.
func applyDNSLockdown(plan dnsLockdown) error {
	for _, o := range plan.Overrides {
		if err := bindOverEtc(o.Target, o.Pattern, o.Body); err != nil {
			return err
		}
	}
	for _, m := range plan.Masks {
		if err := bindOverEtc(m, "clawpatrol-mask-*", ""); err != nil {
			return err
		}
	}
	return nil
}
