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
// glibc can leak a lookup past the bind-mounted resolv.conf in four
// ways, each closed by one layer here:
//
//   - the `dns` module reading the host resolv.conf
//     → bind-mount a gateway-pointing resolv.conf (fatal on failure);
//   - nscd: getaddrinfo tries __nscd_getai over /var/run/nscd/socket
//     BEFORE traversing the `hosts:` NSS chain at all, so a host
//     nscd/unscd with hosts caching enabled can hand back a cached
//     raw address (or NXDOMAIN) no matter what the other layers say
//     → hide the whole nscd runtime directory behind an empty
//       read-only tmpfs (not just the socket file: the directory
//       mask also swallows a socket re-created mid-run by a
//       restarting daemon, and unlike /run/systemd/resolve nothing
//       else references paths inside it);
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
// Every lockdown mount is remounted read-only (bindOverEtc →
// remountReadOnly; the tmpfs dir masks are born read-only): the
// wrapped command runs as the same uid that owns the bind-mount
// source inodes, so a writable mount would let it overwrite
// /etc/resolv.conf after setup and undo the whole lockdown. It also
// cannot unmount them — its ambient caps are cleared before exec,
// and mounts inherited into any namespace it creates for itself are
// kernel-locked (MNT_LOCK).
//
// Residual, accepted: nss-resolve's D-Bus fallback rides
// /run/dbus/system_bus_socket, which stays reachable (masking the
// system bus would break far too much) — it only matters if the
// now-fatal nsswitch rewrite was somehow bypassed. Likewise a
// varlink socket created *after* the namespace is set up (resolved
// restarting mid-run) is not masked; the sanitized nsswitch never
// consults it. And if NO nscd runtime directory exists at setup
// (nscd installed but stopped), a daemon started mid-run creates
// /run/nscd in the shared /run and the child will see it — there is
// no path to mount over up front, and the unprivileged child cannot
// create one in the host-owned /run. The directory mask closes the
// mid-run window only for the common case where nscd is already
// running (its directory exists) at setup.
//
// The planner (computeDNSLockdown) is pure so the per-distro matrix is
// unit-testable; applyDNSLockdown performs the mounts.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
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
	Masks     []string // paths hidden behind an empty read-only regular file
	DirMasks  []string // directories hidden behind an empty read-only tmpfs
}

// dnsLockdownInputs is everything computeDNSLockdown needs from the
// environment, gathered up front so the planner stays pure.
type dnsLockdownInputs struct {
	KeepResolv          bool     // CLAWPATROL_RUN_KEEP_RESOLV=1
	ResolvBody          string   // childResolvConf()
	NsswitchRaw         string   // /etc/nsswitch.conf contents ("" on error)
	NsswitchErr         error    // nil | fs.ErrNotExist (musl) | other (fatal)
	HostsExists         bool     // /etc/hosts present
	Hostname            string   // os.Hostname(), "" if unknown
	VarlinkSocketExists bool     // resolvedVarlinkSocket present
	NscdDirsPresent     []string // subset of nscdDirPaths that exist
}

// resolvedVarlinkSocket is where nss-resolve reaches the host's
// systemd-resolved.
const resolvedVarlinkSocket = "/run/systemd/resolve/io.systemd.Resolve"

// nscdDirPaths are the locations of the name service cache daemon's
// runtime directory (its socket lives directly inside). glibc's
// compiled-in _PATH_NSCDSOCKET is under the /var/run spelling; on
// modern distros /var/run is a symlink to /run, so both usually name
// the same directory — masking both just stacks a second identical
// mount, which is harmless, and covers the odd host where they
// differ.
var nscdDirPaths = []string{
	"/run/nscd",
	"/var/run/nscd",
}

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
	} else if body, changed := rewriteHostsLines(in.NsswitchRaw); changed {
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
	// nscd is consulted before the NSS chain even runs, so no
	// nsswitch rewrite can help — its runtime directory must go dark
	// wholesale, so that even a socket re-created mid-run by a
	// restarting daemon stays invisible.
	plan.DirMasks = append(plan.DirMasks, in.NscdDirsPresent...)
	return plan, nil
}

// classifyStatErr maps a stat result to presence for lockdown
// discovery. Only a definite "does not exist" (ENOENT, or ENOTDIR on
// a missing parent) counts as absent; any other failure — EPERM from
// a hardened /run, EIO, … — is returned as fatal, because "couldn't
// check" is indistinguishable from "leak path present" and silently
// skipping a mask would fail open (#765).
func classifyStatErr(path string, err error) (present bool, fatal error) {
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR):
		return false, nil
	default:
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
}

// statPresence is classifyStatErr over a live os.Stat.
func statPresence(path string) (bool, error) {
	_, err := os.Stat(path)
	return classifyStatErr(path, err)
}

// gatherDNSLockdownInputs collects the planner's inputs from the
// child's view of the filesystem (pre-mount, so it sees host state).
// Discovery is fail-closed: an unexpected stat failure aborts rather
// than silently dropping a mask from the plan.
func gatherDNSLockdownInputs() (dnsLockdownInputs, error) {
	if os.Getenv("CLAWPATROL_RUN_KEEP_RESOLV") == "1" {
		// The escape hatch must win even on hosts where discovery
		// itself fails (an unreadable /run, …) — skip every probe.
		return dnsLockdownInputs{KeepResolv: true}, nil
	}
	raw, err := os.ReadFile("/etc/nsswitch.conf")
	hostname, _ := os.Hostname()
	hostsExists, herr := statPresence("/etc/hosts")
	if herr != nil {
		return dnsLockdownInputs{}, herr
	}
	varlinkExists, verr := statPresence(resolvedVarlinkSocket)
	if verr != nil {
		return dnsLockdownInputs{}, verr
	}
	var nscdDirs []string
	for _, p := range nscdDirPaths {
		present, perr := statPresence(p)
		if perr != nil {
			return dnsLockdownInputs{}, perr
		}
		if present {
			nscdDirs = append(nscdDirs, p)
		}
	}
	return dnsLockdownInputs{
		ResolvBody:          childResolvConf(),
		NsswitchRaw:         string(raw),
		NsswitchErr:         err,
		HostsExists:         hostsExists,
		Hostname:            hostname,
		VarlinkSocketExists: varlinkExists,
		NscdDirsPresent:     nscdDirs,
	}, nil
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
	for _, d := range plan.DirMasks {
		if err := maskDirReadOnly(d); err != nil {
			return err
		}
	}
	return nil
}

// maskDirReadOnly hides dir behind a fresh, empty, read-only tmpfs.
// Everything under the host path becomes invisible to the child —
// including entries created on the host AFTER the mount (a daemon
// re-creating its socket lands in the host directory, not in the
// tmpfs shadowing it). Read-only from birth so the wrapped command
// (same uid) can't populate the shadow either.
func maskDirReadOnly(dir string) error {
	flags := uintptr(unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("none", dir, "tmpfs", flags, "size=4k,mode=0555"); err != nil {
		return fmt.Errorf("mask directory %s: %w", dir, err)
	}
	return nil
}
