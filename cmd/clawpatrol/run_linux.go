//go:build linux

package main

// `clawpatrol run -- <cmd> [args...]` — route a single process tree's
// traffic through the gateway, leave the rest of the machine alone.
//
// The parent process is a thin client to the per-host `clawpatrol
// daemon` (see daemon_linux.go), which owns one shared network
// identity for the host (tsnet peer or WireGuard peer, depending on
// `clawpatrol join` mode). Every concurrent run multiplexes through
// the daemon — no per-process WG keys, no per-process tsnet nodes.
//
// Flow:
//  1. Connect to (or spawn) the daemon via its Unix control socket.
//  2. Ask it to START a session — the daemon replies with its
//     underlay address (ADDR frame) and the env-pushdown JSON. Both
//     are applied locally before the child execs.
//  3. Child in a new user+net+mnt ns creates the TUN, sends fd via
//     SCM_RIGHTS to the parent.
//  4. Parent forwards that TUN fd to the daemon (again via SCM_RIGHTS)
//     on the same control conn.
//  5. Daemon attaches the TUN to a per-session gVisor stack and TCP
//     forwarder; replies ATTACHED.
//  6. Parent signals the child; child brings up its tun + execs the
//     agent. The agent's outbound traffic flows TUN → daemon's
//     gVisor → daemon's transport (tsnet exit-node or wg netstack).
//  7. On child exit the parent closes the control conn; the daemon
//     tears down the session.
//
// Capability model — mirrors ../unclaw/native/napi/src/client_linux/netns.rs:
//   - child holds CAP_NET_ADMIN when calling TUNSETIFF (via ambient, survives exec)
//   - ip subprocesses inherit CAP_NET_ADMIN (ambient propagates through exec chain)
//   - user's final command does NOT hold CAP_NET_ADMIN (ambient cleared before exec)
//
// Implementation: re-exec self with CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS +
// AmbientCaps=[CAP_NET_ADMIN]. Go's forkAndExecInChild raises ambient before
// the exec, so the re-exec'd child has CAP_NET_ADMIN in effective from the
// start — no exec has cleared it yet when TUNSETIFF runs.

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	runChildEnv        = "CLAWPATROL_RUN_CHILD"
	runNoAutoExposeEnv = "CLAWPATROL_RUN_NO_AUTO_EXPOSE"
	// runTunAddrEnv is the CIDR-less IP the child binds to its TUN
	// inside the netns. Set by the parent from the daemon's ADDR
	// reply; emitted into the child's environment so the child
	// netns can configure `ip addr add` without round-tripping
	// the value through the SCM_RIGHTS conn.
	runTunAddrEnv = "CLAWPATROL_TUN_ADDR"
	// runDropUIDEnv / runDropGIDEnv are set by the privileged (sudo)
	// parent (run_sudo_linux.go) to tell runRunChild to drop from root
	// to the invoking user before exec'ing the command. Absent on the
	// unprivileged userns path, where the child already runs as the user.
	runDropUIDEnv = "CLAWPATROL_RUN_DROP_UID"
	runDropGIDEnv = "CLAWPATROL_RUN_DROP_GID"
	tunIfName     = "wg0"
	// runTunMTU is the TUN MTU inside the child's netns. Set to the
	// max IPv4 packet size — the daemon's transport handles real
	// path-MTU + fragmentation behind us.
	runTunMTU = 65535
)

// runRun is `clawpatrol run`. Re-execs self in new user+net+mnt
// namespaces with CAP_NET_ADMIN in the ambient set, hands the TUN fd
// to the per-host daemon, and execs the user's cmd inside the child.
func runRun(args []string) {
	if os.Getenv(runChildEnv) == "1" {
		runRunChild()
		return
	}

	warnIfOnGatewayHost()

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	noAutoExpose := fs.Bool("no-auto-expose", false, "disable the seccomp relay (mirrors TCP listeners inside the netns back to the host AND forwards wrapped-cmd connections to 127.0.0.1 out to host loopback services)")
	_ = fs.Parse(args)
	cmd := fs.Args()
	if len(cmd) == 0 {
		fail("usage: clawpatrol run [--no-auto-expose] -- <cmd> [args...]")
	}

	// Whole-machine join: the host already routes all traffic through
	// the gateway, so there's no per-process daemon/sandbox. Inject the
	// credential env and exec the command directly (this also works as
	// root, unlike the unprivileged-userns path below).
	if isWholeMachineJoin() {
		runWholeMachineDirect(cmd)
		return
	}

	// With passwordless sudo we can set the netns up as real root
	// instead of an unprivileged user namespace, so the wrapped command
	// keeps real uids and `sudo` works inside it. Opt out with
	// CLAWPATROL_NO_SUDO.
	if sudoSetupAvailable() {
		runViaSudo(cmd)
		return
	}

	if os.Geteuid() == 0 {
		fail("run as your normal user; clawpatrol run uses unprivileged user namespaces which root cannot enter on this distro")
	}
	if *noAutoExpose {
		_ = os.Setenv(runNoAutoExposeEnv, "1")
	}
	autoExpose := os.Getenv(runNoAutoExposeEnv) != "1"

	checkUserNS()

	// 1. Open a control conn to the per-host daemon, spawning one if
	// none is alive. Hello handshake happens inside daemonConnect.
	ctrl, err := daemonConnect()
	if err != nil {
		fail("daemon connect: %v\n  (if this machine was joined with --whole-machine, run the command directly — `clawpatrol run` isn't needed; traffic already routes through the gateway)", err)
	}
	defer func() { _ = ctrl.Close() }()

	// 2. Ask for a session. Daemon replies with its underlay IP, the
	// cached env-pushdown JSON, and (when applicable) a one-line
	// boot warning — surface that on stderr so operators see the
	// message without tailing the daemon log.
	br, tunAddr, envVars, daemonWarn, err := daemonClientStartSession(ctrl)
	if err != nil {
		fail("daemon START: %v", err)
	}
	if daemonWarn != "" {
		fmt.Fprintf(os.Stderr, "clawpatrol: daemon: %s\n", daemonWarn)
	}
	_ = os.Setenv(runTunAddrEnv, tunAddr.String())

	// envVars from the daemon are only the gateway-fetched push-down
	// vars — the daemon doesn't know the client's filesystem layout,
	// so the CA-bundle vars (SSL_CERT_FILE, NODE_EXTRA_CA_CERTS,
	// REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO, DENO_CERT,
	// PIP_CERT) have to be added here. Without these, the wrapped
	// agent's HTTPS client (python requests, node fetch, etc.) skips
	// our MITM CA, sees the gateway's mint as untrusted, and either
	// fails the handshake or falls back to its own bundle (which
	// doesn't have our CA).
	caPath := filepath.Join(defaultClawpatrolDir(), "ca.crt")
	allVars := append(caPathPushdownVars(caPath), envVars...)
	applyEnvPushdownVars(allVars)
	installClaudeCodeOAuthShim(cmd)

	// 3. IPC channels for the child: TUN fd handoff + tun-up pipe.
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fail("socketpair: %v", err)
	}
	pSock := os.NewFile(uintptr(sp[0]), "parent-sock")
	cSock := os.NewFile(uintptr(sp[1]), "child-sock")
	defer func() { _ = pSock.Close() }()
	tunUpR, tunUpW, err := os.Pipe()
	if err != nil {
		fail("pipe: %v", err)
	}

	// 4. Spawn child in new user+net+mnt namespace.
	self, err := os.Executable()
	if err != nil {
		fail("self path: %v", err)
	}
	child := exec.Command(self, append([]string{"run"}, cmd...)...)
	child.Env = append(os.Environ(), runChildEnv+"=1")
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{cSock, tunUpR}
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		// Map uid→uid (not 0→uid). Inside uid == host uid == non-zero, so
		// the root-exec rule (euid=0 → F(permitted)=all-1s) does NOT apply
		// when the user's command is exec'd. Caps come only from ambient.
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		// CAP_NET_ADMIN: TUNSETIFF + ip interface/route commands.
		// CAP_SYS_ADMIN: bind-mount of resolv.conf inside the mnt namespace.
		// Both are cleared from ambient before the final user exec so the
		// wrapped command inherits nothing.
		AmbientCaps: []uintptr{capNetAdmin, capSysAdmin},
	}
	if err := child.Start(); err != nil {
		if os.Geteuid() == 0 {
			fail("clone: %v\n  hint: run as your normal user", err)
		}
		fail("clone: %v\n  hint: this distro may have unprivileged user namespaces disabled.\n  enable: sudo sysctl -w kernel.unprivileged_userns_clone=1", err)
	}
	// Now that the child has been cloned (which AppArmor's
	// restrict-unprivileged-userns hook would deny if the parent were
	// already non-dumpable), lock the parent down. Closes the
	// /proc/<parent_pid>/{root,mem} bypass on ptrace_scope=0 systems.
	// The child hasn't exec'd the agent yet — it's blocked on tunUpR
	// waiting for our signal — so there's no window for the agent to
	// read parent state before this prctl lands.
	if err := hideParentFromAgent(); err != nil {
		_ = child.Process.Kill()
		fail("PR_SET_DUMPABLE: %v", err)
	}
	_ = cSock.Close()
	_ = tunUpR.Close()

	// 5. Receive TUN fd from child.
	tunFd, err := recvFD(pSock)
	if err != nil {
		_ = child.Process.Kill()
		fail("recv tun fd: %v", err)
	}

	// 6. Hand the TUN fd off to the daemon over the control conn via
	// WriteMsgUnix. Going through .File() + unix.Sendmsg would dup
	// the fd, and on Linux that clears O_NONBLOCK on the underlying
	// file description (shared across dups) — leaving the conn in
	// blocking mode and stranding the runtime poller on the next
	// read. WriteMsgUnix handles SCM_RIGHTS natively, no dup.
	uc, ok := ctrl.(*net.UnixConn)
	if !ok {
		_ = child.Process.Kill()
		fail("control conn: unexpected type %T", ctrl)
	}
	if err := sendFDUnixConn(uc, tunFd); err != nil {
		_ = child.Process.Kill()
		fail("send tun fd to daemon: %v", err)
	}
	_ = unix.Close(tunFd)

	// 7. Wait for ATTACHED.
	if err := daemonClientWaitAttached(ctrl, br); err != nil {
		_ = child.Process.Kill()
		fail("daemon ATTACHED: %v", err)
	}

	// 8. Signal child: bridge is up.
	_, _ = tunUpW.Write([]byte{1})
	_ = tunUpW.Close()

	// 9. Auto-expose relay: pick up the second SCM_RIGHTS message
	// from the child (seccomp notify fd + supervisor sock fd + loopback
	// sup sock fd), fork the supervisor in the host netns. Absence
	// (--no-auto-expose, unsupported arch) is non-fatal.
	var relaySup *exec.Cmd
	if autoExpose {
		if relayFDs, err := recvFDs(pSock, 3); err == nil {
			notifyFile := os.NewFile(uintptr(relayFDs[0]), "seccomp-notify")
			supSock := os.NewFile(uintptr(relayFDs[1]), "relay-sup-sock")
			lbSock := os.NewFile(uintptr(relayFDs[2]), "relay-lb-sock")
			if c, serr := spawnRelaySupervisor(notifyFile, supSock, lbSock); serr != nil {
				fmt.Fprintf(os.Stderr, "warning: auto-expose relay: %v (webhooks won't be reachable from host, host loopback unreachable from wrapped cmd)\n", serr)
			} else {
				relaySup = c
			}
			_ = notifyFile.Close()
			_ = supSock.Close()
			_ = lbSock.Close()
		} else {
			fmt.Fprintf(os.Stderr, "warning: auto-expose relay: no fds from child: %v\n", err)
		}
	}

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigCh {
			_ = child.Process.Signal(s)
		}
	}()

	waitErr := child.Wait()

	if relaySup != nil && relaySup.Process != nil {
		_ = relaySup.Process.Signal(syscall.SIGTERM)
		_, _ = relaySup.Process.Wait()
	}

	// Closing ctrl (via the deferred Close) tears the session down on
	// the daemon side.

	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			os.Exit(ee.ExitCode())
		}
		fail("wait: %v", waitErr)
	}
}

// runWholeMachineDirect handles `clawpatrol run <cmd>` on a
// --whole-machine device. The host already routes all traffic through
// the gateway, so there's no per-process namespace/daemon: just inject
// the credential env and exec the command. Env is fetched straight
// from the gateway — the daemon fetcher would try to spawn the
// per-host daemon, which whole-machine mode doesn't run.
func runWholeMachineDirect(cmd []string) {
	if os.Getenv("CLAWPATROL_NO_ENV") != "1" {
		caDir := defaultClawpatrolDir()
		if vars, err := envPushdownGatewayFetcher(caDir); err == nil {
			applyEnvPushdownVars(vars)
		} else {
			fmt.Fprintf(os.Stderr, "[clawpatrol] env pushdown: %v (continuing without injected credentials)\n", err)
		}
	}
	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		fail("%s: %v", cmd[0], err)
	}
	fmt.Fprintln(os.Stderr, "[clawpatrol] whole-machine join — traffic already routes through the gateway; running directly (no sandbox)")
	if err := syscall.Exec(bin, cmd, os.Environ()); err != nil {
		fail("exec %s: %v", bin, err)
	}
}

// runRunChild executes inside the unshared user+net+mnt namespaces.
// Receives its socket on fd 3 and the tun-up pipe on fd 4. Has
// CAP_NET_ADMIN in effective (via ambient set from parent's
// AmbientCaps).
func runRunChild() {
	cSock := os.NewFile(3, "parent-sock")
	tunUpR := os.NewFile(4, "tun-up")

	argv := os.Args[2:]
	if len(argv) == 0 {
		fail("internal: child got empty argv")
	}

	tunFd, err := openTUN(tunIfName)
	if err != nil {
		fail("open tun: %v", err)
	}
	if err := sendFD(cSock, tunFd); err != nil {
		fail("send tun fd: %v", err)
	}
	_ = unix.Close(tunFd)

	one := make([]byte, 1)
	if _, err := io.ReadFull(tunUpR, one); err != nil {
		fail("wait tun-up: %v", err)
	}
	_ = tunUpR.Close()

	tunAddr := os.Getenv(runTunAddrEnv)
	if tunAddr == "" {
		fail("%s not set", runTunAddrEnv)
	}

	steps := [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "set", tunIfName, "mtu", fmt.Sprintf("%d", runTunMTU), "up"},
		{"ip", "addr", "add", tunAddr + "/32", "dev", tunIfName},
		{"ip", "route", "add", "default", "dev", tunIfName},
	}
	for _, a := range steps {
		c := exec.Command(a[0], a[1:]...)
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			fail("%s: %v", strings.Join(a, " "), err)
		}
	}

	if os.Getenv("CLAWPATROL_RUN_KEEP_RESOLV") != "1" {
		_ = bindResolv(childResolvConf())
		if body, changed := childNsswitch(); changed {
			// Warn rather than abort: we can't know whether this command
			// actually needs DNS. It may only talk to raw IPs, or not
			// resolve anything at all, in which case a failed nsswitch
			// rewrite breaks nothing. Failing hard here would block runs
			// that would have worked fine; the warning is enough for the
			// case where a lookup later fails for no obvious reason.
			if err := bindNsswitch(body); err != nil {
				fmt.Fprintf(os.Stderr, "[clawpatrol] nsswitch sanitization failed: %v — DNS lookups may fail\n", err)
			}
		}
	}

	// The agent runs as the same uid as the parent and can therefore
	// read anything the parent can; the daemon owns the underlay key
	// material (tsnet auth key under $XDG_STATE_HOME/clawpatrol/, or
	// the wg.conf at ~/.config/clawpatrol/) and never hands it back.
	// PR_SET_DUMPABLE in the parent still closes the ptrace_scope=0
	// /proc memory bypass.

	autoExpose := os.Getenv(runNoAutoExposeEnv) != "1"
	if autoExpose {
		setupRelayInChild(cSock)
	}
	_ = cSock.Close()

	if autoExpose {
		_, _, _ = unix.RawSyscall6(unix.SYS_PRCTL,
			unix.PR_SET_PTRACER, ptraceAny, 0, 0, 0, 0)
	}

	// Privileged (sudo) path: this child was cloned by a root parent and
	// is itself root in the netns. Drop to the invoking user before
	// exec, so the command runs unprivileged (and can sudo on its own).
	// dropToUser changes credentials on every OS thread, so the execve
	// below runs as the user regardless of which thread it lands on.
	// Unprivileged userns path: just shed the ambient caps the parent
	// granted for TUN setup.
	if uidStr := os.Getenv(runDropUIDEnv); uidStr != "" {
		uid, err1 := strconv.Atoi(uidStr)
		gid, err2 := strconv.Atoi(os.Getenv(runDropGIDEnv))
		if err1 != nil || err2 != nil {
			fail("internal: bad drop uid/gid")
		}
		if err := dropToUser(uid, gid); err != nil {
			fail("drop privileges: %v", err)
		}
	} else if err := clearAmbientCaps(); err != nil {
		fail("clear ambient caps: %v", err)
	}

	bin, err := exec.LookPath(argv[0])
	if err != nil {
		fail("lookpath %s: %v", argv[0], err)
	}
	// Strip the internal re-exec coordination vars so the command
	// doesn't inherit them (and can't tell how it was launched).
	if err := syscall.Exec(bin, argv, strippedRunEnv()); err != nil {
		fail("exec %s: %v", bin, err)
	}
}

// strippedRunEnv returns the process environment with clawpatrol's
// internal run-coordination variables removed, so the wrapped command
// doesn't inherit them.
func strippedRunEnv() []string {
	drop := map[string]bool{
		runChildEnv:        true,
		runTunAddrEnv:      true,
		runDropUIDEnv:      true,
		runDropGIDEnv:      true,
		runNoAutoExposeEnv: true,
	}
	env := os.Environ()
	out := env[:0]
	for _, kv := range env {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if drop[name] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// --- daemon client protocol ------------------------------------------

// daemonClientFetchEnv sends "ENV\n" on ctrl and parses the daemon's
// single "ENV <n>\n<n bytes>" reply. Used by `clawpatrol env` so the
// env subcommand can fetch the gateway-declared push-down vars even
// in tsnet-only deployments, where the env process has no host-side
// tailnet route and the in-process gatewayDialOverride is unset
// (that's set by the daemon's own tsnet boot, not by the CLI's).
func daemonClientFetchEnv(ctrl net.Conn) ([]pushdownEnvVar, error) {
	if _, err := io.WriteString(ctrl, "ENV\n"); err != nil {
		return nil, err
	}
	br := bufio.NewReader(ctrl)
	envLen, err := readLenPrefixed(br, "ENV", 1<<20)
	if err != nil {
		return nil, err
	}
	if envLen == 0 {
		return nil, nil
	}
	body := make([]byte, envLen)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, fmt.Errorf("read ENV body: %w", err)
	}
	var vars []pushdownEnvVar
	if err := json.Unmarshal(body, &vars); err != nil {
		return nil, fmt.Errorf("decode ENV body: %w", err)
	}
	return vars, nil
}

// envPushdownDaemonFetcher hooks runEnv (in integrations.go) into the
// Linux-only daemon path. It dials the per-host daemon, asks for the
// cached env-pushdown JSON via the lightweight ENV command, and
// returns it. nil on platforms with no daemon; runEnv then falls back
// to the direct HTTP fetch.
func init() {
	envPushdownDaemonFetcher = func() ([]pushdownEnvVar, error) {
		ctrl, err := daemonConnect()
		if err != nil {
			return nil, err
		}
		defer func() { _ = ctrl.Close() }()
		return daemonClientFetchEnv(ctrl)
	}
}

// daemonClientStartSession sends "START\n" on ctrl and parses the
// daemon's reply: ADDR line, ENV length + JSON body, WARN length +
// optional text. The single bufio.Reader is returned to the caller
// so subsequent reads (e.g. ATTACHED) share the same buffer — using
// a fresh bufio.Reader for later reads would lose any bytes that
// got pulled into this one's buffer during the WARN read.
func daemonClientStartSession(ctrl net.Conn) (*bufio.Reader, netip.Addr, []pushdownEnvVar, string, error) {
	if _, err := io.WriteString(ctrl, "START\n"); err != nil {
		return nil, netip.Addr{}, nil, "", err
	}
	br := bufio.NewReader(ctrl)
	addrLine, err := br.ReadString('\n')
	if err != nil {
		return nil, netip.Addr{}, nil, "", fmt.Errorf("read ADDR: %w", err)
	}
	addrLine = strings.TrimRight(addrLine, "\r\n")
	if !strings.HasPrefix(addrLine, "ADDR ") {
		return nil, netip.Addr{}, nil, "", fmt.Errorf("expected ADDR, got %q", addrLine)
	}
	tunAddr, err := netip.ParseAddr(strings.TrimSpace(addrLine[len("ADDR "):]))
	if err != nil {
		return nil, netip.Addr{}, nil, "", fmt.Errorf("parse ADDR: %w", err)
	}
	envLen, err := readLenPrefixed(br, "ENV", 1<<20)
	if err != nil {
		return nil, netip.Addr{}, nil, "", err
	}
	envBody := make([]byte, envLen)
	if _, err := io.ReadFull(br, envBody); err != nil {
		return nil, netip.Addr{}, nil, "", fmt.Errorf("read ENV body: %w", err)
	}
	var vars []pushdownEnvVar
	if envLen > 0 {
		if err := json.Unmarshal(envBody, &vars); err != nil {
			return nil, netip.Addr{}, nil, "", fmt.Errorf("decode ENV body: %w", err)
		}
	}
	warnLen, err := readLenPrefixed(br, "WARN", 4096)
	if err != nil {
		return nil, netip.Addr{}, nil, "", err
	}
	var warning string
	if warnLen > 0 {
		buf := make([]byte, warnLen)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, netip.Addr{}, nil, "", fmt.Errorf("read WARN body: %w", err)
		}
		warning = string(buf)
	}
	return br, tunAddr, vars, warning, nil
}

// readLenPrefixed reads a "<tag> <n>\n" line and returns n. Errors
// when the tag doesn't match or n is outside [0, maxLen].
func readLenPrefixed(br *bufio.Reader, tag string, maxLen int) (int, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", tag, err)
	}
	line = strings.TrimRight(line, "\r\n")
	prefix := tag + " "
	if !strings.HasPrefix(line, prefix) {
		return 0, fmt.Errorf("expected %s, got %q", tag, line)
	}
	var n int
	if _, err := fmt.Sscanf(line[len(prefix):], "%d", &n); err != nil {
		return 0, fmt.Errorf("parse %s length: %w", tag, err)
	}
	if n < 0 || n > maxLen {
		return 0, fmt.Errorf("%s length %d out of range", tag, n)
	}
	return n, nil
}

func daemonClientWaitAttached(ctrl net.Conn, br *bufio.Reader) error {
	_ = ctrl.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = ctrl.SetReadDeadline(time.Time{}) }()
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimRight(line, "\r\n") != "ATTACHED" {
		return fmt.Errorf("expected ATTACHED, got %q", line)
	}
	return nil
}

// --- capability manipulation -------------------------------------------------

const (
	capNetAdmin = uintptr(12) // CAP_NET_ADMIN
	capSysAdmin = uintptr(21) // CAP_SYS_ADMIN — needed for bind-mount in mnt ns

	// PR_SET_PTRACER_ANY: any same-uid process may ptrace us. The relay
	// supervisor uses this to pidfd_getfd our listen sockets through the
	// yama LSM check.
	ptraceAny = ^uintptr(0)
)

// clearAmbientCaps drops all ambient capabilities before exec'ing the user's
// command so it does not inherit CAP_NET_ADMIN. Mirrors unclaw's
// clear_ambient_caps() in netns.rs.
//
// From capabilities(7): P'(ambient) = (file is privileged) ? 0 : P(ambient)
// Clearing ambient here means the user's cmd exec gets P'(ambient)=0 and
// thus P'(effective)=0 for any cap we had raised.
func clearAmbientCaps() error {
	_, _, errno := unix.RawSyscall6(unix.SYS_PRCTL,
		unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("prctl PR_CAP_AMBIENT_CLEAR_ALL: %w", errno)
	}
	return nil
}

// hideParentFromAgent marks the parent process non-dumpable. Effect:
// /proc/<parent_pid>/{mem,root,fd,maps,environ} flip to root:root
// ownership, so a same-uid agent (forked under us) is denied ptrace
// attach and cannot dereference /proc/<parent_pid>/root to reach the
// host mnt namespace's view of ~/.clawpatrol/. Closes the
// kernel.yama.ptrace_scope=0 bypass.
func hideParentFromAgent() error {
	_, _, errno := unix.RawSyscall6(unix.SYS_PRCTL,
		unix.PR_SET_DUMPABLE, 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("prctl PR_SET_DUMPABLE 0: %w", errno)
	}
	return nil
}

// --- WG-conf parsing (daemon reads it; client never opens it) ---------

// splitWGAddresses parses a wg-quick `Address =` value into one CIDR per
// element. Dual-stack peers receive a comma-joined string like
// `10.55.0.5/32, fd77::5/128`; `ip addr add` rejects that whole string as
// a single prefix, so we split + emit one `ip addr add` per element.
func splitWGAddresses(addrSource string) []string {
	var addrs []string
	for _, part := range strings.Split(addrSource, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if strings.Contains(s, ":") {
				s += "/128"
			} else {
				s += "/32"
			}
		}
		addrs = append(addrs, s)
	}
	return addrs
}

type runConf struct {
	PrivateKey string
	Address    string
	PeerPubKey string
	Endpoint   string
}

func defaultRunConf() string {
	if dir, _ := os.UserConfigDir(); dir != "" {
		return filepath.Join(dir, "clawpatrol", "wg.conf")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "clawpatrol", "wg.conf")
}

func parseRunConf(path string) (*runConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	c := &runConf{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch {
		case section == "interface" && k == "PrivateKey":
			c.PrivateKey = v
		case section == "interface" && k == "Address":
			c.Address = v
		case section == "peer" && k == "PublicKey":
			c.PeerPubKey = v
		case section == "peer" && k == "Endpoint":
			c.Endpoint = v
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if c.PrivateKey == "" || c.Address == "" || c.PeerPubKey == "" || c.Endpoint == "" {
		return nil, fmt.Errorf("missing PrivateKey/Address/PublicKey/Endpoint")
	}
	return c, nil
}

func resolveEndpoint(hp string) (string, error) {
	host, port, err := net.SplitHostPort(hp)
	if err != nil {
		return "", err
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = fmt.Errorf("no A/AAAA")
		}
		return "", err
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// --- TUN fd plumbing -------------------------------------------------

const (
	tunsetiff = 0x400454ca
	iffTun    = 0x0001
	iffNoPi   = 0x1000
	ifnamsiz  = 16
)

type ifreq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_     [22]byte
}

func openTUN(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("/dev/net/tun: %w (try `modprobe tun`)", err)
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPi
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), tunsetiff, uintptr(unsafe.Pointer(&req))); errno != 0 {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	return fd, nil
}

func checkUserNS() {
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(b)) == "0" {
			fail("unprivileged user namespaces disabled.\n  fix: sudo sysctl -w kernel.unprivileged_userns_clone=1")
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			fmt.Fprintf(os.Stderr, "warning: AppArmor may block TUN in user namespaces.\n"+
				"  if `clawpatrol run` fails: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n")
		}
	}
}

func sendFD(s *os.File, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(int(s.Fd()), []byte{0}, rights, nil, 0)
}

// sendFDUnixConn ships one fd via SCM_RIGHTS over a *net.UnixConn,
// using the WriteMsgUnix path instead of .File() + Sendmsg. The
// dup-based path silently switches the underlying file description
// to blocking mode (Linux shares O_NONBLOCK across dups), which
// strands the runtime poller on subsequent reads of the same conn.
// Use this when the SCM_RIGHTS exchange happens on a long-lived
// control conn that the caller keeps reading from afterwards.
func sendFDUnixConn(c *net.UnixConn, fd int) error {
	rights := unix.UnixRights(fd)
	_, _, err := c.WriteMsgUnix([]byte{0}, rights, nil)
	return err
}

// recvFDUnixConn is the counterpart to sendFDUnixConn — reads one fd
// out of one SCM_RIGHTS message off c. Same rationale: avoids the
// .File() dup and keeps the conn usable for follow-up reads.
func recvFDUnixConn(c *net.UnixConn) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return -1, err
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return -1, fmt.Errorf("recvFDUnixConn: ancillary truncated (oobn=%d, n=%d)", oobn, n)
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for _, cmsg := range cmsgs {
		fds, err := unix.ParseUnixRights(&cmsg)
		if err != nil || len(fds) == 0 {
			continue
		}
		for _, x := range fds[1:] {
			_ = unix.Close(x)
		}
		return fds[0], nil
	}
	return -1, fmt.Errorf("no SCM_RIGHTS fd (oobn=%d, n=%d, flags=%#x)", oobn, n, flags)
}

func recvFD(s *os.File) (int, error) {
	fds, err := recvFDs(s, 1)
	if err != nil {
		return -1, err
	}
	return fds[0], nil
}

// sendFDs ships up to a handful of fds in a single SCM_RIGHTS message.
// The payload byte distinguishes nothing in particular today; it exists
// because sendmsg requires at least one byte of inline data on a stream
// socket for the receiver to see the cmsg.
func sendFDs(s *os.File, fds []int) error {
	rights := unix.UnixRights(fds...)
	return unix.Sendmsg(int(s.Fd()), []byte{1}, rights, nil, 0)
}

// recvFDs reads exactly n fds out of one SCM_RIGHTS message. Extras get
// closed so we never leak; a short cmsg returns an error.
func recvFDs(s *os.File, n int) ([]int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4*n))
	_, oobn, _, _, err := unix.Recvmsg(int(s.Fd()), buf, oob, 0)
	if err != nil {
		return nil, err
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	for _, cmsg := range cmsgs {
		fds, err := unix.ParseUnixRights(&cmsg)
		if err != nil || len(fds) == 0 {
			continue
		}
		if len(fds) < n {
			for _, x := range fds {
				_ = unix.Close(x)
			}
			return nil, fmt.Errorf("expected %d fds, got %d", n, len(fds))
		}
		for _, x := range fds[n:] {
			_ = unix.Close(x)
		}
		return fds[:n], nil
	}
	return nil, fmt.Errorf("no SCM_RIGHTS fd")
}

// childResolvConf builds the body of /etc/resolv.conf the child sees
// inside its mnt namespace.
//
// In tsnet mode we point at the gateway's tailnet IP: the gateway
// runs serveTsnetDNSUDP on <tailnet-gateway-ip>:53, which both
// allocates VIPs for intercepted hostnames AND relays anything else
// upstream. Public resolvers don't work because the gateway has no
// UDP fallback handler for exit-routed traffic — DNS packets aimed
// at 1.1.1.1 / 8.8.8.8 get dropped at the gateway, so every name
// lookup inside `clawpatrol run` would time out.
//
// In WG mode the gateway's WG netstack intercepts DNS in-flight, so
// any public-looking nameserver works; fall back to 1.1.1.1 / 8.8.8.8
// for that and for joins old enough that they predate the gateway-IP
// file.
//
// Note: the bind-mounted resolv.conf only governs the glibc `dns` NSS
// module (and tools like dig that read resolv.conf directly). On hosts
// whose nsswitch.conf puts `resolve` (systemd-resolved) ahead of `dns`
// — Fedora's default — getaddrinfo answers from the host resolver
// before ever consulting resolv.conf, so this alone is not enough.
// childNsswitch handles that case.
func childResolvConf() string {
	caDir := defaultClawpatrolDir()
	if gwIP := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "tailnet-gateway-ip"))); gwIP != "" {
		return "nameserver " + gwIP + "\n"
	}
	return "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
}

// bindResolv writes body to a temp file and bind-mounts it over
// /etc/resolv.conf in the calling mount namespace.
//
// The temp file is made world-readable (0644) before the mount. In the
// sudo path bindResolv runs as root (before the drop to the invoking
// user), so a 0600 file ends up root-owned and the unprivileged command
// can't read the resolv.conf bind-mounted over /etc/resolv.conf — every
// name lookup then fails with "could not resolve host" while raw-IP
// traffic still works. A resolv.conf holds only nameserver lines,
// nothing sensitive.
func bindResolv(body string) error {
	return bindOverEtc("/etc/resolv.conf", "clawpatrol-resolv-*", body)
}

// childNsswitch returns a sanitized /etc/nsswitch.conf body and whether
// it differs from the host's. The sandbox bind-mounts a private
// /etc/resolv.conf pointing at the gateway, but resolv.conf only governs
// the glibc `dns` NSS module. Distros that list a host-resolver module
// ahead of `dns` in the `hosts:` line — Fedora ships
// `files myhostname mdns4_minimal [NOTFOUND=return] resolve
// [!UNAVAIL=return] dns` — answer getaddrinfo from systemd-resolved (or
// mDNS) first. That resolver runs on the host, is oblivious to the
// sandbox's resolv.conf, and returns NXDOMAIN for gateway-only names
// like clawpatrol.internal; the `[!UNAVAIL=return]` action then stops
// the lookup before `dns` is ever tried, so the override is bypassed
// and `curl https://clawpatrol.internal` fails to resolve while `dig`
// (which reads resolv.conf directly) succeeds.
//
// See rewriteHostsLine for what the sanitization removes. A missing
// nsswitch.conf is normal (musl/Alpine has no NSS; getaddrinfo reads
// resolv.conf directly), so it is not worth a warning; any other read
// error is, since it likely leaves the resolved short-circuit in place
// and would otherwise turn into a silent resolution failure.
func childNsswitch() (body string, changed bool) {
	raw, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "[clawpatrol] cannot read /etc/nsswitch.conf: %v — DNS lookups may fail\n", err)
		}
		return "", false
	}
	return rewriteHostsLine(string(raw))
}

// splitHostsTokens splits an nsswitch source list into tokens, treating
// a bracketed action item as a single token even when it contains
// whitespace. glibc accepts spaces inside the brackets and the
// multi-status form `[SUCCESS=return NOTFOUND=continue]` is common, so
// strings.Fields would shatter one action into several bogus tokens.
// A `[` always starts an action token that runs to the next `]`
// (inclusive); everything else is whitespace-separated.
func splitHostsTokens(s string) []string {
	var toks []string
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		if s[i] == '[' {
			j := i + 1
			for j < len(s) && s[j] != ']' {
				j++
			}
			if j < len(s) {
				j++ // include the closing ']'
			}
			toks = append(toks, s[i:j])
			i = j
			continue
		}
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '[' {
			j++
		}
		toks = append(toks, s[i:j])
		i = j
	}
	return toks
}

// rewriteHostsLine sanitizes the `hosts:` line of an nsswitch.conf body,
// removing only the NSS modules that bypass the bind-mounted resolv.conf
// — systemd-resolved (`resolve`) and Avahi mDNS (`mdns*`) — along with
// the bracketed action items that trail them, and ensuring `dns` is
// present so getaddrinfo consults resolv.conf. Every other source
// (`files`, `myhostname`, `sss`, `ldap`, `nis`, …) is preserved in its
// original position, so a host that resolves internal names through
// sssd/LDAP keeps doing so inside the sandbox.
//
// It returns the full rewritten body and whether anything changed;
// changed is false when raw has no hosts: line or the line already
// routes through dns without an interfering module (e.g. Ubuntu's
// `files dns`), so unaffected distros keep their nsswitch untouched
// rather than rebinding an identical copy.
func rewriteHostsLine(raw string) (body string, changed bool) {
	if raw == "" {
		return "", false
	}
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		rest, ok := strings.CutPrefix(strings.TrimLeft(line, " \t"), "hosts:")
		if !ok {
			continue
		}
		// Strip trailing comments before tokenizing the source list.
		if c := strings.IndexByte(rest, '#'); c >= 0 {
			rest = rest[:c]
		}
		orig := splitHostsTokens(rest)
		var kept []string
		dropAction := false // drop bracketed actions trailing a removed module
		for _, tok := range orig {
			if strings.HasPrefix(tok, "[") {
				// Action modifier ([!UNAVAIL=return] etc.) applies to the
				// preceding source; keep it only if that source survived.
				if !dropAction {
					kept = append(kept, tok)
				}
				continue
			}
			// resolve (systemd-resolved) and mdns* (Avahi) answer ahead
			// of dns and can't reach the gateway through the tunnel.
			if tok == "resolve" || strings.HasPrefix(tok, "mdns") {
				dropAction = true
				continue
			}
			dropAction = false
			kept = append(kept, tok)
		}
		if !slices.Contains(kept, "dns") {
			kept = append(kept, "dns")
		}
		// No-op when no bypassing module was present (token sequence
		// unchanged), so unaffected distros' nsswitch is left untouched.
		if slices.Equal(orig, kept) {
			return "", false
		}
		lines[i] = "hosts:      " + strings.Join(kept, " ")
		return strings.Join(lines, "\n"), true
	}
	return "", false
}

// bindNsswitch bind-mounts body over /etc/nsswitch.conf in the calling
// mount namespace. Same 0644/teardown semantics as bindResolv.
func bindNsswitch(body string) error {
	return bindOverEtc("/etc/nsswitch.conf", "clawpatrol-nsswitch-*", body)
}

// bindOverEtc writes body to a temp file (named via pattern) and
// bind-mounts it over target in the calling mount namespace. The temp
// file is unlinked on every path — including success: once the
// bind-mount is in place it holds a reference to the inode, so removing
// the source directory entry leaves target intact (the mount points at
// the inode, not the path) while ensuring we don't strand a temp file
// per `clawpatrol run`. The kernel reclaims the inode when the mount
// goes away on namespace exit. The file is made world-readable (0644)
// so an unprivileged wrapped command can read it on the sudo path.
func bindOverEtc(target, pattern, body string) error {
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", target, err)
	}
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write temp file for %s: %w", target, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("chmod temp file for %s: %w", target, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("close temp file for %s: %w", target, err)
	}
	if err := unix.Mount(tmp.Name(), target, "", unix.MS_BIND, ""); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("bind-mount %s: %w", target, err)
	}
	// Mount holds the inode; drop the now-redundant /tmp path so it
	// doesn't accumulate across runs.
	_ = os.Remove(tmp.Name())
	return nil
}
