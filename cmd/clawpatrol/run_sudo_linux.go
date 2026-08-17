//go:build linux

package main

// Privileged `clawpatrol run` setup on a host with passwordless sudo.
//
// The default path (run_linux.go) runs the wrapped command in an
// unprivileged user namespace to obtain CAP_NET_ADMIN / CAP_SYS_ADMIN
// without root. The trade-off is that the userns has no mapped root, so
// `sudo` (and anything needing real root) can't work inside it.
//
// When the host already grants passwordless sudo, we don't need the
// userns: get the caps from real root instead. A small helper, re-exec'd
// once via sudo, creates the net+mnt namespace as root (no userns),
// attaches the TUN to the per-host daemon exactly as the userns child
// does, then drops back to the invoking user and execs the command. The
// command therefore runs with real uids in a namespace where root
// exists — so `sudo` works — while its traffic still routes through the
// gateway (credentials/policy are unaffected; that's enforced gateway-
// side, not by the sandbox).
//
// Privilege escalation fundamentally requires the setuid `sudo` binary —
// there's no syscall that grants root from sudoers — so we exec sudo
// exactly once and do everything else with syscalls.
//
// Opt out with CLAWPATROL_NO_SUDO to force the unprivileged userns path.
//
// Limitation: the auto-expose relay (port mirroring) is not wired into
// this path yet; listeners the command opens aren't published to the
// host. Use the userns path (CLAWPATROL_NO_SUDO=1) if you need that.

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// sudoSetupAvailable reports whether runRun should set the namespace up
// via passwordless sudo (real root) rather than an unprivileged user
// namespace. Gated off by CLAWPATROL_NO_SUDO.
func sudoSetupAvailable() bool {
	if os.Getenv("CLAWPATROL_NO_SUDO") != "" {
		return false
	}
	if os.Geteuid() == 0 {
		// Already root — the userns path refuses this anyway; not our case.
		return false
	}
	// `sudo -n true` exits non-zero (without prompting) when a password
	// would be required, and errors when sudo is absent.
	return exec.Command("sudo", "-n", "true").Run() == nil
}

// runViaSudo ensures the per-host daemon is up (as this user), then
// launches the privileged setup helper under sudo and waits on it.
func runViaSudo(cmd []string) {
	// The helper connects to the daemon but must never spawn one (a
	// root-spawned daemon would own state in the wrong home). Ensure
	// it's running here, as this user. The daemon is persistent
	// (5-minute idle exit), so the brief gap until the helper connects
	// is safe.
	if c, err := daemonConnect(); err != nil {
		fail("daemon connect: %v", err)
	} else {
		_ = c.Close()
	}

	// sudo resets the environment, but the command must run with this
	// user's env. Capture it into a 0600 file the helper reads and deletes.
	// The Claude Code OAuth shim is NOT applied here: the gateway
	// env-pushdown that feeds it ANTHROPIC_AUTH_TOKEN isn't in this
	// (unprivileged, pre-session) env yet. The privileged helper applies it
	// against the fully-built child env instead — see
	// applyClaudeCodeOAuthShimSudo in runRunPrivileged.
	envFile, err := writePrivilegedEnvFile(os.Environ())
	if err != nil {
		fail("env file: %v", err)
	}
	defer func() { _ = os.Remove(envFile) }()

	self, err := os.Executable()
	if err != nil {
		fail("self path: %v", err)
	}
	args := []string{
		"--", self, "__run-privileged",
		"--sock", daemonControlSockPath(),
		"--env-file", envFile,
		"--ca", filepath.Join(defaultClawpatrolDir(), "ca.crt"),
		"--",
	}
	args = append(args, cmd...)
	c := exec.Command("sudo", args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		fail("sudo: %v", err)
	}
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigCh {
			if c.Process != nil {
				_ = c.Process.Signal(s)
			}
		}
	}()
	if err := c.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fail("run: %v", err)
	}
}

// writePrivilegedEnvFile writes env entries NUL-separated to a 0600
// file under the user's runtime dir for the helper to read.
func writePrivilegedEnvFile(env []string) (string, error) {
	f, err := os.CreateTemp(daemonRuntimeDir(), "run-env-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(strings.Join(env, "\x00")); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// runRunPrivileged is the `__run-privileged` subcommand: re-exec'd via
// sudo by runViaSudo, runs as root. It creates the net+mnt namespace,
// attaches the TUN to the daemon, drops to the invoking user, and execs
// the command.
func runRunPrivileged(args []string) {
	if os.Geteuid() != 0 {
		fail("internal: __run-privileged must run as root (via sudo)")
	}
	fs := flag.NewFlagSet("__run-privileged", flag.ExitOnError)
	sock := fs.String("sock", "", "daemon control socket path")
	envFile := fs.String("env-file", "", "NUL-separated env for the command")
	caPath := fs.String("ca", "", "CA path for cert env vars")
	_ = fs.Parse(args)
	cmd := fs.Args()
	if len(cmd) == 0 {
		fail("internal: __run-privileged got no command")
	}

	uid, gid, ok := sudoTargetIDs()
	if !ok {
		fail("internal: missing/!invalid SUDO_UID/SUDO_GID — invoke via sudo")
	}

	// 1. Daemon session. The daemon is already running as the user;
	// dial it directly (never spawn — that would run as root).
	ctrl, ok := daemonDialAndHello(*sock)
	if !ok {
		fail("daemon not reachable at %s", *sock)
	}
	br, tunAddr, pushVars, warn, err := daemonClientStartSession(ctrl)
	if err != nil {
		fail("daemon START: %v", err)
	}
	if warn != "" {
		fmt.Fprintf(os.Stderr, "clawpatrol: daemon: %s\n", warn)
	}
	uc, _ := ctrl.(*net.UnixConn)
	if uc == nil {
		fail("control conn is %T, not *net.UnixConn", ctrl)
	}
	defer func() { _ = ctrl.Close() }()

	// 2. Build the command's environment: the invoking user's env (from
	// the file) plus the cert / push-down vars. The command never sees
	// SUDO_* — we set its env explicitly — and the daemon control conn
	// stays with us (this root parent), never inherited by the command.
	// The control vars below are consumed by runRunChild and stripped
	// before it execs the actual command.
	childEnv := buildPrivilegedEnv(*envFile, *caPath, pushVars)
	// Apply the `clawpatrol run claude` OAuth shim here, not in the
	// unprivileged runViaSudo parent: the gateway env-pushdown that
	// supplies ANTHROPIC_AUTH_TOKEN is merged just above (buildPrivilegedEnv),
	// so the parent's env never had the token to shim. Evaluate against the
	// built child env instead.
	childEnv = applyClaudeCodeOAuthShimSudo(childEnv, cmd, uid, gid)
	childEnv = append(childEnv,
		runChildEnv+"=1",
		runTunAddrEnv+"="+tunAddr.String(),
		runDropUIDEnv+"="+strconv.Itoa(uid),
		runDropGIDEnv+"="+strconv.Itoa(gid),
		runNoAutoExposeEnv+"=1", // auto-expose isn't wired into the sudo path yet
	)

	// 3. IPC channels for the child: TUN fd handoff + tun-up signal.
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

	// 4. Spawn the command as a child cloned into a fresh net+mnt
	// namespace. No user namespace: this parent is real root, so the
	// child is created with full caps, opens its TUN, configures
	// routing/DNS, then drops to the invoking user and execs the
	// command (runRunChild handles the drop when runDropUIDEnv is set).
	// The command thus runs as that user in a namespace where root
	// exists — sudo works — and can't tell it was launched via sudo
	// (clean env, normal uid, parent is clawpatrol, no stray fds).
	self, err := os.Executable()
	if err != nil {
		fail("self path: %v", err)
	}
	child := exec.Command(self, append([]string{"run"}, cmd...)...)
	child.Env = childEnv
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{cSock, tunUpR}
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET,
		// Create the mount namespace via Unshareflags rather than
		// Cloneflags: Go follows an Unshareflags CLONE_NEWNS with a
		// recursive MS_PRIVATE remount of `/`. Without that the new
		// mount namespace inherits the host's shared propagation, so
		// the resolv.conf bind-mount runRunChild does propagates back
		// to the host /etc/resolv.conf and stacks up one overmount per
		// `clawpatrol run` (and pins the /tmp temp file forever). The
		// unprivileged userns path doesn't need this — a userns-owned
		// mount namespace is already private. Real root here can
		// unshare the mount namespace directly.
		Unshareflags: syscall.CLONE_NEWNS,
	}
	if err := child.Start(); err != nil {
		fail("clone child: %v", err)
	}
	_ = cSock.Close()
	_ = tunUpR.Close()

	// 5. Receive the TUN fd from the child, hand it to the daemon, wait
	// ATTACHED.
	tunFd, err := recvFD(pSock)
	if err != nil {
		_ = child.Process.Kill()
		fail("recv tun fd: %v", err)
	}
	if err := sendFDUnixConn(uc, tunFd); err != nil {
		_ = child.Process.Kill()
		fail("send tun fd to daemon: %v", err)
	}
	_ = unix.Close(tunFd)
	if err := daemonClientWaitAttached(ctrl, br); err != nil {
		_ = child.Process.Kill()
		fail("daemon ATTACHED: %v", err)
	}

	// 6. Signal the child that the bridge is up.
	_, _ = tunUpW.Write([]byte{1})
	_ = tunUpW.Close()

	// 7. Forward signals and wait. We hold the daemon control conn for
	// the command's lifetime; the deferred Close tears the session down.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigCh {
			_ = child.Process.Signal(s)
		}
	}()
	waitErr := child.Wait()
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			os.Exit(ee.ExitCode())
		}
		fail("wait: %v", waitErr)
	}
}

// sudoTargetIDs returns the uid/gid sudo recorded for the invoking user.
// Both must be non-root (we only ever drop privileges, never retarget to
// root or the root group). sudo resets the environment and sets these
// from the real invoker by default, so the unprivileged caller can't
// spoof them — barring an unusual sudoers that env_keeps SUDO_UID/GID,
// and even then the worst case is dropping to another non-root identity.
func sudoTargetIDs() (uid, gid int, ok bool) {
	us, gs := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	u, err1 := strconv.Atoi(us)
	g, err2 := strconv.Atoi(gs)
	if err1 != nil || err2 != nil || u <= 0 || g <= 0 {
		return 0, 0, false
	}
	return u, g, true
}

// buildPrivilegedEnv reconstructs the command's environment: the user's
// captured env (from envFile, which it deletes) plus the cert-bundle and
// gateway push-down vars, the latter skipped when the user set
// CLAWPATROL_NO_ENV and never overriding a var the user already set.
func buildPrivilegedEnv(envFile, caPath string, pushVars []pushdownEnvVar) []string {
	data, err := os.ReadFile(envFile)
	if err != nil {
		fail("read env file: %v", err)
	}
	_ = os.Remove(envFile)

	var env []string
	have := map[string]bool{}
	noEnv := false
	for _, kv := range strings.Split(string(data), "\x00") {
		if kv == "" {
			continue
		}
		env = append(env, kv)
		if i := strings.IndexByte(kv, '='); i > 0 {
			have[kv[:i]] = true
			if kv == "CLAWPATROL_NO_ENV=1" {
				noEnv = true
			}
		}
	}
	if noEnv {
		return env
	}
	// The clawpatrol-owned CA vars are force-set: the child MUST trust the
	// combined bundle / MITM CA even if the captured user env already named
	// SSL_CERT_FILE etc. Drop any captured value for those names first, then
	// re-add ours below. Non-CA pushdown vars keep the user's captured value.
	filtered := env[:0]
	for _, kv := range env {
		name := kv
		if i := strings.IndexByte(kv, '='); i > 0 {
			name = kv[:i]
		}
		if clawpatrolCAVarNames[name] {
			continue
		}
		filtered = append(filtered, kv)
	}
	env = filtered
	for _, ev := range append(caPathPushdownVars(caPath), dropClawpatrolCAVars(pushVars)...) {
		if !clawpatrolCAVarNames[ev.Name] && have[ev.Name] {
			continue
		}
		env = append(env, ev.Name+"="+ev.Value)
		have[ev.Name] = true
	}
	return env
}

// applyClaudeCodeOAuthShimSudo reflects the `clawpatrol run claude` OAuth
// shim onto the privileged child's environment slice.
//
// The userns/darwin paths run the shim against the live process env right
// before exec (installClaudeCodeOAuthShim). The sudo path can't: the
// gateway env-pushdown that supplies ANTHROPIC_AUTH_TOKEN is merged here,
// in the root helper (buildPrivilegedEnv), long after the unprivileged
// parent captured its env — so at capture time there was no token to shim
// and the shim silently no-op'd, leaving the child in bearer mode (Claude
// Code precedence #2) instead of subscription OAuth (#6). We instead
// evaluate the shim against the built childEnv: derive the managed config
// dir from the child's (the user's) HOME, and chown the synthesized
// credentials to the target uid/gid so the dropped-to-user command can
// read them.
func applyClaudeCodeOAuthShimSudo(env, cmd []string, uid, gid int) []string {
	get := func(k string) string {
		pre := k + "="
		v := ""
		for _, kv := range env {
			if strings.HasPrefix(kv, pre) {
				v = kv[len(pre):] // last wins, matching exec env semantics
			}
		}
		return v
	}
	clawDir := filepath.Join(get("HOME"), ".clawpatrol")
	res := planClaudeCodeOAuthShim(cmd, get, clawDir, uid, gid)
	if res.warn {
		warnClaudeCodeRemoteControlDisabled()
	}
	if !res.applied {
		return env
	}
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if res.unsetAuthToken && strings.HasPrefix(kv, "ANTHROPIC_AUTH_TOKEN=") {
			continue
		}
		if res.configDir != "" && strings.HasPrefix(kv, "CLAUDE_CONFIG_DIR=") {
			continue
		}
		out = append(out, kv)
	}
	if res.configDir != "" {
		out = append(out, "CLAUDE_CONFIG_DIR="+res.configDir)
	}
	return out
}

// dropToUser permanently drops the process to uid/gid (real, effective,
// and saved), restoring the user's supplementary groups, and verifies
// the drop took. Groups before gid before uid, so each step still has
// the privilege it needs.
//
// Uses the syscall package's setid family deliberately: the Go runtime
// broadcasts those across every OS thread (unlike x/sys/unix.Setgroups,
// which is a per-thread raw syscall). A uniform, all-threads drop means
// no runtime thread is left holding root's credentials, so it doesn't
// matter which thread the subsequent execve runs on.
func dropToUser(uid, gid int) error {
	groups := []int{gid}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		if gidStrs, err := u.GroupIds(); err == nil && len(gidStrs) > 0 {
			groups = groups[:0]
			for _, gs := range gidStrs {
				if g, err := strconv.Atoi(gs); err == nil {
					groups = append(groups, g)
				}
			}
			if len(groups) == 0 {
				groups = []int{gid}
			}
		}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	if syscall.Getuid() != uid || syscall.Geteuid() != uid {
		return fmt.Errorf("uid still %d/%d after drop, want %d", syscall.Getuid(), syscall.Geteuid(), uid)
	}
	return nil
}
