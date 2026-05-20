//go:build linux

package main

// Per-host self-forking daemon. `clawpatrol run` connects to a Unix
// socket; if no daemon is alive, it re-execs itself as `clawpatrol
// daemon-internal` (a hidden subcommand) and the new process binds
// the socket, then idle-exits 5 minutes after the last client
// disconnects.
//
// Race-control protocol:
//   - exclusive flock on spawn.lock serializes the connect-or-spawn
//     path across concurrent clients.
//   - mandatory hello() handshake on every client connect rejects
//     conns landing on a daemon that's mid-teardown.
//   - the idle-exit goroutine drops back to the lock before unlinking
//     the socket; a "lost race" recovery path re-binds a fresh
//     listener when an accept slips in between recheck and close.
//   - single os.Exit site invariant: the main goroutine never returns
//     from runDaemon on its own, so cleanup placed on the exit path
//     cannot be skipped.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tailscale.com/tsnet"
)

const (
	daemonIdleTimeout  = 5 * time.Minute
	daemonHelloTimeout = 2 * time.Second
	daemonSpawnTimeout = 30 * time.Second
	daemonMagicLine    = "CLAWPATROL/1\n"
)

// daemonRuntimeDir resolves the per-user runtime directory holding the
// daemon's coordination state (control socket, spawn lock, log). Prefer
// XDG_RUNTIME_DIR (tmpfs, per-user, no NFS pitfalls); fall back to
// /tmp/clawpatrol-<uid> when unset (containers, minimal images).
func daemonRuntimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "clawpatrol")
	}
	return filepath.Join("/tmp", fmt.Sprintf("clawpatrol-%d", os.Getuid()))
}

func daemonControlSockPath() string { return filepath.Join(daemonRuntimeDir(), "control.sock") }
func daemonSpawnLockPath() string   { return filepath.Join(daemonRuntimeDir(), "spawn.lock") }
func daemonLogPath() string         { return filepath.Join(daemonRuntimeDir(), "daemon.log") }

// daemonConnect returns a control connection to the per-host daemon,
// spawning one if none is running. Safe to call from concurrent
// `clawpatrol run` invocations.
func daemonConnect() (net.Conn, error) {
	dir := daemonRuntimeDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	sockPath := daemonControlSockPath()
	lockPath := daemonSpawnLockPath()

	// 1. Happy path: try to connect + hello without taking the spawn
	// lock. If we land on a live daemon this returns immediately;
	// the lock is reserved for the cold-start / dying-daemon case.
	if c, ok := daemonDialAndHello(sockPath); ok {
		return c, nil
	}

	// 2. Spawn-path: serialize via exclusive flock on spawn.lock so
	// at most one client at a time tries to fork a daemon.
	lf, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open spawn lock: %w", err)
	}
	defer func() { _ = lf.Close() }()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("flock ex: %w", err)
	}
	// Lock released by lf.Close() above.

	// 3. Re-check under the lock — someone may have spawned a daemon
	// while we were blocked.
	if c, ok := daemonDialAndHello(sockPath); ok {
		return c, nil
	}

	// 4. Stale socket from a SIGKILL'd previous daemon? Remove it.
	// bind() in the new daemon would otherwise EADDRINUSE.
	_ = os.Remove(sockPath)

	// 5. Re-exec self as `clawpatrol daemon-internal`.
	if err := daemonSpawn(dir); err != nil {
		return nil, fmt.Errorf("spawn daemon: %w", err)
	}

	// 6. The daemon wrote "ready" before we got here so the socket is
	// bound. Final dial must succeed.
	if c, ok := daemonDialAndHello(sockPath); ok {
		return c, nil
	}
	return nil, errors.New("post-spawn dial failed")
}

// daemonDialAndHello dials the control socket and runs the hello
// handshake. Returns the conn on success; on any failure closes the
// conn and returns nil + false. The caller distinguishes "no daemon"
// from "daemon is dying" by retrying under the spawn lock.
func daemonDialAndHello(sockPath string) (net.Conn, bool) {
	c, err := net.DialTimeout("unix", sockPath, 200*time.Millisecond)
	if err != nil {
		return nil, false
	}
	if err := daemonHello(c); err != nil {
		_ = c.Close()
		return nil, false
	}
	return c, true
}

// daemonHello writes a magic line + a fresh nonce and expects the
// daemon to echo the nonce. A mismatch (ECONNRESET because the
// listener tore down between connect() and accept(), read timeout,
// random garbage) lets the caller treat the daemon as gone.
func daemonHello(c net.Conn) error {
	_ = c.SetDeadline(time.Now().Add(daemonHelloTimeout))
	defer func() { _ = c.SetDeadline(time.Time{}) }()

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	nonceLine := hex.EncodeToString(nonce) + "\n"
	if _, err := io.WriteString(c, daemonMagicLine+nonceLine); err != nil {
		return err
	}
	br := bufio.NewReader(c)
	got, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if got != nonceLine {
		return fmt.Errorf("hello mismatch: got %q want %q", got, nonceLine)
	}
	return nil
}

// daemonSpawn re-execs the current binary as `clawpatrol
// daemon-internal`, waits for it to write "ready\n" on the inherited
// pipe (fd 3), then returns. The child detaches via Setsid and
// ignores SIGHUP.
func daemonSpawn(dir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer func() { _ = pr.Close() }()

	logf, err := os.OpenFile(daemonLogPath(),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		_ = pw.Close()
		return err
	}
	defer func() { _ = logf.Close() }()

	cmd := exec.Command(self, "daemon-internal")
	cmd.Stdin = nil
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.ExtraFiles = []*os.File{pw} // becomes fd 3 in the child
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return err
	}
	// Parent closes its write end so child death (without writing
	// "ready") propagates back as EOF rather than hanging.
	_ = pw.Close()
	// Release the child to its own lifecycle. Without this the runtime
	// keeps a SIGCHLD wait pending and the child reaps as a zombie when
	// this process exits.
	if err := cmd.Process.Release(); err != nil {
		log.Printf("warn: release daemon: %v", err)
	}

	_ = pr.SetReadDeadline(time.Now().Add(daemonSpawnTimeout))
	br := bufio.NewReader(pr)
	line, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("daemon ready: %w (read %q)", err, line)
	}
	if line != "ready\n" {
		return fmt.Errorf("daemon ready: unexpected %q", line)
	}
	return nil
}

// ----- daemon process -------------------------------------------------

type daemon struct {
	sockPath string
	lockFile *os.File

	// tsServer is the daemon's single tailnet identity, shared by every
	// concurrent `clawpatrol run` session on this host. Set once at
	// startup, never replaced. envVars is the cached env-pushdown
	// response — clients pull it from us instead of dialing the gateway
	// themselves (they're not on the tailnet; only we are).
	tsServer *tsnet.Server
	tsIP     netip.Addr
	envVars  []byte // pre-serialized JSON for the FETCH path in handle()

	// bootWarning is a one-line message that the smoke-probe at startup
	// generates when exit-node routing looks broken. Empty means clean
	// boot. Sent on every session START so `clawpatrol run` can repeat
	// it on stderr — operators shouldn't have to tail daemon.log to
	// discover ACL misconfiguration.
	bootWarning string

	activeConns atomic.Int32

	mu        sync.Mutex
	listener  net.Listener
	idleTimer *time.Timer
	exited    bool
	// rebindCh: tryExit sends here after replacing d.listener on the
	// lost-race recovery path. On the clean-exit path tryExit calls
	// os.Exit instead; the main goroutine blocks on this channel and
	// dies with the process.
	rebindCh chan struct{}
}

// runDaemon is the entry point for the `clawpatrol daemon-internal`
// subcommand. Invoked exclusively by daemonSpawn — clients should
// never run this directly. Returns only via os.Exit from tryExit (or
// log.Fatal on fatal startup error).
func runDaemon(_ []string) {
	log.SetFlags(log.Lmicroseconds)

	if err := os.MkdirAll(daemonRuntimeDir(), 0o700); err != nil {
		log.Fatalf("daemon: mkdir runtime: %v", err)
	}
	sockPath := daemonControlSockPath()
	lockPath := daemonSpawnLockPath()

	log.Printf("daemon pid=%d starting", os.Getpid())

	// Boot tsnet first. We don't bind the control socket until the
	// daemon is fully usable — that way a parent reading "ready\n" can
	// proceed straight to a session START without retries.
	tsServer, tsIP, bootWarning, err := daemonStartTsnet()
	if err != nil {
		log.Fatalf("daemon: tsnet: %v", err)
	}

	// Fetch the env-pushdown JSON once and cache it. Sessions get the
	// same vars over their lifetime — refreshing per-session would
	// stampede the gateway under bursty agent fleets.
	envJSON := daemonFetchEnvPushdown(tsServer)

	// Register this tsnet IP with the gateway so it maps to the host's
	// device row (and therefore its profile). Best-effort: a failure
	// only means traffic lands in the default profile until the next
	// daemon restart.
	daemonRegisterWithGateway(tsServer, tsIP)

	// Bind the control socket last. Parent still holds spawn.lock at
	// this point, so we can't race another daemon for the path.
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Fatalf("daemon: listen %s: %v", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		log.Printf("warn: chmod sock: %v", err)
	}

	lf, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		log.Fatalf("daemon: open spawn lock: %v", err)
	}

	d := &daemon{
		sockPath:    sockPath,
		listener:    ln,
		lockFile:    lf,
		tsServer:    tsServer,
		tsIP:        tsIP,
		envVars:     envJSON,
		bootWarning: bootWarning,
		rebindCh:    make(chan struct{}),
	}

	// Signal ready on the inherited pipe (fd 3). Once this lands, the
	// parent unblocks and the spawn lock is released.
	if ready := os.NewFile(3, "ready"); ready != nil {
		_, _ = ready.WriteString("ready\n")
		_ = ready.Close()
	}

	d.startIdleTimer()

	// Main loop. After serve() returns the only valid events are:
	//   - tryExit re-bound (sends on rebindCh) → loop, serve new listener.
	//   - tryExit is exiting (calls os.Exit) → channel receive blocks
	//     forever, process dies under us.
	// Never busy-poll d.exited or d.listener — that's how the previous
	// (pre-prototype) version of this code spun the CPU.
	for {
		d.serve()
		<-d.rebindCh
		log.Printf("daemon pid=%d serve loop: re-entering accept on new listener", os.Getpid())
	}
}

func (d *daemon) startIdleTimer() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.exited {
		return
	}
	if d.idleTimer != nil {
		d.idleTimer.Stop()
	}
	d.idleTimer = time.AfterFunc(daemonIdleTimeout, d.tryExit)
}

func (d *daemon) cancelIdleTimer() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.idleTimer != nil {
		d.idleTimer.Stop()
	}
}

func (d *daemon) serve() {
	d.mu.Lock()
	ln := d.listener
	d.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed by tryExit
		}
		n := d.activeConns.Add(1)
		d.cancelIdleTimer()
		log.Printf("daemon: accept, active=%d", n)
		go d.handle(c)
	}
}

// handle services a single `clawpatrol run` session. After the
// hello handshake the protocol is:
//
//	client → daemon:  "START\n"
//	daemon → client:  "TSIP <ip>\n" "ENV <n>\n" <n bytes JSON>
//	client → daemon:  SCM_RIGHTS carrying one TUN fd (payload byte 0)
//	daemon → client:  "ATTACHED\n"
//	client → daemon:  (control conn stays open; close = session end)
//
// On close the per-session gVisor stack tears down, the TUN fd is
// released, and any in-flight conns through tsnet drain.
func (d *daemon) handle(c net.Conn) {
	defer func() {
		_ = c.Close()
		n := d.activeConns.Add(-1)
		log.Printf("daemon: close, active=%d", n)
		if n == 0 {
			d.startIdleTimer()
		}
	}()

	if err := daemonHandshake(c); err != nil {
		log.Printf("daemon: handshake: %v", err)
		return
	}

	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(daemonHelloTimeout))
	line, err := br.ReadString('\n')
	if err != nil {
		log.Printf("daemon: read command: %v", err)
		return
	}
	if line != "START\n" {
		log.Printf("daemon: unknown command %q", line)
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	// 1. Tell the client our tsnet IP, ship the env-pushdown JSON, and
	// pass along any one-line warning the smoke-probe generated at
	// daemon boot.
	if err := daemonWriteStartReply(c, d.tsIP, d.envVars, d.bootWarning); err != nil {
		return
	}

	// 2. Receive the TUN fd via SCM_RIGHTS using the *net.UnixConn's
	// native ReadMsgUnix path. Going through .File() + unix.Recvmsg
	// would dup the underlying fd, which on Linux clears O_NONBLOCK
	// on the shared file description and leaves the conn deadlocked
	// for subsequent reads — see sendFDUnixConn for the same
	// reasoning on the client side.
	uc, ok := c.(*net.UnixConn)
	if !ok {
		log.Printf("daemon: conn is not *net.UnixConn (got %T)", c)
		return
	}
	tunFd, err := recvFDUnixConn(uc)
	if err != nil {
		log.Printf("daemon: recv TUN fd: %v", err)
		return
	}
	tunFile := os.NewFile(uintptr(tunFd), tunIfName)
	defer func() { _ = tunFile.Close() }()

	// 3. Build the per-session gVisor stack. Multiple sessions share
	// the daemon's single tsnet.Server but each gets its own stack so
	// a misbehaving session can't OOM a neighbor.
	gvStack, gvEp, err := newTsnetRunStack(d.tsIP)
	if err != nil {
		log.Printf("daemon: gvisor stack: %v", err)
		return
	}
	defer gvStack.Close()
	startTunBridge(tunFile, gvEp, d.tsServer)
	enableTsnetTCPForwarder(gvStack, d.tsServer)

	// 4. Tell the client the bridge is up.
	if _, err := io.WriteString(c, "ATTACHED\n"); err != nil {
		return
	}

	// 5. Block until the client closes (signals session end). A read
	// here either returns EOF on a clean close or an error on abort;
	// either way we fall through to defers and tear down.
	buf := make([]byte, 256)
	for {
		_ = c.SetReadDeadline(time.Now().Add(time.Hour))
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

// daemonStartTsnet reads persisted join state (auth-key, control-url,
// gateway-ip), starts a tsnet.Server, waits for it to come up, and
// points its outbound dials at the gateway as an exit node. Returns
// the started server and our assigned 100.x address.
// Returns the started server, its tailnet IP, and a non-empty warning
// string when exit-node routing looks broken (so each `clawpatrol run`
// can repeat it on stderr instead of leaving the operator to discover
// it in daemon.log).
func daemonStartTsnet() (*tsnet.Server, netip.Addr, string, error) {
	caDir := defaultClawpatrolDir()
	stateDir := daemonStateDir()
	authKey := strings.TrimSpace(readFileSilent(filepath.Join(stateDir, "auth-key")))
	controlURL := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "control-url")))
	gwIPStr := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "tailnet-gateway-ip")))
	if authKey == "" {
		return nil, netip.Addr{}, "", fmt.Errorf("missing auth-key in %s (re-run `clawpatrol join`)", stateDir)
	}
	if gwIPStr == "" {
		return nil, netip.Addr{}, "", fmt.Errorf("missing tailnet-gateway-ip in %s (re-run `clawpatrol join`)", caDir)
	}
	gwIP, err := netip.ParseAddr(gwIPStr)
	if err != nil {
		return nil, netip.Addr{}, "", fmt.Errorf("parse tailnet-gateway-ip %q: %w", gwIPStr, err)
	}

	// Persistent state dir so the tsnet node keeps the same identity
	// (and tailnet IP, when the control plane is cooperative) across
	// idle-exit + respawn cycles. Auth keys are minted non-ephemeral,
	// so a single device row shows up on the dashboard per host
	// instead of churning one per daemon lifetime.
	tsnetDir := filepath.Join(stateDir, "tsnet")
	if err := os.MkdirAll(tsnetDir, 0o700); err != nil {
		return nil, netip.Addr{}, "", fmt.Errorf("tsnet state dir: %w", err)
	}

	hn := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "hostname")))
	if hn == "" {
		hn, _ = os.Hostname()
	}

	s := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Dir:        tsnetDir,
		Ephemeral:  false,
		Logf:       func(string, ...any) {},
	}

	log.Printf("daemon: joining tailnet as %q...", hn)
	tsIP, err := waitTsnetUp(s)
	if err != nil {
		_ = s.Close()
		return nil, netip.Addr{}, "", fmt.Errorf("waitTsnetUp: %w", err)
	}
	log.Printf("daemon: tailnet IP %s", tsIP)

	if err := setGatewayExitNode(s, gwIP); err != nil {
		_ = s.Close()
		return nil, netip.Addr{}, "", fmt.Errorf("set exit-node %s: %w", gwIP, err)
	}

	// Smoke-test exit-node routing. EditPrefs accepts ExitNodeIP
	// unconditionally, but actual routing requires the tailnet ACL to
	// auto-approve the gateway as an exit node for our tag (see
	// doc/tailscale.md → "Required tailnet ACL"). Without that, every
	// dial silently times out instead of returning a useful error.
	// Probe by dialing the gateway's tailnet IP on port 53 — that
	// port is bound by the gateway's tsnet DNS listener so a working
	// path returns "connection established" within hundreds of ms.
	var bootWarning string
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 8*time.Second)
	if c, derr := s.Dial(probeCtx, "tcp", net.JoinHostPort(gwIP.String(), "53")); derr == nil {
		_ = c.Close()
	} else {
		bootWarning = fmt.Sprintf("tsnet probe: gateway unreachable via exit-node routing (%v). "+
			"Check autoApprovers.exitNode in your tailnet ACL — see doc/tailscale.md. "+
			"Outbound traffic from `clawpatrol run` will fail until the ACL is fixed.", derr)
		log.Printf("%s", bootWarning)
	}
	probeCancel()

	// Let any code path that needs a tailnet-routed HTTP client (e.g.
	// gatewayClient → /api/env-pushdown) reach 100.x via tsnet.
	gatewayDialOverride = s.Dial

	return s, tsIP, bootWarning, nil
}

// daemonFetchEnvPushdown asks the gateway for the env-pushdown vars
// belonging to this host's profile. Returns a JSON byte slice that
// handle() ships to each new session verbatim. Best-effort: on any
// failure we cache an empty list and log; clients then run without
// pushdown until the daemon restarts.
func daemonFetchEnvPushdown(_ *tsnet.Server) []byte {
	caDir := defaultClawpatrolDir()
	vars, err := fetchEnvPushdownFromGateway(caDir)
	if err != nil {
		log.Printf("daemon: env-pushdown fetch: %v (continuing with empty set)", err)
		vars = nil
	}
	if vars == nil {
		vars = []pushdownEnvVar{}
	}
	out, err := json.Marshal(vars)
	if err != nil {
		log.Printf("daemon: env-pushdown marshal: %v", err)
		return []byte("[]")
	}
	return out
}

// daemonRegisterWithGateway POSTs this daemon's tsnet IP to the
// gateway's /api/peer/ephemeral/tsnet/register so it maps to the
// host's device row (and therefore the host's profile). Best-effort.
func daemonRegisterWithGateway(s *tsnet.Server, tsIP netip.Addr) {
	caDir := defaultClawpatrolDir()
	gwURL := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "tailnet-url")))
	if gwURL == "" {
		gwURL = strings.TrimSpace(readFileSilent(filepath.Join(caDir, "gateway")))
	}
	token := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "api-token")))
	if gwURL == "" || token == "" {
		log.Printf("daemon: register: missing gateway URL or api-token; skipping")
		return
	}
	cli := tsnetHTTPClient(s, filepath.Join(caDir, "ca.crt"))
	if err := registerEphemeralTsnetIP(cli, gwURL, token, tsIP.String()); err != nil {
		log.Printf("daemon: register: %v (default profile until next restart)", err)
	}
}

// daemonWriteStartReply writes the TSIP / ENV / WARN frames that the
// daemon emits in response to a session START. Pure framing — does
// not touch tsServer or the gVisor stack, so it's testable in
// isolation. The WARN frame is always emitted (n=0 when clean) so
// the client's parser never has to peek ahead.
func daemonWriteStartReply(w io.Writer, tsIP netip.Addr, envVars []byte, warning string) error {
	if _, err := fmt.Fprintf(w, "TSIP %s\nENV %d\n", tsIP, len(envVars)); err != nil {
		return err
	}
	if _, err := w.Write(envVars); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "WARN %d\n", len(warning)); err != nil {
		return err
	}
	if len(warning) > 0 {
		if _, err := io.WriteString(w, warning); err != nil {
			return err
		}
	}
	return nil
}

// daemonHandshake reads the client's "CLAWPATROL/1\n<nonce>\n" hello
// and echoes the nonce. Any framing error closes the conn (the client
// re-enters the spawn path on a hello failure).
func daemonHandshake(c net.Conn) error {
	_ = c.SetReadDeadline(time.Now().Add(daemonHelloTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	br := bufio.NewReader(c)
	mag, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if mag != daemonMagicLine {
		return fmt.Errorf("bad magic %q", mag)
	}
	nonce, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if _, err := io.WriteString(c, nonce); err != nil {
		return err
	}
	return nil
}

// tryExit is the race-sensitive bit. The ordering — lock, recheck,
// unlink, close, recheck, exit-or-rebind — is what makes concurrent
// connect-or-spawn safe; see the file-header comment for the protocol
// and the inline comments below for each step's rationale. The
// single os.Exit site here is load-bearing: allowing the main
// goroutine to fall out of runDaemon after serve() returns would skip
// whatever cleanup we add to this path.
func (d *daemon) tryExit() {
	if err := syscall.Flock(int(d.lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		// A client is mid-spawn-check. Back off and rearm.
		log.Printf("daemon: tryExit: lock contended (%v), rearming", err)
		d.startIdleTimer()
		return
	}
	// On any abort below we MUST release the lock and rearm. On the
	// exit path we hold it through os.Exit (kernel releases at process
	// death).

	if n := d.activeConns.Load(); n > 0 {
		log.Printf("daemon: tryExit: active=%d after lock; abort", n)
		_ = syscall.Flock(int(d.lockFile.Fd()), syscall.LOCK_UN)
		d.startIdleTimer()
		return
	}

	log.Printf("daemon: tryExit: unlinking socket")
	if err := os.Remove(d.sockPath); err != nil && !os.IsNotExist(err) {
		log.Printf("warn: unlink: %v", err)
	}
	_ = d.listener.Close()

	if n := d.activeConns.Load(); n > 0 {
		// Lost the race: a conn was accepted between our last check
		// and listener.Close(). Re-bind and keep serving. Do NOT spawn
		// a fresh serve goroutine — the main loop's <-d.rebindCh will
		// pick this up.
		log.Printf("daemon: tryExit: lost race (active=%d); re-binding", n)
		ln, err := net.Listen("unix", d.sockPath)
		if err != nil {
			log.Printf("FATAL: re-bind after lost race: %v", err)
			os.Exit(1)
		}
		_ = os.Chmod(d.sockPath, 0o600)
		d.mu.Lock()
		d.listener = ln
		d.mu.Unlock()
		_ = syscall.Flock(int(d.lockFile.Fd()), syscall.LOCK_UN)
		d.startIdleTimer()
		d.rebindCh <- struct{}{}
		return
	}

	d.mu.Lock()
	d.exited = true
	d.mu.Unlock()

	// Close tsnet politely so the control plane can mark this node
	// offline immediately rather than aging it out. Best-effort: we're
	// about to exit anyway.
	if d.tsServer != nil {
		_ = d.tsServer.Close()
	}

	log.Printf("daemon pid=%d clean exit", os.Getpid())
	os.Exit(0)
}

// daemonConnectContext is a thin context-aware wrapper used by callers
// that want to bound the total connect-or-spawn time. tsnet boot is
// the slow part; daemonSpawnTimeout already covers it.
func daemonConnectContext(ctx context.Context) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := daemonConnect()
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
