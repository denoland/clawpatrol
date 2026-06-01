//go:build linux

package main

// Per-host self-forking daemon. `clawpatrol run` connects to a Unix
// socket; if no daemon is alive, it re-execs itself as `clawpatrol
// daemon-internal` (a hidden subcommand) and the new process binds
// the socket, then idle-exits 5 minutes after the last client
// disconnects.
//
// The daemon owns a single network identity (tsnet peer or WireGuard
// peer) shared across every concurrent `clawpatrol run` session on
// the host. Transport selection is decided at startup from the
// `mode` marker file written by `clawpatrol join`; per-mode
// specifics live behind the daemonTransport interface so the
// session loop, control protocol, and gVisor stack code stay
// transport-agnostic.
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
)

const (
	daemonIdleTimeout  = 5 * time.Minute
	daemonHelloTimeout = 2 * time.Second
	daemonSpawnTimeout = 30 * time.Second
	daemonMagicLine    = "CLAWPATROL/1\n"
)

// daemonTransport is the per-host network identity shared by every
// concurrent `clawpatrol run` session. Implementations:
//   - tsnetTransport (daemon_transport_tsnet_linux.go) — embeds
//     tsnet.Server, sets the gateway as its exit node; outbound
//     dials route through the gateway's tsnet RegisterFallbackTCPHandler.
//   - wgTransport (daemon_transport_wg_linux.go) — embeds a
//     wireguard-go device + gVisor stack; outbound dials hit the
//     gateway's WG L3 forwarder.
//
// Lifetime: created once at runDaemon startup, closed once on
// clean exit. Multiple sessions share the same transport — no
// per-session re-init.
type daemonTransport interface {
	// Dial opens a connection to addr (an "ip:port" string) through
	// the transport. Used by the per-session gVisor TCP forwarder
	// (TCP, "tcp") and the per-session UDP forwarder (UDP, "udp").
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	// LocalAddr is the IP the child's TUN inside its netns should
	// bind to. For tsnet it's the 100.x.x.x tailnet IP; for wg it's
	// the /32 the gateway assigned at join time.
	LocalAddr() netip.Addr
	// BootWarning is a one-line operator-facing message emitted to
	// every client that connects this lifetime, or "" when clean.
	// Each `clawpatrol run` repeats it on stderr so configuration
	// issues surface without tailing daemon.log.
	BootWarning() string
	// Close tears down the transport. Best-effort — the daemon is
	// about to exit.
	Close() error
}

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
func daemonSpawn(_ string) error {
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

	// transport is the per-host network identity. Set once at startup,
	// never replaced.
	transport daemonTransport

	// lastGoodEnv holds the most recent non-empty env-pushdown response
	// observed during this daemon's lifetime. freshEnvVars hits the
	// gateway on every call so a credential change made on the
	// dashboard (operator connects a credential, HCL reload pulls in a
	// new credential block) is visible to the very next `clawpatrol
	// run` — issue #546. lastGoodEnv only kicks in when a fetch comes
	// back empty AND a previous fetch was non-empty, to ride out
	// transient gateway errors (daemonFetchEnvPushdown returns the "[]"
	// sentinel on any failure and can't distinguish that from "no vars
	// declared"). Held under envMu — concurrent handle() goroutines
	// share the JSON byte slice.
	envMu       sync.Mutex
	lastGoodEnv []byte

	// envFetch is the fetcher freshEnvVars calls to pull the latest
	// env-pushdown JSON from the gateway. Injected so tests can stub
	// the gateway round-trip; defaults to daemonFetchEnvPushdown when
	// nil.
	envFetch func() []byte

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

	// Boot the transport first. We don't bind the control socket
	// until the daemon is fully usable — that way a parent reading
	// "ready\n" can proceed straight to a session START without
	// retries.
	transport, err := daemonStartTransport()
	if err != nil {
		log.Fatalf("daemon: transport: %v", err)
	}

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
		sockPath:  sockPath,
		listener:  ln,
		lockFile:  lf,
		transport: transport,
		rebindCh:  make(chan struct{}),
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

// daemonStartTransport picks the transport implementation based on the
// `mode` marker written by `clawpatrol join`. Tailscale mode boots a
// tsnet.Server with the gateway pinned as its exit node; WireGuard
// mode boots a wireguard-go device + gVisor stack from the persisted
// wg.conf. Either way, the returned transport carries one network
// identity shared by every `clawpatrol run` on this host.
func daemonStartTransport() (daemonTransport, error) {
	modeFile := filepath.Join(defaultClawpatrolDir(), "mode")
	mode := strings.TrimSpace(readFileSilent(modeFile))
	switch mode {
	case "tailscale":
		return startTsnetTransport()
	case "wireguard":
		return startWGTransport()
	case "":
		// No mode file: either a legacy WG join (older builds didn't write
		// the marker) or join never completed / wrote nothing (permission
		// error on clawDir). Distinguish by checking for wg.conf.
		if _, err := os.Stat(defaultRunConf()); err == nil {
			return startWGTransport()
		}
		return nil, fmt.Errorf("no mode file at %s and no wg.conf — re-run `clawpatrol join`", modeFile)
	default:
		return nil, fmt.Errorf("unknown mode %q in %s — re-run `clawpatrol join`", mode, modeFile)
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
//	daemon → client:  "ADDR <ip>\n" "ENV <n>\n" <n bytes JSON>
//	                  "WARN <m>\n" <m bytes text>
//	client → daemon:  SCM_RIGHTS carrying one TUN fd (payload byte 0)
//	daemon → client:  "ATTACHED\n"
//	client → daemon:  (control conn stays open; close = session end)
//
// On close the per-session gVisor stack tears down, the TUN fd is
// released, and any in-flight conns through the transport drain.
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
	_ = c.SetReadDeadline(time.Time{})

	switch line {
	case "START\n":
		// fall through below
	case "ENV\n":
		// Lightweight query: ship the env-pushdown JSON and return.
		// No TUN handoff, no per-session gVisor stack — `clawpatrol
		// env` is a one-shot read, not a wrapped child. Without this
		// branch the env subcommand has no tailnet route to the
		// gateway from its own process (the daemon's tsnet.Server is
		// process-local), and the direct fetch silently times out in
		// tsnet-only deployments.
		if err := daemonWriteEnvReply(c, d.freshEnvVars()); err != nil {
			log.Printf("daemon: ENV reply: %v", err)
		}
		return
	default:
		log.Printf("daemon: unknown command %q", line)
		return
	}

	// 1. Tell the client our underlay IP, ship the env-pushdown JSON,
	// and pass along any one-line warning the transport's boot probe
	// generated.
	if err := daemonWriteStartReply(c, d.transport.LocalAddr(), d.freshEnvVars(), d.transport.BootWarning()); err != nil {
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
	// the daemon's single transport but each gets its own stack so a
	// misbehaving session can't OOM a neighbor.
	gvStack, gvEp, err := newRunStack(d.transport.LocalAddr())
	if err != nil {
		log.Printf("daemon: gvisor stack: %v", err)
		return
	}
	defer gvStack.Close()
	startTunBridge(tunFile, gvEp, d.transport)
	enableTransportTCPForwarder(gvStack, d.transport)

	// 4. Tell the client the bridge is up.
	if _, err := io.WriteString(c, "ATTACHED\n"); err != nil {
		return
	}

	// 5. Block until the client closes (signals session end).
	daemonWaitForClientClose(c)
}

func daemonWaitForClientClose(c net.Conn) {
	buf := make([]byte, 256)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

// freshEnvVars fetches the env-pushdown JSON from the gateway on
// every call so a credential change made on the dashboard (operator
// connects a credential, HCL reload pulls in a new credential block)
// is visible to the next `clawpatrol run` without a daemon restart
// (#546). The gateway lives on-tailnet so the round-trip is sub-50ms;
// agent sessions are not noticeably slower, and an idle daemon
// generates no traffic.
//
// daemonFetchEnvPushdown returns the "[]" sentinel on any fetch
// failure and can't distinguish that from "no vars declared". If a
// fetch comes back empty and we previously observed a non-empty list
// in this daemon's lifetime, serve that last-known-good list rather
// than silently dropping pushdown vars on a transient blip.
func (d *daemon) freshEnvVars() []byte {
	fresh := d.fetchEnv()
	d.envMu.Lock()
	defer d.envMu.Unlock()
	if isEmptyEnvList(fresh) && !isEmptyEnvList(d.lastGoodEnv) {
		return d.lastGoodEnv
	}
	if !isEmptyEnvList(fresh) {
		d.lastGoodEnv = fresh
	}
	return fresh
}

// fetchEnv resolves the env-pushdown fetcher to use. Defaults to the
// gateway-dialing daemonFetchEnvPushdown; tests inject a stub via the
// envFetch field. The function value itself is immutable after daemon
// construction, so no envMu required.
func (d *daemon) fetchEnv() []byte {
	if d.envFetch != nil {
		return d.envFetch()
	}
	return daemonFetchEnvPushdown()
}

// isEmptyEnvList recognises the two encodings of "no push-down vars"
// the daemon writes: empty bytes (uninitialised) and "[]" (the
// daemonFetchEnvPushdown error-case sentinel).
func isEmptyEnvList(b []byte) bool {
	switch string(b) {
	case "", "[]":
		return true
	}
	return false
}

// daemonFetchEnvPushdown asks the gateway for the env-pushdown vars
// belonging to this host's profile. Returns a JSON byte slice that
// handle() ships to each new session verbatim. Best-effort: on any
// failure we cache an empty list and log; clients then run without
// pushdown until the daemon restarts.
func daemonFetchEnvPushdown() []byte {
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

// daemonWriteEnvReply writes a single "ENV <n>\n<n bytes>" frame —
// the cached env-pushdown JSON. Used by the lightweight ENV control
// command (no session, no TUN handoff).
func daemonWriteEnvReply(w io.Writer, envVars []byte) error {
	if _, err := fmt.Fprintf(w, "ENV %d\n", len(envVars)); err != nil {
		return err
	}
	if len(envVars) > 0 {
		if _, err := w.Write(envVars); err != nil {
			return err
		}
	}
	return nil
}

// daemonWriteStartReply writes the ADDR / ENV / WARN frames that the
// daemon emits in response to a session START. Pure framing — does
// not touch the transport or the gVisor stack, so it's testable in
// isolation. The WARN frame is always emitted (n=0 when clean) so
// the client's parser never has to peek ahead.
func daemonWriteStartReply(w io.Writer, addr netip.Addr, envVars []byte, warning string) error {
	if _, err := fmt.Fprintf(w, "ADDR %s\nENV %d\n", addr, len(envVars)); err != nil {
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

	// Close the transport politely so any upstream state (tsnet
	// control plane registration, wireguard-go device, etc.) can
	// settle before we exit.
	if d.transport != nil {
		_ = d.transport.Close()
	}

	log.Printf("daemon pid=%d clean exit", os.Getpid())
	os.Exit(0)
}
