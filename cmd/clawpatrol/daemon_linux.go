//go:build linux

package main

// Per-host self-forking daemon. `clawpatrol run` connects to a Unix
// socket; if no daemon is alive, it re-execs itself as `clawpatrol
// daemon` (a hidden subcommand) and the new process binds the socket,
// then idle-exits 5 minutes after the last client disconnects.
//
// The race-control protocol is the same one validated by the
// ~/self-fork prototype: an exclusive flock around spawn, an
// idle-timer that drops back to the lock before unlinking, a
// mandatory hello() handshake on every client connect, and a
// single-`os.Exit`-site invariant in the daemon. See the prototype's
// README for the lost-race re-bind path and the two earlier
// implementation bugs the test suite is designed to catch.
//
// For now the daemon's `handle()` only does the hello + holds the conn
// open until the client closes. The session protocol (TUN-fd passing,
// gVisor multiplexing over a shared tsnet.Server) is added in a
// follow-up.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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

	// 5. Re-exec self as `clawpatrol daemon`.
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

// daemonSpawn re-execs the current binary as `clawpatrol daemon`,
// waits for it to write "ready\n" on the inherited pipe (fd 3), then
// returns. The child detaches via Setsid and ignores SIGHUP.
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

	cmd := exec.Command(self, "daemon")
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

// runDaemon is the entry point for the `clawpatrol daemon` subcommand.
// Invoked exclusively by daemonSpawn — clients should never run this
// directly. Returns only via os.Exit from tryExit (or log.Fatal on
// fatal startup error).
func runDaemon(_ []string) {
	log.SetFlags(log.Lmicroseconds)

	dir := daemonRuntimeDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatalf("daemon: mkdir runtime: %v", err)
	}
	sockPath := daemonControlSockPath()
	lockPath := daemonSpawnLockPath()

	log.Printf("daemon pid=%d starting", os.Getpid())

	// Bind first. Parent holds the spawn lock while we do this, so we
	// can't race another daemon for the socket.
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
		sockPath: sockPath,
		listener: ln,
		lockFile: lf,
		rebindCh: make(chan struct{}),
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

// handle services a single client conn: hello handshake, then block
// until the client closes. The actual session protocol (TUN-fd via
// SCM_RIGHTS, gVisor attach) is added in a follow-up commit.
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

	// Keep the conn alive until peer closes.
	buf := make([]byte, 256)
	for {
		_ = c.SetReadDeadline(time.Now().Add(time.Hour))
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
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

// tryExit is the race-sensitive bit. Step-by-step rationale lives in
// the ~/self-fork README; the ordering here matches the prototype's
// tested version. The single os.Exit site below is load-bearing:
// allowing main goroutine to fall out of runDaemon after serve()
// returns would skip whatever cleanup we add to this path.
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
