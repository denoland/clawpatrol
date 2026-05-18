//go:build linux

package main

// Auto-expose relay: tunnels TCP listeners that the wrapped command opens
// inside its netns back to the same port on the host.
//
// Mirrors ../unclaw/native/napi/src/client_linux/relay.rs:
//
//   top parent (host netns, drives WG, owns child.Wait)
//      │
//      ├── relay-supervisor (host netns, fork+exec child)
//      │     receives seccomp notify fd + sup_sock via ExtraFiles
//      │     loops: notif_recv → host listen → accept → sendmsg(fd) to worker
//      │
//      └── child (agent userns+netns, current runRunChild)
//             ├── installs seccomp filter trapping listen(2) → user_notif
//             ├── opens socketpair(worker_sock, sup_sock); ships
//             │   {notify_fd, sup_sock} back to top parent via SCM_RIGHTS
//             ├── fork+execs relay-worker (inherits agent userns+netns)
//             │     receives worker_sock on fd 3
//             │     loops: recvmsg(port, fd) → connect 127.0.0.1:port → splice
//             └── execs user cmd (still inside agent netns)
//
// The seccomp filter is inherited across the final exec, so listen() calls
// in the user's command (or its children) are what trigger the notify.

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// --- BPF + seccomp ABI (re-declared because x/sys/unix has no SockFprog
// helper for the SECCOMP_SET_MODE_FILTER syscall) ---------------------

const (
	bpfLD  = 0x00
	bpfJMP = 0x05
	bpfRET = 0x06
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJEQ = 0x10
	bpfK   = 0x00

	seccompSetModeFilter = 1

	// struct seccomp_data offsets.
	seccompDataNROffset   = 0
	seccompDataARCHOffset = 4
)

type sockFilter struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	_      [6]byte
	Filter *sockFilter
}

func bpfStmt(code uint16, k uint32) sockFilter {
	return sockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) sockFilter {
	return sockFilter{Code: code, JT: jt, JF: jf, K: k}
}

// installListenTrapFilter raises PR_SET_NO_NEW_PRIVS and installs a seccomp
// filter trapping listen(2) → SECCOMP_RET_USER_NOTIF. Returns the notify fd
// the supervisor reads via SECCOMP_IOCTL_NOTIF_RECV.
//
// Unknown architectures fall through to ALLOW so the binary stays usable;
// auto-expose simply won't fire on them.
func installListenTrapFilter() (int, error) {
	if _, _, e := unix.RawSyscall6(unix.SYS_PRCTL,
		unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); e != 0 {
		return -1, fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", e)
	}

	arch, listenNR, ok := seccompArch()
	if !ok {
		return -1, errSeccompUnsupportedArch
	}

	// if data.arch != TARGET_ARCH: ALLOW
	// if data.nr == SYS_listen: USER_NOTIF
	// else: ALLOW
	prog := []sockFilter{
		bpfStmt(bpfLD|bpfW|bpfABS, seccompDataARCHOffset),
		bpfJump(bpfJMP|bpfJEQ|bpfK, arch, 1, 0),
		bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ALLOW),
		bpfStmt(bpfLD|bpfW|bpfABS, seccompDataNROffset),
		bpfJump(bpfJMP|bpfJEQ|bpfK, listenNR, 0, 1),
		bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_USER_NOTIF),
		bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ALLOW),
	}
	fprog := sockFprog{
		Len:    uint16(len(prog)),
		Filter: &prog[0],
	}

	rc, _, e := unix.Syscall(unix.SYS_SECCOMP,
		seccompSetModeFilter,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
		uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if e != 0 {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER, NEW_LISTENER): %w", e)
	}
	return int(rc), nil
}

var errSeccompUnsupportedArch = errors.New("seccomp: unsupported architecture for listen trap")

// --- struct seccomp_notif / seccomp_notif_resp -----------------------

// seccompData mirrors `struct seccomp_data` (linux/seccomp.h).
type seccompData struct {
	NR                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

// seccompNotif is what SECCOMP_IOCTL_NOTIF_RECV fills.
type seccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  seccompData
}

// seccompNotifResp is what SECCOMP_IOCTL_NOTIF_SEND consumes.
type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

func notifRecv(fd int) (*seccompNotif, error) {
	var n seccompNotif
	_, _, e := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_RECV),
		uintptr(unsafe.Pointer(&n)))
	if e != 0 {
		return nil, e
	}
	return &n, nil
}

func notifSendContinue(fd int, id uint64) error {
	r := seccompNotifResp{
		ID:    id,
		Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE,
	}
	_, _, e := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_SEND),
		uintptr(unsafe.Pointer(&r)))
	if e != 0 {
		return e
	}
	return nil
}

// --- relay-supervisor subcommand --------------------------------------

// runRelaySupervisor is invoked by re-exec from the top parent. It reads:
//
//	fd 3: seccomp notify fd
//	fd 4: SOCK_SEQPACKET socket to the worker
//
// On each listen() trap it inspects the agent's socket, opens a host-side
// listener on the same port, and hands accepted connections to the worker.
func runRelaySupervisor(_ []string) {
	notifyFile := os.NewFile(3, "seccomp-notify")
	workerSock := os.NewFile(4, "worker-sock")
	if notifyFile == nil || workerSock == nil {
		fail("relay-supervisor: expected fds 3,4 to be open")
	}
	notifyFD := int(notifyFile.Fd())
	workerFD := int(workerSock.Fd())

	// SIGPIPE on the worker socket shouldn't kill the supervisor — log
	// from the accept goroutines instead.
	ignoreSIGPIPE()

	// SOCK_SEQPACKET is message-atomic so concurrent sendmsg don't need
	// serialization for correctness, but a mutex lets us reason about
	// retries on transient errors without races on the fd.
	var sendMu sync.Mutex

	seen := make(map[uint16]bool)
	var seenMu sync.Mutex

	listenNR := uint32(0)
	if _, nr, ok := seccompArch(); ok {
		listenNR = nr
	}

	for {
		n, err := notifRecv(notifyFD)
		if err != nil {
			// ENOENT = the filter has no remaining tasks. Normal shutdown.
			if errors.Is(err, unix.ENOENT) {
				return
			}
			fmt.Fprintf(os.Stderr, "[clawpatrol relay] notif_recv: %v\n", err)
			return
		}

		isListen := uint32(n.Data.NR) == listenNR

		if isListen {
			port, ip, family, perr := peekAgentListener(int(n.Pid), int(n.Data.Args[0]))
			// Always reply CONTINUE first so the agent's listen() proceeds.
			_ = notifSendContinue(notifyFD, n.ID)

			if perr != nil {
				fmt.Fprintf(os.Stderr, "[clawpatrol relay] inspect listen sockfd: %v\n", perr)
				continue
			}
			seenMu.Lock()
			already := seen[port]
			if !already {
				seen[port] = true
			}
			seenMu.Unlock()
			if already {
				continue
			}
			host := mirrorBindScope(family, ip)
			ln, lerr := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
			if lerr != nil {
				fmt.Fprintf(os.Stderr, "[clawpatrol relay] could not tunnel %s:%d: %v\n", host, port, lerr)
				seenMu.Lock()
				delete(seen, port)
				seenMu.Unlock()
				continue
			}
			fmt.Fprintf(os.Stderr, "[clawpatrol relay] auto-expose %s:%d → agent netns\n", host, port)
			go acceptLoop(ln, port, workerFD, &sendMu)
		} else {
			_ = notifSendContinue(notifyFD, n.ID)
		}
	}
}

// peekAgentListener returns (port, bind_ip, family) for the socket fd
// inside the agent. Tries two paths in order:
//
//  1. pidfd_open + pidfd_getfd + getsockname — preferred (race-free, the
//     socket fd is pinned via the dup'd reference for the lifetime of the
//     call). Needs PTRACE_MODE_ATTACH_REALCREDS, which under yama
//     ptrace_scope=1 means the tracee must have called
//     prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY). The agent child does
//     this before exec; PR_SET_PTRACER survives execve but is reset on
//     fork(), so direct children of the user's command that exec a
//     listener will skip this path.
//
//  2. /proc/<pid>/fd/<sockfd> readlink → inode, then scan
//     /proc/<pid>/net/tcp{,6} for a listening socket with that inode.
//     Only requires same-uid (we are), not ptrace. This covers
//     fork-then-listen patterns (shell wrappers, supervisord-style
//     launchers) that pidfd_getfd can't reach under yama.
func peekAgentListener(pid, sockfd int) (uint16, net.IP, int, error) {
	port, ip, family, pidfdErr := pidfdPeekListener(pid, sockfd)
	if pidfdErr == nil {
		return port, ip, family, nil
	}
	port, ip, family, procErr := procPeekListener(pid, sockfd)
	if procErr == nil {
		return port, ip, family, nil
	}
	return 0, nil, 0, fmt.Errorf("pidfd_getfd: %v; /proc fallback: %v", pidfdErr, procErr)
}

// pidfdPeekListener: open the agent as a pidfd, dup the socket fd over,
// getsockname. Race-free but ptrace-gated.
func pidfdPeekListener(pid, sockfd int) (uint16, net.IP, int, error) {
	pidfd, _, e := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(pid), 0, 0)
	if e != 0 {
		return 0, nil, 0, fmt.Errorf("pidfd_open(%d): %w", pid, e)
	}
	defer unix.Close(int(pidfd))

	dupfd, _, e := unix.Syscall(unix.SYS_PIDFD_GETFD, pidfd, uintptr(sockfd), 0)
	if e != 0 {
		return 0, nil, 0, fmt.Errorf("pidfd_getfd(pid=%d, fd=%d): %w", pid, sockfd, e)
	}
	defer unix.Close(int(dupfd))

	sa, err := unix.Getsockname(int(dupfd))
	if err != nil {
		return 0, nil, 0, fmt.Errorf("getsockname: %w", err)
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return uint16(a.Port), net.IP(a.Addr[:]), unix.AF_INET, nil
	case *unix.SockaddrInet6:
		return uint16(a.Port), net.IP(a.Addr[:]), unix.AF_INET6, nil
	}
	return 0, nil, 0, fmt.Errorf("unsupported sockaddr family")
}

// procPeekListener: read /proc/<pid>/fd/<sockfd> to get the socket inode,
// then scan /proc/<pid>/net/tcp{,6} for the matching TCP_LISTEN row.
//
// /proc/<pid>/net/tcp is per-netns (the kernel resolves the symlink
// against the target's net ns), so we see the agent's view — exactly
// what we want. Same-uid is enough to read both paths; yama doesn't
// apply.
func procPeekListener(pid, sockfd int) (uint16, net.IP, int, error) {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, sockfd))
	if err != nil {
		return 0, nil, 0, fmt.Errorf("readlink /proc/%d/fd/%d: %w", pid, sockfd, err)
	}
	const prefix = "socket:["
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, "]") {
		return 0, nil, 0, fmt.Errorf("not a socket fd: %q", link)
	}
	inode, err := strconv.ParseUint(link[len(prefix):len(link)-1], 10, 64)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("parse inode %q: %w", link, err)
	}

	// IPv4 entries appear in /proc/<pid>/net/tcp, IPv6 in tcp6. Try v6
	// first because dual-stack listeners (the common case for Go's
	// net.Listen("tcp", ":port")) bind via AF_INET6 with a v4-mapped
	// any address.
	for _, t := range [...]struct {
		path   string
		family int
		ipHex  int
	}{
		{fmt.Sprintf("/proc/%d/net/tcp6", pid), unix.AF_INET6, 32},
		{fmt.Sprintf("/proc/%d/net/tcp", pid), unix.AF_INET, 8},
	} {
		port, ip, ok, err := scanProcNetTcp(t.path, inode, t.ipHex)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			// Surface IO errors but keep trying the other family.
			fmt.Fprintf(os.Stderr, "[clawpatrol relay] read %s: %v\n", t.path, err)
			continue
		}
		if ok {
			return port, ip, t.family, nil
		}
	}
	return 0, nil, 0, fmt.Errorf("no TCP_LISTEN row with inode %d in /proc/%d/net/tcp{,6}", inode, pid)
}

// scanProcNetTcp scans one /proc/<pid>/net/tcp{,6} file for a row whose
// inode matches `wantInode` and whose state is TCP_LISTEN (0x0A). On
// match, returns the parsed (port, ip). On miss, returns ok=false.
func scanProcNetTcp(path string, wantInode uint64, ipHexLen int) (uint16, net.IP, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, false, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	headerSkipped := false
	for sc.Scan() {
		if !headerSkipped {
			headerSkipped = true
			continue
		}
		// Fields, 0-indexed:
		//   0 sl  1 local_address  2 rem_address  3 st  4 tx/rx  ...
		//   9 inode (1-extent count after the per-row ":" pieces)
		// We split on whitespace; column 9 is the inode for both v4
		// and v6 because the IP+port pair counts as one field each.
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[3] != "0A" { // TCP_LISTEN
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode != wantInode {
			continue
		}
		local := fields[1]
		sep := strings.IndexByte(local, ':')
		if sep < 0 || len(local[:sep]) != ipHexLen {
			return 0, nil, false, fmt.Errorf("malformed local_address %q in %s", local, path)
		}
		port64, err := strconv.ParseUint(local[sep+1:], 16, 16)
		if err != nil {
			return 0, nil, false, fmt.Errorf("parse port %q: %w", local[sep+1:], err)
		}
		ip, err := parseProcNetIPHex(local[:sep])
		if err != nil {
			return 0, nil, false, err
		}
		return uint16(port64), ip, true, nil
	}
	if err := sc.Err(); err != nil {
		return 0, nil, false, err
	}
	return 0, nil, false, nil
}

// parseProcNetIPHex decodes the local_address IP component from
// /proc/net/tcp{,6}.
//
// The kernel formats each 4-byte word of the address with %08X on the
// __be32 storage — i.e., reads each network-order word as a host-endian
// uint32 and prints it. On a little-endian host the bytes appear
// reversed within each word vs. the network representation; on a
// big-endian host they match it.
//
// Round-tripping via NativeEndian → BigEndian gives us the canonical
// network-order bytes regardless of which we're running on.
func parseProcNetIPHex(s string) (net.IP, error) {
	if len(s) != 8 && len(s) != 32 {
		return nil, fmt.Errorf("unexpected ip hex length %d", len(s))
	}
	buf, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode %q: %w", s, err)
	}
	for i := 0; i < len(buf); i += 4 {
		word := binary.NativeEndian.Uint32(buf[i:])
		binary.BigEndian.PutUint32(buf[i:], word)
	}
	return net.IP(buf), nil
}

// mirrorBindScope picks the host-side bind address: loopback if the agent
// bound loopback, otherwise unspecified (so external traffic reaches us).
func mirrorBindScope(family int, inner net.IP) string {
	switch family {
	case unix.AF_INET:
		if inner.IsLoopback() {
			return "127.0.0.1"
		}
		return "0.0.0.0"
	case unix.AF_INET6:
		if inner.IsLoopback() {
			return "::1"
		}
		return "::"
	}
	return "127.0.0.1"
}

func acceptLoop(ln net.Listener, port uint16, workerFD int, sendMu *sync.Mutex) {
	for {
		c, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[clawpatrol relay] accept on :%d ended: %v\n", port, err)
			return
		}
		fd, perr := tcpRawFD(c)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "[clawpatrol relay] raw fd on :%d: %v\n", port, perr)
			_ = c.Close()
			continue
		}
		var portBuf [2]byte
		binary.LittleEndian.PutUint16(portBuf[:], port)
		rights := unix.UnixRights(fd)
		sendMu.Lock()
		err = unix.Sendmsg(workerFD, portBuf[:], rights, nil, 0)
		sendMu.Unlock()
		_ = c.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[clawpatrol relay] sendmsg to worker on :%d: %v\n", port, err)
			return
		}
	}
}

// tcpRawFD extracts the raw fd from a *net.TCPConn for SCM_RIGHTS handoff.
// The conn keeps owning the fd; the caller closes the conn after sendmsg.
func tcpRawFD(c net.Conn) (int, error) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return -1, fmt.Errorf("not a TCPConn: %T", c)
	}
	sc, err := tcp.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	if err := sc.Control(func(rawFd uintptr) { fd = int(rawFd) }); err != nil {
		return -1, err
	}
	return fd, nil
}

// --- relay-worker subcommand ------------------------------------------

// runRelayWorker is invoked by re-exec inside the agent's userns+netns
// (inherited from its parent, the agent child process). Reads:
//
//	fd 3: SOCK_SEQPACKET socket from the supervisor
//
// Each frame is (u16 port, SCM_RIGHTS accepted fd). Connect 127.0.0.1:port
// on the agent loopback and bidi-copy.
func runRelayWorker(_ []string) {
	sock := os.NewFile(3, "supervisor-sock")
	if sock == nil {
		fail("relay-worker: expected fd 3 to be open")
	}
	sockFD := int(sock.Fd())
	ignoreSIGPIPE()

	for {
		port, fd, err := recvJob(sockFD)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			fmt.Fprintf(os.Stderr, "[clawpatrol relay-worker] recv: %v\n", err)
			return
		}
		go handleJob(port, fd)
	}
}

func recvJob(fd int) (uint16, int, error) {
	buf := make([]byte, 2)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, 0)
	if err != nil {
		return 0, -1, err
	}
	if n == 0 {
		return 0, -1, io.EOF
	}
	if n != 2 {
		return 0, -1, fmt.Errorf("short frame: %d bytes", n)
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, -1, fmt.Errorf("parse cmsg: %w", err)
	}
	for _, cm := range cmsgs {
		fds, err := unix.ParseUnixRights(&cm)
		if err == nil && len(fds) > 0 {
			// Close any extras (shouldn't happen — supervisor sends one).
			for _, extra := range fds[1:] {
				_ = unix.Close(extra)
			}
			return binary.LittleEndian.Uint16(buf), fds[0], nil
		}
	}
	return 0, -1, fmt.Errorf("no SCM_RIGHTS in frame")
}

func handleJob(port uint16, fd int) {
	incoming := os.NewFile(uintptr(fd), "host-conn")
	defer func() { _ = incoming.Close() }()

	inner, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[clawpatrol relay-worker] dial 127.0.0.1:%d: %v\n", port, err)
		return
	}
	defer func() { _ = inner.Close() }()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(inner, incoming)
		if tc, ok := inner.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(incoming, inner)
		if sc, err := incoming.SyscallConn(); err == nil {
			_ = sc.Control(func(rawFd uintptr) {
				_ = unix.Shutdown(int(rawFd), unix.SHUT_WR)
			})
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// --- arch dispatch ----------------------------------------------------

// seccompArch returns the AUDIT_ARCH constant and listen(2) syscall number
// for the host architecture. ok=false on unsupported arches; the caller
// falls back to running without auto-expose.
func seccompArch() (uint32, uint32, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_LISTEN), true
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, uint32(unix.SYS_LISTEN), true
	}
	return 0, 0, false
}

// setupRelayInChild is called by the netns child after interface plumbing
// and before exec. It installs the seccomp listen-trap, opens the worker
// socketpair, ships [notify_fd, sup_sock] up to the top parent over the
// existing parent socket, and forks the worker (which inherits this
// process's userns+netns).
//
// Best-effort: any error logs a warning and skips sending the second
// SCM_RIGHTS message. The parent's recvFDs then fails and the parent
// continues without spawning a supervisor — `clawpatrol run` still works
// for outbound-only workloads.
func setupRelayInChild(parentSock *os.File) {
	notifyFD, err := installListenTrapFilter()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ auto-expose relay: %v (continuing without it)\n", err)
		return
	}

	sp, err := unix.Socketpair(unix.AF_UNIX,
		unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ auto-expose relay: socketpair: %v\n", err)
		_ = unix.Close(notifyFD)
		return
	}
	supSock := os.NewFile(uintptr(sp[0]), "relay-sup-sock")
	workerSock := os.NewFile(uintptr(sp[1]), "relay-worker-sock")

	if err := sendFDs(parentSock, []int{notifyFD, int(supSock.Fd())}); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ auto-expose relay: send fds: %v\n", err)
		_ = supSock.Close()
		_ = workerSock.Close()
		_ = unix.Close(notifyFD)
		return
	}
	// Top parent now owns its own copies of notifyFD and supSock; drop ours.
	_ = unix.Close(notifyFD)
	_ = supSock.Close()

	if _, err := spawnRelayWorker(workerSock); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ auto-expose relay: spawn worker: %v\n", err)
	}
	_ = workerSock.Close()
}

// --- relay spawn helpers ----------------------------------------------

// spawnRelaySupervisor re-execs self as `relay-supervisor`, passing the
// seccomp notify fd and worker socket via ExtraFiles (fd 3 and fd 4).
// Returns the started *exec.Cmd; the caller does not Wait — Pdeathsig
// reaps the supervisor when the top parent exits.
func spawnRelaySupervisor(notifyFile, workerSock *os.File) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("self path: %w", err)
	}
	c := exec.Command(self, "relay-supervisor")
	c.ExtraFiles = []*os.File{notifyFile, workerSock}
	c.Stdin = nil
	c.Stdout = nil
	c.Stderr = os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	return c, nil
}

// spawnRelayWorker re-execs self as `relay-worker`, passing the worker
// end of the socketpair on fd 3. Called from inside the agent child so
// the worker inherits agent userns+netns.
//
// Pdeathsig=SIGTERM ties the worker's lifetime to its parent: when the
// agent child execs into the user cmd and that user cmd later exits,
// our PID exits, the kernel sends SIGTERM to the worker.
func spawnRelayWorker(workerSock *os.File) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("self path: %w", err)
	}
	c := exec.Command(self, "relay-worker")
	c.ExtraFiles = []*os.File{workerSock}
	c.Stdin = nil
	c.Stdout = nil
	c.Stderr = os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	return c, nil
}

// --- misc helpers -----------------------------------------------------

// ignoreSIGPIPE sets the disposition for SIGPIPE to SIG_IGN via the
// standard library. The relay processes write across socket pairs
// whose far end may close; an unhandled SIGPIPE would kill the relay
// and starve the running webhook.
func ignoreSIGPIPE() {
	signal.Ignore(syscall.SIGPIPE)
}
