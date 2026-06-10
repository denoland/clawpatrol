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

// relayDebug gates the relay / relay-worker diagnostic chatter (port
// auto-expose, the host-loopback forwarder line, per-connection
// errors). It's noise during a normal `clawpatrol run`, so it's off
// unless CLAWPATROL_DEBUG is set. Genuine functional warnings (the ⚠
// lines) print regardless. Evaluated once — the env is inherited
// across the relay-worker re-exec.
var relayDebug = func() bool {
	v := os.Getenv("CLAWPATROL_DEBUG")
	return v != "" && v != "0"
}()

// relayDebugf writes a relay diagnostic line to stderr only when
// CLAWPATROL_DEBUG is set.
func relayDebugf(format string, a ...any) {
	if relayDebug {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}

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
//	fd 4: SOCK_SEQPACKET socket to the worker (auto-expose direction:
//	      supervisor → worker, accepted host-side fds)
//	fd 5: SOCK_SEQPACKET socket from the worker (host-loopback direction:
//	      worker → supervisor, accepted agent-side fds redirected by the
//	      agent-netns iptables REDIRECT rule)
//
// On each listen() trap it inspects the agent's socket, opens a host-side
// listener on the same port, and hands accepted connections to the worker.
// In parallel, a goroutine on fd 5 receives loopback jobs and dials the
// host's 127.0.0.1:port for each.
func runRelaySupervisor(_ []string) {
	notifyFile := os.NewFile(3, "seccomp-notify")
	workerSock := os.NewFile(4, "worker-sock")
	lbSock := os.NewFile(5, "lb-sock")
	if notifyFile == nil || workerSock == nil || lbSock == nil {
		fail("relay-supervisor: expected fds 3,4,5 to be open")
	}
	notifyFD := int(notifyFile.Fd())

	// SIGPIPE on the worker socket shouldn't kill the supervisor — log
	// from the accept goroutines instead.
	ignoreSIGPIPE()

	// Hand the per-direction loops RawConns rather than raw int fds.
	// RawConn carries an internal reference to the underlying *os.File
	// (so GC can't pull the fd out from under the goroutines) and its
	// Read/Write methods integrate with the runtime poller (transient
	// EAGAIN/EWOULDBLOCK/EINTR absorbed without us writing retry logic).
	workerRC, err := workerSock.SyscallConn()
	if err != nil {
		fail("relay-supervisor: SyscallConn(worker-sock): %v", err)
	}
	lbRC, err := lbSock.SyscallConn()
	if err != nil {
		fail("relay-supervisor: SyscallConn(lb-sock): %v", err)
	}

	// The worker's first message on the lb sock is its PID. We use it to
	// suppress mirroring listen() traps from the worker itself — the
	// host-loopback forwarder is a TCP listener inside the agent netns
	// and we don't want it auto-exposed back to the host.
	workerPID, err := recvWorkerPID(lbRC)
	if err != nil {
		relayDebugf("[clawpatrol relay] read worker pid: %v\n", err)
		return
	}

	// Loopback direction: worker forwards each agent → 127.0.0.0/8:port
	// connection up to us; we dial host ip:port and bidi-copy.
	go runLoopbackSupervisorLoop(lbRC)

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
			relayDebugf("[clawpatrol relay] notif_recv: %v\n", err)
			return
		}

		isListen := uint32(n.Data.NR) == listenNR

		if isListen {
			if int(n.Pid) == workerPID {
				// Our own host-loopback forwarder calls listen(); don't
				// mirror it to the host.
				_ = notifSendContinue(notifyFD, n.ID)
				continue
			}
			port, ip, family, perr := peekAgentListener(int(n.Pid), int(n.Data.Args[0]))
			// Always reply CONTINUE first so the agent's listen() proceeds.
			_ = notifSendContinue(notifyFD, n.ID)

			if perr != nil {
				relayDebugf("[clawpatrol relay] inspect listen sockfd: %v\n", perr)
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
				relayDebugf("[clawpatrol relay] could not tunnel %s:%d: %v\n", host, port, lerr)
				seenMu.Lock()
				delete(seen, port)
				seenMu.Unlock()
				continue
			}
			relayDebugf("[clawpatrol relay] auto-expose %s:%d → agent netns\n", host, port)
			go acceptLoop(ln, port, workerRC)
		} else {
			_ = notifSendContinue(notifyFD, n.ID)
		}
	}
}

// recvWorkerPID reads the 4-byte LE PID that the worker sends as its
// first message on the loopback sock. Uses RawConn.Read so the runtime
// poller handles transient EAGAIN/EWOULDBLOCK/EINTR and the *os.File
// stays alive for the syscall's duration.
func recvWorkerPID(lbRC syscall.RawConn) (int, error) {
	var (
		pid  int
		rerr error
	)
	err := lbRC.Read(func(rawFD uintptr) (done bool) {
		buf := make([]byte, 4)
		n, _, _, _, recvErr := unix.Recvmsg(int(rawFD), buf, nil, 0)
		if recvErr != nil {
			if errors.Is(recvErr, syscall.EAGAIN) ||
				errors.Is(recvErr, syscall.EWOULDBLOCK) ||
				errors.Is(recvErr, syscall.EINTR) {
				return false
			}
			rerr = recvErr
			return true
		}
		if n != 4 {
			rerr = fmt.Errorf("short pid frame: %d bytes", n)
			return true
		}
		pid = int(binary.LittleEndian.Uint32(buf))
		return true
	})
	if err != nil {
		return 0, err
	}
	return pid, rerr
}

// runLoopbackSupervisorLoop reads (ip, port, fd) frames from the worker
// and proxies each to the host's ip:port (some address in 127.0.0.0/8).
// EOF on the sock is normal (agent netns torn down); other errors abort
// the loop.
func runLoopbackSupervisorLoop(lbRC syscall.RawConn) {
	for {
		ip, port, fd, err := recvLoopbackJob(lbRC)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			relayDebugf("[clawpatrol relay] loopback recv: %v\n", err)
			return
		}
		go handleLoopbackJob(ip, port, fd)
	}
}

// handleLoopbackJob dials the host's ip:port (the wrapped command's
// original loopback destination, recovered by the worker via
// SO_ORIGINAL_DST) and bidi-copies with the agent-side fd.
//
// ip always falls in 127.0.0.0/8 because the agent-netns REDIRECT only
// matches that block; we re-assert it defensively so a malformed frame
// can never steer the host-side dial off loopback.
func handleLoopbackJob(ip [4]byte, port uint16, fd int) {
	agentSide := os.NewFile(uintptr(fd), "agent-redirected")
	defer func() { _ = agentSide.Close() }()

	dst := net.IPv4(ip[0], ip[1], ip[2], ip[3])
	if !dst.IsLoopback() {
		relayDebugf("[clawpatrol relay] refusing non-loopback dst %s\n", dst)
		return
	}
	host, err := net.Dial("tcp", net.JoinHostPort(dst.String(), fmt.Sprintf("%d", port)))
	if err != nil {
		relayDebugf("[clawpatrol relay] dial host %s:%d: %v\n", dst, port, err)
		return
	}
	defer func() { _ = host.Close() }()

	bidiCopyTCP(agentSide, host)
}

// bidiCopyTCP runs an io.Copy in each direction between a *os.File (an fd
// adopted via SCM_RIGHTS) and a net.Conn, half-closing the writes on each
// side as the corresponding direction drains. Used by both the existing
// agent-side auto-expose worker and the new host-loopback supervisor.
func bidiCopyTCP(fileSide *os.File, connSide net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(connSide, fileSide)
		if tc, ok := connSide.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(fileSide, connSide)
		if sc, err := fileSide.SyscallConn(); err == nil {
			_ = sc.Control(func(rawFd uintptr) {
				_ = unix.Shutdown(int(rawFd), unix.SHUT_WR)
			})
		}
		done <- struct{}{}
	}()
	<-done
	<-done
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
	return 0, nil, 0, fmt.Errorf("pidfd_getfd: %w; /proc fallback: %w", pidfdErr, procErr)
}

// pidfdPeekListener: open the agent as a pidfd, dup the socket fd over,
// getsockname. Race-free but ptrace-gated.
func pidfdPeekListener(pid, sockfd int) (uint16, net.IP, int, error) {
	pidfd, _, e := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(pid), 0, 0)
	if e != 0 {
		return 0, nil, 0, fmt.Errorf("pidfd_open(%d): %w", pid, e)
	}
	defer func() { _ = unix.Close(int(pidfd)) }()

	dupfd, _, e := unix.Syscall(unix.SYS_PIDFD_GETFD, pidfd, uintptr(sockfd), 0)
	if e != 0 {
		return 0, nil, 0, fmt.Errorf("pidfd_getfd(pid=%d, fd=%d): %w", pid, sockfd, e)
	}
	defer func() { _ = unix.Close(int(dupfd)) }()

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
		port, ip, ok, err := scanProcNetTCP(t.path, inode, t.ipHex)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			// Surface IO errors but keep trying the other family.
			relayDebugf("[clawpatrol relay] read %s: %v\n", t.path, err)
			continue
		}
		if ok {
			return port, ip, t.family, nil
		}
	}
	return 0, nil, 0, fmt.Errorf("no TCP_LISTEN row with inode %d in /proc/%d/net/tcp{,6}", inode, pid)
}

// scanProcNetTCP scans one /proc/<pid>/net/tcp{,6} file for a row whose
// inode matches `wantInode` and whose state is TCP_LISTEN (0x0A). On
// match, returns the parsed (port, ip). On miss, returns ok=false.
func scanProcNetTCP(path string, wantInode uint64, ipHexLen int) (uint16, net.IP, bool, error) {
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

// acceptLoop owns one host-side listener for a port the agent opened.
// Each accepted host-side connection is shipped to the worker via
// SCM_RIGHTS over workerRC.
//
// workerRC.Write integrates with the runtime poller and takes a per-
// RawConn lock internally, so multiple acceptLoop goroutines writing
// to the same workerRC are serialized correctly without an external
// mutex, and EAGAIN/EWOULDBLOCK/EINTR on the kernel sendmsg are
// absorbed by the poll-and-retry path inside Write.
func acceptLoop(ln net.Listener, port uint16, workerRC syscall.RawConn) {
	for {
		c, err := ln.Accept()
		if err != nil {
			relayDebugf("[clawpatrol relay] accept on :%d ended: %v\n", port, err)
			return
		}
		fd, perr := tcpRawFD(c)
		if perr != nil {
			relayDebugf("[clawpatrol relay] raw fd on :%d: %v\n", port, perr)
			_ = c.Close()
			continue
		}
		var portBuf [2]byte
		binary.LittleEndian.PutUint16(portBuf[:], port)
		rights := unix.UnixRights(fd)
		err = sendJob(workerRC, portBuf[:], rights)
		_ = c.Close()
		if err != nil {
			relayDebugf("[clawpatrol relay] sendmsg to worker on :%d: %v\n", port, err)
			return
		}
	}
}

// sendJob ships one (port-frame, SCM_RIGHTS-fd) message to the worker.
// Mirrors recvJob's structure: the poller absorbs transient EAGAIN and
// the RawConn keeps the underlying *os.File alive for the syscall's
// duration.
func sendJob(rc syscall.RawConn, frame []byte, oob []byte) error {
	var serr error
	err := rc.Write(func(rawFD uintptr) (done bool) {
		e := unix.Sendmsg(int(rawFD), frame, oob, nil, 0)
		if e != nil {
			if errors.Is(e, syscall.EAGAIN) ||
				errors.Is(e, syscall.EWOULDBLOCK) ||
				errors.Is(e, syscall.EINTR) {
				return false
			}
			serr = e
			return true
		}
		return true
	})
	if err != nil {
		return err
	}
	return serr
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
//	fd 3: SOCK_SEQPACKET socket from the supervisor (auto-expose direction:
//	      supervisor → worker, each frame is u16 port + SCM_RIGHTS accepted fd;
//	      worker dials 127.0.0.1:port on the agent loopback and bidi-copies)
//	fd 4: SOCK_SEQPACKET socket to the supervisor (host-loopback direction:
//	      worker → supervisor; worker forwards each agent → 127.0.0.1:port
//	      connection that the netns iptables rule redirected to our forwarder)
//	fd 5: write end of a pipe used to signal "host-loopback forwarder + iptables
//	      rules are in place"; the agent child holds the read end and blocks
//	      its user-cmd exec until that byte arrives, eliminating the race
//	      where the wrapped command dials 127.0.0.1 before REDIRECT lands.
func runRelayWorker(_ []string) {
	sock := os.NewFile(3, "supervisor-sock")
	lbSock := os.NewFile(4, "lb-sock")
	readyPipe := os.NewFile(5, "ready-pipe")
	if sock == nil || lbSock == nil || readyPipe == nil {
		fail("relay-worker: expected fds 3,4,5 to be open")
	}
	ignoreSIGPIPE()

	rc, err := sock.SyscallConn()
	if err != nil {
		fail("relay-worker: SyscallConn(supervisor-sock): %v", err)
	}
	lbRC, err := lbSock.SyscallConn()
	if err != nil {
		fail("relay-worker: SyscallConn(lb-sock): %v", err)
	}

	// Tell the supervisor our PID so it can ignore the listen() trap
	// triggered by our own host-loopback forwarder below.
	if err := sendWorkerPID(lbRC); err != nil {
		relayDebugf("[clawpatrol relay-worker] send pid: %v\n", err)
		// Continue — supervisor's loopback loop will block on recv
		// and the auto-expose direction will still work.
	}

	// Host-loopback forwarder: TCP listener inside the agent netns plus
	// iptables NAT REDIRECT that captures every 127.0.0.0/8:* connect()
	// from the wrapped command and routes it here. Failure is logged but
	// non-fatal — the auto-expose reverse direction is independent.
	if err := setupHostLoopbackForwarder(lbRC); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ host-loopback forwarder: %v (services on host 127.0.0.1 won't be reachable from wrapped cmd)\n", err)
	}

	// Signal the agent child that REDIRECT is in place so it can exec the
	// user command. Write before entering the main loop, regardless of
	// whether the forwarder setup succeeded, so the agent child never
	// hangs waiting on us.
	_, _ = readyPipe.Write([]byte{1})
	_ = readyPipe.Close()

	relayWorkerLoop(rc, handleJob)
}

// relayWorkerLoop reads SCM_RIGHTS frames off the supervisor sock and
// dispatches each to handle in a fresh goroutine. The loop owns the
// recv side of the sock; nothing else reads from rc, so we never have
// concurrent Read calls fighting over the per-RawConn lock.
//
// Lifetime: rc carries an internal reference to the underlying *os.File,
// so as long as the loop is running the runtime can't GC the file out
// from under us. (Holding the raw int fd directly would not have that
// property — see relay_linux.go history for the failure mode that caused.)
//
// Transient errors: rc.Read integrates with the runtime poller. When the
// kernel returns EAGAIN/EWOULDBLOCK/EINTR inside the callback, we return
// false; Read parks the goroutine on the poll wait and re-runs the
// callback when the fd becomes readable. The loop never observes these
// errno classes itself — they're absorbed by the poller before the
// outer loop sees anything.
func relayWorkerLoop(rc syscall.RawConn, handle func(uint16, int)) {
	for {
		port, fd, err := recvJob(rc)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			relayDebugf("[clawpatrol relay-worker] recv: %v\n", err)
			return
		}
		go handle(port, fd)
	}
}

// sendWorkerPID writes the worker's PID as a 4-byte LE frame on the lb
// sock. The supervisor reads it first and uses it to suppress mirroring
// of our own host-loopback forwarder listener back to the host. Uses
// sendJob (RawConn.Write under the hood) so the poller absorbs transient
// EAGAIN/EWOULDBLOCK/EINTR.
func sendWorkerPID(lbRC syscall.RawConn) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(os.Getpid()))
	return sendJob(lbRC, buf[:], nil)
}

// recvJob reads one (port, SCM_RIGHTS fd) frame off the supervisor sock,
// using the RawConn's poller integration to handle transient EAGAIN /
// EWOULDBLOCK / EINTR inside the kernel without ever surfacing them to
// the caller.
func recvJob(rc syscall.RawConn) (uint16, int, error) {
	var (
		port  uint16
		jobFD = -1
		rerr  error
	)
	err := rc.Read(func(rawFD uintptr) (done bool) {
		buf := make([]byte, 2)
		oob := make([]byte, unix.CmsgSpace(4))
		n, oobn, _, _, recvErr := unix.Recvmsg(int(rawFD), buf, oob, 0)
		if recvErr != nil {
			if errors.Is(recvErr, syscall.EAGAIN) ||
				errors.Is(recvErr, syscall.EWOULDBLOCK) ||
				errors.Is(recvErr, syscall.EINTR) {
				return false
			}
			rerr = recvErr
			return true
		}
		if n == 0 {
			rerr = io.EOF
			return true
		}
		if n != 2 {
			rerr = fmt.Errorf("short frame: %d bytes", n)
			return true
		}
		jobFD, rerr = scmRightsFD(oob[:oobn])
		if rerr == nil {
			port = binary.LittleEndian.Uint16(buf)
		}
		return true
	})
	if err != nil {
		return 0, -1, err
	}
	return port, jobFD, rerr
}

// recvLoopbackJob reads a host-loopback job frame (4-byte original dst
// IP + 2-byte LE port) plus its SCM_RIGHTS fd off the lb sock. Distinct
// from recvJob, which carries only a port: the auto-expose reverse
// direction always targets the agent's own 127.0.0.1, but the host-
// loopback direction spans 127.0.0.0/8 and must ferry the address too.
func recvLoopbackJob(rc syscall.RawConn) ([4]byte, uint16, int, error) {
	var (
		ip    [4]byte
		port  uint16
		jobFD = -1
		rerr  error
	)
	err := rc.Read(func(rawFD uintptr) (done bool) {
		buf := make([]byte, loopbackFrameLen)
		oob := make([]byte, unix.CmsgSpace(4))
		n, oobn, _, _, recvErr := unix.Recvmsg(int(rawFD), buf, oob, 0)
		if recvErr != nil {
			if errors.Is(recvErr, syscall.EAGAIN) ||
				errors.Is(recvErr, syscall.EWOULDBLOCK) ||
				errors.Is(recvErr, syscall.EINTR) {
				return false
			}
			rerr = recvErr
			return true
		}
		if n == 0 {
			rerr = io.EOF
			return true
		}
		if n != loopbackFrameLen {
			rerr = fmt.Errorf("short frame: %d bytes", n)
			return true
		}
		jobFD, rerr = scmRightsFD(oob[:oobn])
		if rerr == nil {
			ip, port = decodeLoopbackFrame(buf)
		}
		return true
	})
	if err != nil {
		return [4]byte{}, 0, -1, err
	}
	return ip, port, jobFD, rerr
}

// scmRightsFD extracts the single passed fd from a control-message blob,
// closing any unexpected extras. Shared by recvJob and recvLoopbackJob.
func scmRightsFD(oob []byte) (int, error) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return -1, fmt.Errorf("parse cmsg: %w", err)
	}
	for _, cm := range cmsgs {
		fds, err := unix.ParseUnixRights(&cm)
		if err == nil && len(fds) > 0 {
			// Close any extras (shouldn't happen — sender sends one).
			for _, extra := range fds[1:] {
				_ = unix.Close(extra)
			}
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no SCM_RIGHTS in frame")
}

func handleJob(port uint16, fd int) {
	incoming := os.NewFile(uintptr(fd), "host-conn")
	defer func() { _ = incoming.Close() }()

	inner, err := dialAgentLoopback(port)
	if err != nil {
		relayDebugf("[clawpatrol relay-worker] dial 127.0.0.1:%d: %v\n", port, err)
		return
	}
	defer func() { _ = inner.Close() }()

	bidiCopyTCP(incoming, inner)
}

// dialAgentLoopback dials 127.0.0.1:port inside the agent netns with
// SO_MARK = loopbackBypassMark set on the socket. The matching iptables
// rule in the agent netns RETURNs early for marked traffic, so this dial
// reaches the agent's own listener instead of bouncing back to the host
// via the host-loopback REDIRECT.
func dialAgentLoopback(port uint16) (net.Conn, error) {
	d := net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sErr error
			err := c.Control(func(fd uintptr) {
				sErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(loopbackBypassMark))
			})
			if err != nil {
				return err
			}
			return sErr
		},
	}
	return d.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
}

// --- host-loopback forwarder (agent-netns side) -----------------------

// loopbackBypassMark is the SO_MARK value the relay-worker stamps on its
// own dials to 127.0.0.1:port so the agent-netns iptables REDIRECT rule
// lets that traffic pass through to the agent's local listener instead of
// looping back through the host. The exact value is arbitrary; we just
// need it to be unlikely to collide with marks the wrapped command might
// set itself — but the wrapped command runs without CAP_NET_ADMIN, so it
// can't set SO_MARK at all and collisions are theoretical.
const loopbackBypassMark uint32 = 0xc1aa

// soOriginalDst is SO_ORIGINAL_DST from <linux/netfilter_ipv4.h>. Not
// exported by x/sys/unix because it lives in a netfilter header.
const soOriginalDst = 80

// setupHostLoopbackForwarder binds a TCP listener on 127.0.0.1:0 inside
// the agent netns, then installs iptables NAT rules in the agent netns
// that REDIRECT every 127.0.0.0/8:* connect() from the wrapped command to
// our listener. Each accepted connection is forwarded over lbSockFD to
// the supervisor (host netns) along with the original destination IP and
// port, recovered via getsockopt(SO_ORIGINAL_DST).
//
// Threat-model notes:
//   - The listener is bound to 127.0.0.1 inside the AGENT netns. The
//     agent netns has no external connectivity except via the TUN that
//     goes to the gateway; the gateway never tunnels traffic to the
//     agent's loopback. So only the wrapped command (and its children,
//     both inside the same netns) can reach this listener.
//   - The supervisor only dials a host 127.0.0.0/8 address in response
//     to an SCM_RIGHTS frame from the worker, and the SCM_RIGHTS sock is
//     a SOCK_SEQPACKET socketpair whose worker end is held only by the
//     worker process — the wrapped command does not have it in its fd
//     table (it's a child of the agent child, not of the worker, and
//     the worker's fds aren't inherited). The dialed address comes from
//     SO_ORIGINAL_DST under a 127.0.0.0/8 REDIRECT, so it is always
//     loopback; the supervisor re-checks IsLoopback before dialing.
//   - Host-loopback services are therefore reachable only by the wrapped
//     command, never by anything routed via the gateway/tailnet.
func setupHostLoopbackForwarder(lbRC syscall.RawConn) error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not available: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen 127.0.0.1:0: %w", err)
	}
	fwdPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	if err := installLoopbackRedirectRules(fwdPort); err != nil {
		_ = ln.Close()
		return fmt.Errorf("install REDIRECT rules: %w", err)
	}
	relayDebugf("[clawpatrol relay-worker] host-loopback forwarder on 127.0.0.1:%d (REDIRECT installed)\n", fwdPort)
	go loopbackAcceptLoop(ln, lbRC)
	return nil
}

// installLoopbackRedirectRules shells out to iptables to install the two
// nat-OUTPUT rules that capture wrapped-command loopback connect()s:
//
//  1. Mark-RETURN exemption: traffic with SO_MARK = loopbackBypassMark
//     bypasses the REDIRECT so the worker's own dials to 127.0.0.1:port
//     (auto-expose reverse direction) reach the agent's local listener.
//  2. REDIRECT every other 127.0.0.0/8:port (except the forwarder's own
//     port, to avoid an obvious loop) to fwdPort.
//
// The match covers the whole 127.0.0.0/8 loopback block, not just
// 127.0.0.1: services on the host bind across the range (127.0.0.2,
// per-service aliases, etc.) and a wrapped command dialing any of them
// must reach the right host listener. The original destination address
// is recovered per-connection via SO_ORIGINAL_DST and preserved when the
// supervisor dials the host, so 127.0.0.2:p forwards to host 127.0.0.2:p,
// not 127.0.0.1:p.
//
// IPv6 (::1) is intentionally not configured here — it'd need an
// ip6tables rule with the same shape. Tracked as follow-up; the issue
// scopes IPv6 as a separate item.
func installLoopbackRedirectRules(fwdPort uint16) error {
	for _, r := range loopbackRedirectRuleArgs(fwdPort) {
		c := exec.Command("iptables", r...)
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("iptables %s: %w", strings.Join(r, " "), err)
		}
	}
	return nil
}

// loopbackRedirectRuleArgs returns the iptables argv slices that install
// the agent-netns NAT REDIRECT for host-loopback forwarding. Split out
// from installLoopbackRedirectRules so it can be unit-tested without
// shelling out to iptables.
func loopbackRedirectRuleArgs(fwdPort uint16) [][]string {
	mark := fmt.Sprintf("0x%x/0x%x", loopbackBypassMark, loopbackBypassMark)
	fwd := fmt.Sprintf("%d", fwdPort)
	return [][]string{
		{"-t", "nat", "-A", "OUTPUT", "-m", "mark", "--mark", mark, "-j", "RETURN"},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.0/8",
			"-m", "tcp", "!", "--dport", fwd, "-j", "REDIRECT", "--to-ports", fwd},
	}
}

// loopbackFrameLen is the size of a host-loopback job frame: 4-byte
// original destination IPv4 (network order) + 2-byte LE port. The IP is
// carried explicitly because the REDIRECT matches all of 127.0.0.0/8, so
// the supervisor can't assume 127.0.0.1.
const loopbackFrameLen = 6

// encodeLoopbackFrame packs the original destination (IPv4 in network
// order + port) into the wire frame ferried over the lb sock alongside
// the SCM_RIGHTS fd.
func encodeLoopbackFrame(ip [4]byte, port uint16) [loopbackFrameLen]byte {
	var f [loopbackFrameLen]byte
	copy(f[0:4], ip[:])
	binary.LittleEndian.PutUint16(f[4:6], port)
	return f
}

// decodeLoopbackFrame is the inverse of encodeLoopbackFrame.
func decodeLoopbackFrame(b []byte) (ip [4]byte, port uint16) {
	copy(ip[:], b[0:4])
	port = binary.LittleEndian.Uint16(b[4:6])
	return ip, port
}

// loopbackAcceptLoop accepts connections on the agent-side forwarder,
// extracts the original destination IP+port via SO_ORIGINAL_DST, and
// ships (ip, port, accepted_fd) to the supervisor over lbRC via
// SCM_RIGHTS. sendJob's RawConn.Write integrates with the runtime
// poller and takes a per-RawConn lock internally, so concurrent senders
// (none today, but cheap insurance) are serialised and transient EAGAIN
// is absorbed without us writing retry logic.
func loopbackAcceptLoop(ln net.Listener, lbRC syscall.RawConn) {
	for {
		c, err := ln.Accept()
		if err != nil {
			relayDebugf("[clawpatrol relay-worker] loopback accept ended: %v\n", err)
			return
		}
		fd, perr := tcpRawFD(c)
		if perr != nil {
			relayDebugf("[clawpatrol relay-worker] loopback raw fd: %v\n", perr)
			_ = c.Close()
			continue
		}
		origIP, origPort, perr := getOriginalDst(fd)
		if perr != nil {
			relayDebugf("[clawpatrol relay-worker] SO_ORIGINAL_DST: %v\n", perr)
			_ = c.Close()
			continue
		}
		frame := encodeLoopbackFrame(origIP, origPort)
		rights := unix.UnixRights(fd)
		err = sendJob(lbRC, frame[:], rights)
		_ = c.Close()
		if err != nil {
			relayDebugf("[clawpatrol relay-worker] loopback sendmsg: %v\n", err)
			return
		}
	}
}

// getOriginalDst returns the IP and port the wrapped command was trying
// to reach before iptables REDIRECT rewrote the destination, by reading
// SO_ORIGINAL_DST on the accepted socket. Conntrack remembers the original
// tuple for the lifetime of the connection; this is the same trick that
// transparent proxies use.
//
// The kernel populates a struct sockaddr_in with the original ip+port.
// sa.Addr holds the IPv4 address in network byte order (i.e. natural
// dotted-quad order: 127.0.0.2 → {127,0,0,2}), so we return it verbatim.
// sin_port is also in network byte order, so we read its in-memory bytes
// via binary.BigEndian to get the host-order value regardless of host
// endianness. With the REDIRECT now matching all of 127.0.0.0/8 the IP is
// no longer always 127.0.0.1, so the supervisor must preserve it.
func getOriginalDst(fd int) ([4]byte, uint16, error) {
	var sa unix.RawSockaddrInet4
	sz := uint32(unsafe.Sizeof(sa))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(unix.SOL_IP), uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&sa)),
		uintptr(unsafe.Pointer(&sz)),
		0,
	)
	if errno != 0 {
		return [4]byte{}, 0, errno
	}
	portBytes := (*[2]byte)(unsafe.Pointer(&sa.Port))
	return sa.Addr, binary.BigEndian.Uint16(portBytes[:]), nil
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
// and before exec. It:
//  1. Installs the seccomp listen-trap (auto-expose direction).
//  2. Opens two SOCK_SEQPACKET socketpairs:
//     - supSock / workerSock for the existing auto-expose direction
//     (supervisor → worker: accepted host-side fds).
//     - lbSupSock / lbWorkerSock for the new host-loopback direction
//     (worker → supervisor: accepted agent-side fds that the netns
//     iptables REDIRECT captured).
//  3. Opens a one-shot ready pipe so we can block the user-cmd exec
//     until the worker has installed the REDIRECT rules — otherwise the
//     wrapped command can race and dial 127.0.0.1:port before REDIRECT
//     lands, giving the issue's "host services invisible" symptom on
//     fast-starting children.
//  4. Ships [notify_fd, sup_sock, lb_sup_sock] up to the top parent
//     over the existing parent socket via SCM_RIGHTS.
//  5. Spawns the relay-worker with [worker_sock, lb_worker_sock,
//     ready_write] on fds 3,4,5.
//  6. Blocks on ready_read for one byte, then returns so the caller can
//     exec the user cmd.
//
// Best-effort: any error logs a warning and skips the rest. The parent's
// recvFDs then fails and the parent continues without spawning a
// supervisor — `clawpatrol run` still works for outbound-only workloads
// (just with no auto-expose and no host-loopback access).
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

	lbsp, err := unix.Socketpair(unix.AF_UNIX,
		unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ auto-expose relay: loopback socketpair: %v\n", err)
		_ = supSock.Close()
		_ = workerSock.Close()
		_ = unix.Close(notifyFD)
		return
	}
	lbSupSock := os.NewFile(uintptr(lbsp[0]), "relay-lb-sup-sock")
	lbWorkerSock := os.NewFile(uintptr(lbsp[1]), "relay-lb-worker-sock")

	readyR, readyW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ auto-expose relay: ready pipe: %v\n", err)
		_ = supSock.Close()
		_ = workerSock.Close()
		_ = lbSupSock.Close()
		_ = lbWorkerSock.Close()
		_ = unix.Close(notifyFD)
		return
	}

	if err := sendFDs(parentSock, []int{notifyFD, int(supSock.Fd()), int(lbSupSock.Fd())}); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ auto-expose relay: send fds: %v\n", err)
		_ = supSock.Close()
		_ = workerSock.Close()
		_ = lbSupSock.Close()
		_ = lbWorkerSock.Close()
		_ = readyR.Close()
		_ = readyW.Close()
		_ = unix.Close(notifyFD)
		return
	}
	// Top parent now owns its own copies of the three fds; drop ours.
	_ = unix.Close(notifyFD)
	_ = supSock.Close()
	_ = lbSupSock.Close()

	if _, err := spawnRelayWorker(workerSock, lbWorkerSock, readyW); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ auto-expose relay: spawn worker: %v\n", err)
		_ = workerSock.Close()
		_ = lbWorkerSock.Close()
		_ = readyR.Close()
		_ = readyW.Close()
		return
	}
	_ = workerSock.Close()
	_ = lbWorkerSock.Close()
	_ = readyW.Close()

	// Block until the worker has installed the iptables REDIRECT rule
	// (or has decided to give up on it). Either way it writes one byte
	// before its main recv loop, so this read returns promptly. If the
	// worker dies before writing, we get EOF and continue anyway — the
	// alternative is a hang on `clawpatrol run`.
	one := make([]byte, 1)
	if _, err := readyR.Read(one); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ auto-expose relay: ready signal: %v\n", err)
	}
	_ = readyR.Close()
}

// --- relay spawn helpers ----------------------------------------------

// spawnRelaySupervisor re-execs self as `relay-supervisor`, passing the
// seccomp notify fd, worker socket, and loopback supervisor socket via
// ExtraFiles (fds 3, 4, 5). Returns the started *exec.Cmd; the caller
// does not Wait — Pdeathsig reaps the supervisor when the top parent
// exits.
func spawnRelaySupervisor(notifyFile, workerSock, lbSock *os.File) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("relay-supervisor: self path: %w", err)
	}
	c := exec.Command(self, "relay-supervisor")
	c.ExtraFiles = []*os.File{notifyFile, workerSock, lbSock}
	c.Stdin = nil
	c.Stdout = nil
	c.Stderr = os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("relay-supervisor: start %s: %w", self, err)
	}
	return c, nil
}

// spawnRelayWorker re-execs self as `relay-worker`, passing on fd 3 the
// supervisor socket (auto-expose direction), on fd 4 the loopback worker
// socket (host-loopback direction), and on fd 5 the write end of the
// ready pipe. Called from inside the agent child so the worker inherits
// the agent userns+netns.
//
// Pdeathsig=SIGTERM ties the worker's lifetime to its parent: when the
// agent child execs into the user cmd and that user cmd later exits,
// our PID exits, the kernel sends SIGTERM to the worker.
func spawnRelayWorker(workerSock, lbSock, readyW *os.File) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("relay-worker: self path: %w", err)
	}
	c := exec.Command(self, "relay-worker")
	c.ExtraFiles = []*os.File{workerSock, lbSock, readyW}
	c.Stdin = nil
	c.Stdout = nil
	c.Stderr = os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("relay-worker: start %s: %w", self, err)
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
