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
	"time"
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

// relaySupervisorFiles keeps *os.File wrappers reachable for the
// lifetime of the relay-supervisor subprocess.
//
// The wrappers' finalizers close the underlying fd; without a
// long-lived reference the wrapper goes unreachable as soon as we
// extract the raw fd via .Fd(), and a later GC run closes the fd from
// under us. That manifested in production as "notif_recv: bad file
// descriptor" (denoland/orchid#175).
//
// Only the seccomp notify fd needs this: the worker socket is driven
// through a SyscallConn (workerRC), which carries its own internal
// reference to the *os.File. The relay-worker's supervisor socket is
// likewise pinned by its SyscallConn.
//
// Accessed only from runRelaySupervisor, so concurrent access is not a
// concern.
var relaySupervisorFiles = map[*os.File]struct{}{}

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

	// os.NewFile attaches a finalizer to the *os.File that closes the
	// underlying fd when it gets GC'd. Once we extract the raw fd via
	// .Fd() we never touch notifyFile again, so liveness analysis can
	// mark it dead — and a later finalizer run then closes fd 3 from
	// under the next ioctl(NOTIF_RECV), which surfaces as
	// "notif_recv: bad file descriptor". (Observed in
	// denoland/orchid#175.)
	//
	// We can't clear the finalizer directly: os.File sets it on its
	// unexported inner struct, not on *File. Instead, hold a
	// package-level reference so the wrapper stays reachable for the
	// lifetime of the process — the supervisor never returns from its
	// receive loop until the process is about to exit anyway.
	//
	// workerSock needs no such pin: workerRC (its SyscallConn, below)
	// already carries an internal reference to the *os.File.
	relaySupervisorFiles[notifyFile] = struct{}{}

	// SIGPIPE on the worker socket shouldn't kill the supervisor — log
	// from the accept goroutines instead.
	ignoreSIGPIPE()

	// Hand each acceptLoop a RawConn over workerSock rather than the raw
	// int fd. The RawConn carries an internal reference to the *os.File,
	// so the runtime can't GC workerSock out from under the goroutines
	// and Write integrates with the poller (transient EAGAIN absorbed
	// without us writing retry logic).
	workerRC, err := workerSock.SyscallConn()
	if err != nil {
		fail("relay-supervisor: SyscallConn(worker-sock): %v", err)
	}

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

		if !isListen {
			_ = notifSendContinue(notifyFD, n.ID)
			continue
		}

		// Two-phase inspection so the trapped listen() doesn't stall
		// behind our work — and, more importantly, so the /proc
		// fallback can find a TCP_LISTEN row (which only exists
		// after listen() actually runs).
		capture := captureBeforeContinue(int(n.Pid), int(n.Data.Args[0]))
		_ = notifSendContinue(notifyFD, n.ID)
		port, ip, family, perr := capture.resolveAfterContinue()
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
		go acceptLoop(ln, port, workerRC)
	}
}

// listenerCapture inspects an in-flight, seccomp-trapped listen(2) call
// in two phases:
//
//	c := captureBeforeContinue(pid, sockfd)
//	_ = notifSendContinue(notifyFD, n.ID)
//	port, ip, family, err := c.resolveAfterContinue()
//
// The pidfd path (preferred, race-free) yields a final answer in the
// pre-continue phase: getsockname(2) works on a bound but not-yet-
// listening socket, and the dup'd fd pins the kernel socket for the
// lifetime of the call.
//
// The /proc fallback can only capture the socket *inode* pre-continue —
// the matching TCP_LISTEN row in /proc/<pid>/net/tcp{,6} won't exist
// until listen(2) actually runs, which is gated on the supervisor
// sending SECCOMP_USER_NOTIF_FLAG_CONTINUE. The post-continue phase
// polls for that row with a short bounded timeout.
//
// Why the fallback matters:
//
//   - pidfd_open(tid) returns EINVAL when the trapped listen() came from
//     a non-leader thread (the seccomp notify pid field carries the TID,
//     not the TGID). Older kernels (<6.10) have no PIDFD_THREAD escape
//     hatch, so multi-threaded agents always need /proc.
//   - pidfd_getfd is gated by PTRACE_MODE_ATTACH_REALCREDS. Under yama
//     ptrace_scope=1 the tracee must call PR_SET_PTRACER; we do this in
//     the agent child, but it survives execve and not fork(), so any
//     fork-then-listen pattern (shell wrappers, supervisord-style
//     launchers) skips the pidfd path.
//
// In both cases /proc/<pid>/fd/<fd> + /proc/<pid>/net/tcp{,6} works:
// the kernel resolves /proc/<pid>/net symlinks against the target's
// net namespace, and same-uid is enough.
type listenerCapture struct {
	pid      int
	sockfd   int
	procRoot string

	// pidfd path: if non-nil, captureBeforeContinue produced a final
	// answer and resolveAfterContinue just returns it.
	pidfd *listenerInfo

	// /proc path: inode captured pre-continue via readlink. ok=false
	// means the readlink itself failed, so the fallback has nothing
	// to poll for.
	inode    uint64
	inodeOK  bool
	inodeErr error

	pidfdErr error

	// Tunable from tests. Defaults set by captureBeforeContinue.
	pollTimeout time.Duration
	pollFloor   time.Duration
	pollCeil    time.Duration
}

type listenerInfo struct {
	port   uint16
	ip     net.IP
	family int
}

// procFallbackTimeout is the post-continue budget for the kernel to
// transition the trapped socket into TCP_LISTEN once we send CONTINUE.
// In practice this lands well under 1ms on idle machines; the ceiling
// is generous to cover scheduler hiccups on busy hosts without making
// the trap latency user-visible.
const procFallbackTimeout = 500 * time.Millisecond

// captureBeforeContinue runs the pre-continue half of the two-phase
// inspection. It is safe to call before notifSendContinue: it never
// touches the trapped syscall, only the agent's fd table and /proc.
func captureBeforeContinue(pid, sockfd int) *listenerCapture {
	c := &listenerCapture{
		pid:         pid,
		sockfd:      sockfd,
		procRoot:    "/proc",
		pollTimeout: procFallbackTimeout,
		pollFloor:   1 * time.Millisecond,
		pollCeil:    25 * time.Millisecond,
	}
	c.capture()
	return c
}

func (c *listenerCapture) capture() {
	port, ip, family, pidfdErr := pidfdPeekListener(c.pid, c.sockfd)
	if pidfdErr == nil {
		c.pidfd = &listenerInfo{port: port, ip: ip, family: family}
		return
	}
	c.pidfdErr = pidfdErr
	// pidfd path lost — capture the inode now while the agent's fd
	// is guaranteed still open (seccomp is still holding listen()).
	inode, err := procReadSocketInode(c.procRoot, c.pid, c.sockfd)
	if err != nil {
		c.inodeErr = err
		return
	}
	c.inode = inode
	c.inodeOK = true
}

// resolveAfterContinue produces the final answer for a listener. Must be
// called after notifSendContinue has released the trapped listen(); for
// the /proc path the kernel only inserts the TCP_LISTEN row at that
// point.
func (c *listenerCapture) resolveAfterContinue() (uint16, net.IP, int, error) {
	if c.pidfd != nil {
		return c.pidfd.port, c.pidfd.ip, c.pidfd.family, nil
	}
	if !c.inodeOK {
		return 0, nil, 0, fmt.Errorf("pidfd_getfd: %w; /proc fallback: %w", c.pidfdErr, c.inodeErr)
	}
	port, ip, family, err := procPollForListen(c.procRoot, c.pid, c.inode, c.pollTimeout, c.pollFloor, c.pollCeil)
	if err == nil {
		return port, ip, family, nil
	}
	return 0, nil, 0, fmt.Errorf("pidfd_getfd: %w; /proc fallback: %w", c.pidfdErr, err)
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

// procReadSocketInode reads /proc/<pid>/fd/<sockfd> and parses out the
// socket inode encoded in the readlink target ("socket:[NNN]"). Cheap
// and safe to call pre-continue: it only inspects the kernel-side fd
// table, not the socket's connection state.
func procReadSocketInode(procRoot string, pid, sockfd int) (uint64, error) {
	path := fmt.Sprintf("%s/%d/fd/%d", procRoot, pid, sockfd)
	link, err := os.Readlink(path)
	if err != nil {
		return 0, fmt.Errorf("readlink %s: %w", path, err)
	}
	const prefix = "socket:["
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, "]") {
		return 0, fmt.Errorf("not a socket fd: %q", link)
	}
	inode, err := strconv.ParseUint(link[len(prefix):len(link)-1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse inode %q: %w", link, err)
	}
	return inode, nil
}

// procPollForListen polls /proc/<pid>/net/tcp{,6} for `inode` in
// TCP_LISTEN state, with exponential backoff up to `timeout`. Returns
// the first successful (port, ip, family) or a descriptive timeout
// error.
//
// Why polling: the supervisor sends CONTINUE and immediately races the
// kernel's TCP_LISTEN transition. On amd64 with a warm scheduler this
// typically lands in <1 ms; we cap the polling to keep relay overhead
// bounded even on contended hosts.
func procPollForListen(procRoot string, pid int, inode uint64, timeout, pollFloor, pollCeil time.Duration) (uint16, net.IP, int, error) {
	// IPv4 entries appear in /proc/<pid>/net/tcp, IPv6 in tcp6. Try
	// v6 first because dual-stack listeners (the common case for Go's
	// net.Listen("tcp", ":port")) bind via AF_INET6 with a v4-mapped
	// any address.
	targets := [...]struct {
		path   string
		family int
		ipHex  int
	}{
		{fmt.Sprintf("%s/%d/net/tcp6", procRoot, pid), unix.AF_INET6, 32},
		{fmt.Sprintf("%s/%d/net/tcp", procRoot, pid), unix.AF_INET, 8},
	}
	deadline := time.Now().Add(timeout)
	backoff := pollFloor
	attempts := 0
	for {
		attempts++
		for _, t := range targets {
			port, ip, ok, err := scanProcNetTCP(t.path, inode, t.ipHex)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				// Surface IO errors but keep trying the other
				// family / a later poll iteration.
				fmt.Fprintf(os.Stderr, "[clawpatrol relay] read %s: %v\n", t.path, err)
				continue
			}
			if ok {
				return port, ip, t.family, nil
			}
		}
		if time.Now().After(deadline) {
			return 0, nil, 0, fmt.Errorf("no TCP_LISTEN row with inode %d in %s/%d/net/tcp{,6} after %v (%d polls)", inode, procRoot, pid, timeout, attempts)
		}
		time.Sleep(backoff)
		backoff *= 2
		if backoff > pollCeil {
			backoff = pollCeil
		}
	}
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
		err = sendJob(workerRC, portBuf[:], rights)
		_ = c.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[clawpatrol relay] sendmsg to worker on :%d: %v\n", port, err)
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
//	fd 3: SOCK_SEQPACKET socket from the supervisor
//
// Each frame is (u16 port, SCM_RIGHTS accepted fd). Connect 127.0.0.1:port
// on the agent loopback and bidi-copy.
func runRelayWorker(_ []string) {
	sock := os.NewFile(3, "supervisor-sock")
	if sock == nil {
		fail("relay-worker: expected fd 3 to be open")
	}
	ignoreSIGPIPE()

	rc, err := sock.SyscallConn()
	if err != nil {
		fail("relay-worker: SyscallConn(supervisor-sock): %v", err)
	}
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
			fmt.Fprintf(os.Stderr, "[clawpatrol relay-worker] recv: %v\n", err)
			return
		}
		go handle(port, fd)
	}
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
			// EAGAIN/EWOULDBLOCK: no message queued yet — ask the poller
			// to wait for readability and re-run us. EINTR: a signal ran
			// during recvmsg; same shape, retry.
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
		cmsgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
		if perr != nil {
			rerr = fmt.Errorf("parse cmsg: %w", perr)
			return true
		}
		for _, cm := range cmsgs {
			fds, perr := unix.ParseUnixRights(&cm)
			if perr == nil && len(fds) > 0 {
				// Close any extras (shouldn't happen — supervisor sends one).
				for _, extra := range fds[1:] {
					_ = unix.Close(extra)
				}
				port = binary.LittleEndian.Uint16(buf)
				jobFD = fds[0]
				return true
			}
		}
		rerr = fmt.Errorf("no SCM_RIGHTS in frame")
		return true
	})
	if err != nil {
		return 0, -1, err
	}
	return port, jobFD, rerr
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
		return nil, fmt.Errorf("relay-supervisor: self path: %w", err)
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
		return nil, fmt.Errorf("relay-supervisor: start %s: %w", self, err)
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
		return nil, fmt.Errorf("relay-worker: self path: %w", err)
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
