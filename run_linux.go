//go:build linux

package main

// macHelperInstall is darwin-only — no-op on linux. login.go calls
// it from runJoin under `runtime.GOOS == "darwin"`, but the compiler
// still needs the symbol on every platform.
func macHelperInstall(wholeMachine bool) error { return nil }

// `clawpatrol run -- <cmd> [args...]` — route a single process tree's
// traffic through the gateway, leave the rest of the machine alone.
// Same shape as ../unclaw/native/napi/src/client_linux/netns.rs and
// cmusatyalab/wireguard4netns: fork a child, unshare user+net+mnt,
// open a TUN inside the child netns, ship the fd back via SCM_RIGHTS,
// run wireguard-go on that fd in init netns so its UDP socket egresses
// the host's normal default route, then exec the user's cmd inside
// the child.
//
// Unprivileged. Reuses the machine's existing WG keypair persisted at
// ~/.config/clawpatrol/wg.conf by `clawpatrol join`. Multiple
// concurrent `clawpatrol run` invocations work — each gets its own
// netns + its own peer slot via the same machine identity (single
// dashboard device).

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

const (
	runChildEnv = "CLAWPATROL_RUN_CHILD"
	tunIfName   = "wg0"
	tunMTU      = 1420
)

// runRun is `clawpatrol run`. fork the child, drive WG in this
// process, exec the user's cmd in the child.
func runRun(args []string) {
	if os.Getenv(runChildEnv) == "1" {
		runRunChild()
		return
	}

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	confPath := fs.String("conf", defaultRunConf(), "path to wg conf written by `clawpatrol join`")
	_ = fs.Parse(args)
	cmd := fs.Args()
	if len(cmd) == 0 {
		fail("usage: clawpatrol run [--conf <path>] -- <cmd> [args...]")
	}

	cfg, err := parseRunConf(*confPath)
	if err != nil {
		fail("conf %s: %v\n  hint: run `clawpatrol join --url <gw>` first", *confPath, err)
	}

	// socketpair for SCM_RIGHTS handoff of the TUN fd, plus a pipe
	// the parent uses to tell the child "wg is up, finish setup".
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fail("socketpair: %v", err)
	}
	pSock := os.NewFile(uintptr(sp[0]), "parent-sock")
	cSock := os.NewFile(uintptr(sp[1]), "child-sock")
	defer pSock.Close()
	wgUpR, wgUpW, err := os.Pipe()
	if err != nil {
		fail("pipe: %v", err)
	}

	// Re-exec self under unshare(USER|NET|MNT). Go writes uid_map +
	// gid_map for us when UidMappings/GidMappingsEnableSetgroups are
	// set. The clone happens before the runtime starts in the child,
	// so the single-thread requirement for setns(CLONE_NEWUSER) is
	// satisfied automatically.
	self, err := os.Executable()
	if err != nil {
		fail("self path: %v", err)
	}
	child := exec.Command(self, append([]string{"run"}, cmd...)...)
	child.Env = append(os.Environ(), runChildEnv+"=1")
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{cSock, wgUpR}
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}
	if err := child.Start(); err != nil {
		fail("clone: %v\n  hint: this distro may have unprivileged user namespaces disabled.\n  enable: sudo sysctl -w kernel.unprivileged_userns_clone=1", err)
	}
	cSock.Close()
	wgUpR.Close()

	// Receive the TUN fd the child opened.
	tunFd, err := recvFD(pSock)
	if err != nil {
		_ = child.Process.Kill()
		fail("recv tun fd: %v", err)
	}

	// Build a wireguard-go device on that fd. tun lives in the child
	// netns; UDP socket binds in our netns (init) so it egresses
	// through the host's default route. We wrap the fd in a minimal
	// tun.Device that returns a hardcoded MTU — wireguard-go's stock
	// linux tun queries SIOCGIFMTU/netlink which won't find wg0 (it's
	// in the child's netns). The wireguard4netns project documents
	// this exact footgun; the adapter sidesteps it without patching
	// the upstream library.
	tunDev := newRawFDTun(tunFd)
	logger := device.NewLogger(device.LogLevelError, "[clawpatrol run] ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(buildWGIpc(cfg)); err != nil {
		_ = child.Process.Kill()
		fail("wg ipc: %v", err)
	}
	if err := dev.Up(); err != nil {
		_ = child.Process.Kill()
		fail("wg up: %v", err)
	}
	defer dev.Close()

	// Tell the child WG is up — go ahead and configure addr/route + exec.
	wgUpW.Write([]byte{1})
	wgUpW.Close()

	// Forward signals to the child cmd group.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigCh {
			_ = child.Process.Signal(s)
		}
	}()

	if err := child.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fail("wait: %v", err)
	}
}

// runRunChild executes inside the unshared user+net+mnt namespaces.
// Parent passes the socketpair end as fd 3 and the wg-up pipe as fd 4.
func runRunChild() {
	cSock := os.NewFile(3, "parent-sock")
	wgUpR := os.NewFile(4, "wg-up")
	if cSock == nil || wgUpR == nil {
		fail("internal: child fds missing")
	}

	// argv after the leading "run": this is the user's cmd.
	argv := os.Args[2:]
	if len(argv) == 0 {
		fail("internal: child got empty argv")
	}

	// Open /dev/net/tun with TUNSETIFF for wg0.
	tunFd, err := openTUN(tunIfName)
	if err != nil {
		fail("open tun: %v", err)
	}

	// Send the fd to the parent.
	if err := sendFD(cSock, tunFd); err != nil {
		fail("send tun fd: %v", err)
	}
	cSock.Close()
	unix.Close(tunFd)

	// Wait for parent to bring WG up.
	one := make([]byte, 1)
	if _, err := io.ReadFull(wgUpR, one); err != nil {
		fail("wait wg-up: %v", err)
	}
	wgUpR.Close()

	// Configure wg0: link up, addr, default route, MTU. Shelling to
	// `ip` here is fine — we're inside the unshared netns, so this
	// configures wg0 not the host. Avoids a netlink dep for ~5 lines.
	cfg := mustParseRunConf(os.Getenv("CLAWPATROL_RUN_CONF"))
	addr := cfg.Address
	if !strings.Contains(addr, "/") {
		addr += "/32"
	}
	for _, a := range [][]string{
		{"ip", "link", "set", tunIfName, "mtu", fmt.Sprintf("%d", tunMTU), "up"},
		{"ip", "addr", "add", addr, "dev", tunIfName},
		{"ip", "route", "add", "default", "dev", tunIfName},
	} {
		c := exec.Command(a[0], a[1:]...)
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			fail("%s: %v", strings.Join(a, " "), err)
		}
	}

	// Bind-mount a per-run resolv.conf with a public resolver. Our
	// netns has no host interfaces — DNS only works through wg0 →
	// gateway. The gateway forwards UDP/53 like any other packet.
	// Skip if user said --keep-resolv (pass-through inherited copy).
	if os.Getenv("CLAWPATROL_RUN_KEEP_RESOLV") != "1" {
		_ = bindResolv("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
	}

	// execve the user's cmd. Replaces the child process; parent's
	// waitpid sees the cmd's exit status directly.
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		fail("lookpath %s: %v", argv[0], err)
	}
	if err := syscall.Exec(bin, argv, os.Environ()); err != nil {
		fail("exec %s: %v", bin, err)
	}
}

// --- WG conf parsing -------------------------------------------------

type runConf struct {
	PrivateKey string
	Address    string // x.y.z.w[/mask]
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
	defer f.Close()
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
	// Stash for the child re-exec to read without re-parsing.
	os.Setenv("CLAWPATROL_RUN_CONF", path)
	return c, nil
}

func mustParseRunConf(path string) *runConf {
	c, err := parseRunConf(path)
	if err != nil {
		fail("conf %s: %v", path, err)
	}
	return c
}

// buildWGIpc translates runConf into the IpcSet text format wg-go
// accepts. private/public keys must be hex; conf carries them in
// base64 (wg-quick format), so decode + re-hex.
func buildWGIpc(c *runConf) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", b64ToHex(c.PrivateKey))
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", b64ToHex(c.PeerPubKey))
	// Resolve hostname → IP — wg-go's parser wants a numeric endpoint.
	if ep, err := resolveEndpoint(c.Endpoint); err == nil {
		fmt.Fprintf(&b, "endpoint=%s\n", ep)
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=25\n")
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	return b.String()
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
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %v", errno)
	}
	return fd, nil
}

func sendFD(s *os.File, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(int(s.Fd()), []byte{0}, rights, nil, 0)
}

func recvFD(s *os.File) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(s.Fd()), buf, oob, 0)
	if err != nil {
		return -1, err
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for _, cmsg := range cmsgs {
		fds, err := unix.ParseUnixRights(&cmsg)
		if err == nil && len(fds) > 0 {
			for _, x := range fds[1:] {
				unix.Close(x)
			}
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no SCM_RIGHTS fd")
}

func bindResolv(body string) error {
	tmp, err := os.CreateTemp("", "clawpatrol-resolv-*")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	return unix.Mount(tmp.Name(), "/etc/resolv.conf", "", unix.MS_BIND, "")
}

// --- raw-fd tun adapter ---------------------------------------------

// rawFDTun is the smallest tun.Device that wireguard-go accepts.
// Reads/writes go straight to the fd; MTU returns the constant we
// configured on the iface inside the child netns. Avoids touching
// netlink/ioctl on the host side.
type rawFDTun struct {
	f      *os.File
	events chan wgtun.Event
}

func newRawFDTun(fd int) *rawFDTun {
	t := &rawFDTun{
		f:      os.NewFile(uintptr(fd), tunIfName),
		events: make(chan wgtun.Event, 1),
	}
	t.events <- wgtun.EventUp
	return t
}

func (t *rawFDTun) File() *os.File             { return t.f }
func (t *rawFDTun) Name() (string, error)      { return tunIfName, nil }
func (t *rawFDTun) MTU() (int, error)          { return tunMTU, nil }
func (t *rawFDTun) Events() <-chan wgtun.Event { return t.events }
func (t *rawFDTun) BatchSize() int             { return 1 }
func (t *rawFDTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.f.Read(bufs[0][offset:])
	if n > 0 {
		sizes[0] = n
	}
	return 1, err
}
func (t *rawFDTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if _, err := t.f.Write(b[offset:]); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}
func (t *rawFDTun) Close() error {
	close(t.events)
	return t.f.Close()
}

// --- helpers ---------------------------------------------------------

func b64ToHex(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
