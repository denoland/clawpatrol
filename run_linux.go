//go:build linux

package main

// `clawpatrol run -- <cmd> [args...]` — route a single process tree's
// traffic through the gateway, leave the rest of the machine alone.
//
// Mirrors ../unclaw/native/napi/src/client_linux/netns.rs capability model:
//   - child holds CAP_NET_ADMIN when calling TUNSETIFF (via ambient, survives exec)
//   - ip subprocesses inherit CAP_NET_ADMIN (ambient propagates through exec chain)
//   - user's final command does NOT hold CAP_NET_ADMIN (ambient cleared before exec)
//
// Implementation: re-exec self with CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS +
// AmbientCaps=[CAP_NET_ADMIN]. Go's forkAndExecInChild raises ambient before
// the exec, so the re-exec'd child has CAP_NET_ADMIN in effective from the
// start — no exec has cleared it yet when TUNSETIFF runs.
//
// unclaw uses fork()+unshare() (never re-execs before TUNSETIFF). The effect
// on capabilities is identical: TUNSETIFF sees effective CAP_NET_ADMIN,
// ip subprocesses inherit it, the user's cmd gets nothing.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
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

// runRun is `clawpatrol run`. Re-execs self in new user+net+mnt namespaces
// with CAP_NET_ADMIN in the ambient set, drives WireGuard in this process,
// and execs the user's cmd inside the child.
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
		fail("conf %s: %v\n  hint: run `clawpatrol join <gw>` first", *confPath, err)
	}

	checkUserNS()

	// Stamp CA + per-credential env vars; child and user's cmd inherit them.
	applyEnvPushdown(defaultClawpatrolDir())

	// Allocate a per-run ephemeral WireGuard identity so concurrent
	// `clawpatrol run` invocations on the same machine don't share a
	// keypair and fight over the gateway's WG session.
	cleanupEphemeral, _ := ephemeralPeer(cfg)
	defer cleanupEphemeral()

	// socketpair: TUN fd handoff (child→parent) via SCM_RIGHTS.
	// pipe: parent signals child "WG is up, finish setup".
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fail("socketpair: %v", err)
	}
	pSock := os.NewFile(uintptr(sp[0]), "parent-sock")
	cSock := os.NewFile(uintptr(sp[1]), "child-sock")
	defer func() { _ = pSock.Close() }()
	wgUpR, wgUpW, err := os.Pipe()
	if err != nil {
		fail("pipe: %v", err)
	}

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
		fail("clone: %v\n  hint: this distro may have unprivileged user namespaces disabled.\n  enable: sudo sysctl -w kernel.unprivileged_userns_clone=1", err)
	}
	_ = cSock.Close()
	_ = wgUpR.Close()

	tunFd, err := recvFD(pSock)
	if err != nil {
		_ = child.Process.Kill()
		fail("recv tun fd: %v", err)
	}

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

	_, _ = wgUpW.Write([]byte{1})
	_ = wgUpW.Close()

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigCh {
			_ = child.Process.Signal(s)
		}
	}()

	if err := child.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fail("wait: %v", err)
	}
}

// runRunChild executes inside the unshared user+net+mnt namespaces.
// Receives its socket on fd 3 and the wg-up pipe on fd 4.
// Has CAP_NET_ADMIN in effective (via ambient set from parent's AmbientCaps).
func runRunChild() {
	cSock := os.NewFile(3, "parent-sock")
	wgUpR := os.NewFile(4, "wg-up")

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
	_ = cSock.Close()
	_ = unix.Close(tunFd)

	one := make([]byte, 1)
	if _, err := io.ReadFull(wgUpR, one); err != nil {
		fail("wait wg-up: %v", err)
	}
	_ = wgUpR.Close()

	cfg := mustParseRunConf(os.Getenv("CLAWPATROL_RUN_CONF"))
	// CLAWPATROL_EPHEMERAL_ADDR overrides cfg.Address when the parent
	// successfully registered an ephemeral WG identity for this run.
	addrSource := cfg.Address
	if ea := os.Getenv("CLAWPATROL_EPHEMERAL_ADDR"); ea != "" {
		addrSource = ea
	}
	addrs := splitWGAddresses(addrSource)
	if len(addrs) == 0 {
		fail("wg conf: empty Address")
	}
	steps := [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "set", tunIfName, "mtu", fmt.Sprintf("%d", tunMTU), "up"},
	}
	for _, a := range addrs {
		steps = append(steps, []string{"ip", "addr", "add", a, "dev", tunIfName})
	}
	steps = append(steps, []string{"ip", "route", "add", "default", "dev", tunIfName})
	for _, a := range steps {
		c := exec.Command(a[0], a[1:]...)
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			fail("%s: %v", strings.Join(a, " "), err)
		}
	}

	if os.Getenv("CLAWPATROL_RUN_KEEP_RESOLV") != "1" {
		_ = bindResolv("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
	}

	// Clear ambient caps before exec so the user's command does not inherit
	// CAP_NET_ADMIN. Mirrors clear_ambient_caps() in unclaw netns.rs.
	if err := clearAmbientCaps(); err != nil {
		fail("clear ambient caps: %v", err)
	}

	bin, err := exec.LookPath(argv[0])
	if err != nil {
		fail("lookpath %s: %v", argv[0], err)
	}
	if err := syscall.Exec(bin, argv, os.Environ()); err != nil {
		fail("exec %s: %v", bin, err)
	}
}

// --- capability manipulation -------------------------------------------------

const (
	capNetAdmin = uintptr(12) // CAP_NET_ADMIN
	capSysAdmin = uintptr(21) // CAP_SYS_ADMIN — needed for bind-mount in mnt ns
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

// splitWGAddresses parses a wg-quick `Address =` value into one CIDR per
// element. Dual-stack peers receive a comma-joined string like
// `10.55.0.5/32, fd77::5/128`; `ip addr add` rejects that whole string as
// a single prefix, so we split + emit one `ip addr add` per element.
//
// Whitespace around elements is trimmed and empty elements are dropped.
// Elements without an explicit `/prefix` get a host route (`/32` for v4,
// `/128` for v6).
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

// --- WG conf parsing -------------------------------------------------

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
	_ = os.Setenv("CLAWPATROL_RUN_CONF", path)
	return c, nil
}

func mustParseRunConf(path string) *runConf {
	c, err := parseRunConf(path)
	if err != nil {
		fail("conf %s: %v", path, err)
	}
	return c
}

func buildWGIpc(c *runConf) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", b64ToHex(c.PrivateKey))
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", b64ToHex(c.PeerPubKey))
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
				_ = unix.Close(x)
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
		_ = tmp.Close()
		return err
	}
	_ = tmp.Close()
	return unix.Mount(tmp.Name(), "/etc/resolv.conf", "", unix.MS_BIND, "")
}

// --- raw-fd tun adapter ---------------------------------------------

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

// --- ephemeral peer --------------------------------------------------

// ephemeralCacheFile is the on-disk record of this host's ephemeral
// WireGuard identity. Concurrent and sequential `clawpatrol run`
// invocations on the same host share it: the first run generates the
// keypair + registers it with the gateway; every subsequent run reads
// the cache and POSTs the SAME pubkey so the gateway returns the
// existing /32 instead of allocating a new one. Without this every
// invocation produced a fresh peer + a new dashboard row.
const ephemeralCacheFile = "wg-ephemeral.json"

type ephemeralCache struct {
	GatewayURL string `json:"gateway_url"` // invalidates the cache when the host re-joins a different gateway
	PrivateKey string `json:"private_key"` // base64
	PublicHex  string `json:"public_hex"`  // hex (the form sent to gateway)
	IP         string `json:"ip"`          // v4 /32 assigned by gateway
	IP6        string `json:"ip6"`         // v6 /128
}

// ephemeralPeer registers (or reuses) this host's ephemeral WireGuard
// identity with the gateway, mutates cfg to use the ephemeral private
// key and address, and sets CLAWPATROL_EPHEMERAL_ADDR so the re-exec'd
// child uses the ephemeral IP for `ip addr add`. Returns a cleanup
// func — currently a no-op, since the identity is persisted across
// runs and a normal exit must not invalidate concurrent siblings.
//
// Best-effort: any failure logs a warning and returns a no-op cleanup
// so the caller falls back to the shared permanent identity.
func ephemeralPeer(cfg *runConf) (cleanup func(), err error) {
	noop := func() {}
	dir := defaultClawpatrolDir()

	gwURL := strings.TrimSpace(readFileSilent(filepath.Join(dir, "gateway")))
	token := strings.TrimSpace(readFileSilent(filepath.Join(dir, "api-token")))
	if gwURL == "" || token == "" {
		return noop, fmt.Errorf("ephemeral peer: no gateway url or api-token")
	}

	client, err := gatewayHTTPClient(filepath.Join(dir, "ca.crt"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ ephemeral peer: build http client: %v (using shared identity)\n", err)
		return noop, err
	}

	// Acquire a flock on the cache so concurrent runs serialize their
	// read-or-mint step. With this in place the second run sees the
	// first run's keypair in the cache and reuses it instead of
	// generating its own — that's the whole point of the cache.
	cachePath := filepath.Join(dir, ephemeralCacheFile)
	unlock, err := acquireEphemeralLock(cachePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ ephemeral peer: lock cache: %v (using shared identity)\n", err)
		return noop, err
	}
	defer unlock()

	cached, _ := readEphemeralCache(cachePath)
	if cached != nil && cached.GatewayURL != gwURL {
		// Gateway URL changed (host re-joined a different gateway) —
		// the cached pubkey is bound to a parent on the old gateway
		// and would be rejected on the new one. Discard.
		cached = nil
	}

	var (
		privB64 string
		pubHex  string
	)
	if cached != nil {
		privB64 = cached.PrivateKey
		pubHex = cached.PublicHex
	} else {
		privB64, pubHex, _, err = wgGenKeypair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ ephemeral peer: keygen: %v (using shared identity)\n", err)
			return noop, err
		}
	}

	ip, ip6, err := postEphemeralPeer(client, gwURL, token, pubHex)
	if err != nil && cached != nil {
		// Cache was stale (gateway-side eviction, DB wipe, peer manually
		// removed). Mint a fresh keypair and retry exactly once.
		fmt.Fprintf(os.Stderr, "⚠ ephemeral peer: reuse failed (%v); minting fresh keypair\n", err)
		privB64, pubHex, _, err = wgGenKeypair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ ephemeral peer: keygen: %v (using shared identity)\n", err)
			return noop, err
		}
		ip, ip6, err = postEphemeralPeer(client, gwURL, token, pubHex)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ ephemeral peer: %v (using shared identity)\n", err)
		return noop, err
	}

	writeEphemeralCache(cachePath, &ephemeralCache{
		GatewayURL: gwURL,
		PrivateKey: privB64,
		PublicHex:  pubHex,
		IP:         ip,
		IP6:        ip6,
	})

	cfg.PrivateKey = privB64
	cfg.Address = ip + "/32, " + ip6 + "/128"
	_ = os.Setenv("CLAWPATROL_EPHEMERAL_ADDR", cfg.Address)

	// Cleanup is intentionally a no-op. The ephemeral identity persists
	// across runs (that's the whole reuse story), so an exit MUST NOT
	// DELETE it: a sibling `clawpatrol run` may still be using the
	// tunnel. The gateway evicts the identity when a different pubkey
	// arrives from the same parent (cache invalidation path) or when
	// the parent device itself is revoked.
	return noop, nil
}

// postEphemeralPeer POSTs to /api/peer/ephemeral?pubkey=<hex>. Returns
// the (v4, v6) addresses the gateway assigned.
func postEphemeralPeer(client *http.Client, gwURL, token, pubHex string) (string, string, error) {
	req, err := http.NewRequest(http.MethodPost,
		gwURL+"/api/peer/ephemeral?pubkey="+pubHex, nil)
	if err != nil {
		return "", "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("register: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("gateway returned %d", resp.StatusCode)
	}
	var result struct {
		IP  string `json:"ip"`
		IP6 string `json:"ip6"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("decode response: %w", err)
	}
	return result.IP, result.IP6, nil
}

// readEphemeralCache loads the on-disk ephemeral identity. Returns nil
// on any error (missing / malformed / unreadable) — the caller mints
// a fresh keypair.
func readEphemeralCache(path string) (*ephemeralCache, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ephemeralCache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.PrivateKey == "" || c.PublicHex == "" {
		return nil, fmt.Errorf("cache missing keypair")
	}
	return &c, nil
}

// writeEphemeralCache persists c atomically (write-then-rename). 0600
// because c.PrivateKey is the WG private key for this host's
// ephemeral identity — leaking it lets anyone register as this peer.
func writeEphemeralCache(path string, c *ephemeralCache) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// acquireEphemeralLock serializes the read-or-mint window between
// concurrent `clawpatrol run` invocations. Uses LOCK_EX so the second
// run blocks until the first one finishes its POST + cache write; the
// second run then reads the freshly-written cache and reuses the
// keypair instead of generating its own (which would have raced to
// register a separate IP, defeating the whole reuse mechanism).
func acquireEphemeralLock(cachePath string) (func(), error) {
	lockPath := cachePath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// gatewayHTTPClient builds an http.Client that trusts caPath in addition
// to system roots.
func gatewayHTTPClient(caPath string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(caPath); err == nil {
		roots.AppendCertsFromPEM(pem)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}, nil
}

// readFileSilent reads a file and returns its contents as a string,
// or empty on any error.
func readFileSilent(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// --- helpers ---------------------------------------------------------

func b64ToHex(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
