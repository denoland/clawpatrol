package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// stage1Payload rides CLAWPATROL_SANDBOX_SPEC from the gateway to the
// re-exec'd child.
type stage1Payload struct {
	Spec Spec
	Mode Mode
}

// Stage1 is the env-gated re-exec entry point. Host binaries that
// spawn plugins must call it as the first statement of main() (test
// packages: from TestMain). In the parent it only records that the
// hook is wired. In the re-exec'd child (CLAWPATROL_SANDBOX_STAGE1
// set) it sets the sandbox up and execs the plugin binary — it never
// returns. Setup failures print one "clawpatrol-sandbox:" line on
// stderr (stdout stays clean for the go-plugin handshake) and exit 87.
func Stage1() {
	stage1Wired = true
	action := os.Getenv(EnvStage1)
	if action == "" {
		return
	}
	runtime.LockOSThread()
	if err := stage1Main(action); err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol-sandbox: %v\n", err)
		os.Exit(stage1ExitCode)
	}
	// Only the probe action gets here; stage1Main execs otherwise.
	os.Exit(0)
}

func stage1Main(action string) error {
	raw := os.Getenv(EnvSpec)
	if raw == "" {
		return fmt.Errorf("%s is set but %s is empty", EnvStage1, EnvSpec)
	}
	var p stage1Payload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return fmt.Errorf("decoding %s: %w", EnvSpec, err)
	}

	// no_new_privs first: nothing the sandbox runs may regain
	// privileges via setuid/fscap binaries, and Landlock requires it.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_NO_NEW_PRIVS: %w", err)
	}

	switch p.Mode {
	case ModeNamespaces:
		if err := setupNamespaceRoot(p.Spec); err != nil {
			return err
		}
		// The setup above ran as uid 0 in the user namespace (needed
		// for mount/pivot_root). Strip every privilege before exec so
		// the plugin can't undo the read-only binds.
		if err := dropNamespacePrivileges(); err != nil {
			return err
		}
	case ModeLandlock:
		if err := applyLandlock(p.Spec); err != nil {
			return err
		}
	default:
		return fmt.Errorf("stage1: unsupported mode %q", p.Mode)
	}

	if action == stage1Probe {
		return nil
	}

	env := scrubbedEnviron()
	if err := unix.Exec(p.Spec.BinaryPath, []string{p.Spec.BinaryPath}, env); err != nil {
		return fmt.Errorf("exec %s: %w", p.Spec.BinaryPath, err)
	}
	return nil // unreachable
}

// scrubbedEnviron returns the child's environment minus the stage-1
// control variables. Everything else in it came from BaseEnv plus
// go-plugin's handshake vars, which the plugin needs.
func scrubbedEnviron() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, EnvStage1+"=") ||
			strings.HasPrefix(kv, EnvSpec+"=") ||
			strings.HasPrefix(kv, EnvBackend+"=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// Secure-bit flags (linux/securebits.h; not exported by x/sys/unix).
// SECBIT_NOROOT stops execve from granting a uid-0 process the
// implicit full capability set; the _LOCKED bits make the choice
// irreversible.
const (
	secbitNoRoot            = 0x01 // SECBIT_NOROOT
	secbitNoRootLocked      = 0x02 // SECBIT_NOROOT_LOCKED
	secbitNoSetuidFixup     = 0x04 // SECBIT_NO_SETUID_FIXUP
	secbitNoSetuidFixupLock = 0x08 // SECBIT_NO_SETUID_FIXUP_LOCKED
	prSetSecurebits         = 0x1c // PR_SET_SECUREBITS
)

// dropNamespacePrivileges turns the uid-0 namespace-setup process
// into a powerless one before exec: it disables the root capability
// default (SECBIT_NOROOT), clears the ambient set, drops the entire
// bounding set, and zeroes the effective/permitted/inheritable sets.
// After this the plugin runs as uid 0 in its user namespace with no
// capabilities and no way to regain any (NO_NEW_PRIVS is already
// set), so it cannot remount the read-only binds or mount anything
// new.
func dropNamespacePrivileges() error {
	secbits := uintptr(secbitNoRoot | secbitNoRootLocked | secbitNoSetuidFixup | secbitNoSetuidFixupLock)
	if err := unix.Prctl(prSetSecurebits, secbits, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_SECUREBITS: %w", err)
	}
	_ = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
	last := 40
	if b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			last = n
		}
	}
	for c := 0; c <= last; c++ {
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData // all-zero: drop every cap in every set
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset (drop all): %w", err)
	}
	return nil
}

// setupNamespaceRoot builds the deny-by-default filesystem and pivots
// into it. Runs as pid 1 of a fresh pid namespace, inside fresh
// user+mount namespaces, holding a full capability set over them.
func setupNamespaceRoot(spec Spec) error {
	// Stop mount events from propagating back to the host.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("remount / private: %w", err)
	}

	// Stage the new root as its own tmpfs mount — pivot_root requires
	// the new root to be a mount point, not a plain directory. The
	// staging dir lives under /tmp (world-writable, 1777, so mkdir
	// works as the unprivileged-mapped root) with a name derived from
	// the unique socket dir so concurrent plugins don't collide on
	// the host /tmp before each mounts over it. Writes under it are
	// invisible to the host; the host tree stays visible for
	// resolving bind sources until pivot_root.
	root := "/tmp/.cproot-" + filepath.Base(spec.SocketDir)
	if err := os.Mkdir(root, 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return fmt.Errorf("mount tmpfs on %s: %w", root, err)
	}

	// Fresh /tmp inside the new root. Mounted before the SocketDir
	// bind: SocketDir conventionally lives under /tmp and its bind
	// target must sit on this tmpfs, not shadow it.
	if err := os.Mkdir(root+"/tmp", 0o777); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", root+"/tmp", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777"); err != nil {
		return fmt.Errorf("mount tmpfs on %s/tmp: %w", root, err)
	}

	for _, b := range bindPlan(spec) {
		if err := bindIntoRoot(root, b); err != nil {
			return err
		}
	}

	// Minimal /dev: file-binds of the harmless device nodes.
	if err := os.MkdirAll(root+"/dev", 0o755); err != nil {
		return err
	}
	for _, dev := range []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"} {
		if err := bindIntoRoot(root, bind{src: dev, ro: false}); err != nil {
			return err
		}
	}

	// Fresh /proc scoped to the new pid namespace (we are its pid 1).
	if err := os.MkdirAll(root+"/proc", 0o555); err != nil {
		return err
	}
	if err := unix.Mount("proc", root+"/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}

	// Stacked pivot_root: pivot onto itself, then detach the old
	// root that is left mounted underneath.
	if err := unix.Chdir(root); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount old root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	return nil
}

type bind struct {
	src string
	ro  bool
	// optional marks bind sources that are skipped when absent
	// (distro-dependent lib dirs, cert stores).
	optional bool
}

// bindPlan lists every host path mirrored into the sandbox, all at
// their original absolute paths.
func bindPlan(spec Spec) []bind {
	plan := []bind{
		{src: spec.BinaryPath, ro: true},
		// Dynamic linker + system libraries (no-ops for pure-Go
		// plugins; required for cgo or non-Go plugin binaries).
		{src: "/lib", ro: true, optional: true},
		{src: "/lib32", ro: true, optional: true},
		{src: "/lib64", ro: true, optional: true},
		{src: "/usr/lib", ro: true, optional: true},
		{src: "/usr/lib32", ro: true, optional: true},
		{src: "/usr/lib64", ro: true, optional: true},
		{src: "/etc/ld.so.cache", ro: true, optional: true},
		{src: "/etc/ld.so.conf", ro: true, optional: true},
		{src: "/etc/ld.so.conf.d", ro: true, optional: true},
	}
	if spec.Network == NetworkOutbound {
		plan = append(plan,
			bind{src: "/etc/resolv.conf", ro: true, optional: true},
			bind{src: "/etc/hosts", ro: true, optional: true},
			bind{src: "/etc/nsswitch.conf", ro: true, optional: true},
			bind{src: "/etc/ssl", ro: true, optional: true},
			bind{src: "/etc/ca-certificates", ro: true, optional: true},
			bind{src: "/etc/pki", ro: true, optional: true},
			bind{src: "/usr/share/ca-certificates", ro: true, optional: true},
		)
	}
	for _, p := range spec.ReadPaths {
		plan = append(plan, bind{src: p, ro: true})
	}
	plan = append(plan, bind{src: spec.SocketDir, ro: false})
	for _, p := range spec.WritePaths {
		plan = append(plan, bind{src: p, ro: false})
	}
	return plan
}

// bindIntoRoot bind-mounts b.src at root+b.src, then remounts
// read-only when asked.
func bindIntoRoot(root string, b bind) error {
	fi, err := os.Stat(b.src)
	if err != nil {
		if b.optional && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("bind source %s: %w", b.src, err)
	}
	target := filepath.Join(root, b.src)
	if fi.IsDir() {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_ = f.Close()
	}
	if err := unix.Mount(b.src, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s: %w", b.src, err)
	}
	if b.ro {
		if err := remountRO(target); err != nil {
			return fmt.Errorf("remount %s read-only: %w", b.src, err)
		}
	}
	return nil
}

// remountRO flips a fresh bind mount read-only. The remount must
// preserve every flag the kernel locked when our mount namespace was
// cloned from the host's (can_change_locked_flags in fs/namespace.c):
// locked nosuid/nodev/noexec may not be cleared and atime flags must
// match exactly, so the current flags are read back via statfs and
// carried over.
func remountRO(target string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(target, &st); err != nil {
		return err
	}
	flags := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV)
	if st.Flags&unix.ST_NOEXEC != 0 {
		flags |= unix.MS_NOEXEC
	}
	if st.Flags&unix.ST_NOATIME != 0 {
		flags |= unix.MS_NOATIME
	}
	if st.Flags&unix.ST_NODIRATIME != 0 {
		flags |= unix.MS_NODIRATIME
	}
	if st.Flags&unix.ST_RELATIME != 0 {
		flags |= unix.MS_RELATIME
	}
	return unix.Mount("", target, "", flags, "")
}
