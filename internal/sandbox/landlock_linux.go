package sandbox

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// x/sys/unix (v0.43.0) ships the Landlock syscall numbers, the
// ruleset/path-beneath types, and the access constants, but no
// wrapper functions — raw syscalls below. Note network restriction
// needs no rule type: handling LANDLOCK_ACCESS_NET_* with zero rules
// denies all TCP bind/connect.
//
// Per-ABI feature masks. Handling an access right the running kernel
// doesn't know fails landlock_create_ruleset, so the full mask is
// trimmed to the probed ABI before use.
const (
	landlockFSv1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM

	landlockRead = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	landlockExec = landlockRead | unix.LANDLOCK_ACCESS_FS_EXECUTE

	// landlockFileRights are the access rights that apply to regular
	// files. A path_beneath rule whose parent_fd is a file must not
	// carry directory-only rights (READ_DIR, MAKE_*, REMOVE_*, REFER)
	// or landlock_add_rule returns EINVAL, so a rule on a file is
	// masked down to these.
	landlockFileRights = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

func landlockABI() int {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	return int(v)
}

func landlockFSMask(abi int) uint64 {
	mask := uint64(landlockFSv1)
	if abi >= 2 {
		mask |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		mask |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		mask |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return mask
}

// applyLandlock restricts the calling thread (the caller holds
// runtime.LockOSThread; execve carries the domain into the plugin) to
// the spec's paths, denying everything else the ABI can express. With
// ABI >= 4 and no network grant, all TCP bind/connect is denied too
// (UDP/ICMP are not expressible — stated in the probe warning).
func applyLandlock(spec Spec) error {
	abi := landlockABI()
	if abi < 1 {
		return fmt.Errorf("landlock: kernel support missing")
	}
	fsMask := landlockFSMask(abi)
	attr := unix.LandlockRulesetAttr{Access_fs: fsMask}
	if abi >= 4 && spec.Network == NetworkNone {
		attr.Access_net = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	defer unix.Close(int(fd))

	type grant struct {
		path     string
		access   uint64
		optional bool
	}
	grants := []grant{
		{path: spec.BinaryPath, access: landlockExec},
		{path: "/lib", access: landlockExec, optional: true},
		{path: "/lib32", access: landlockExec, optional: true},
		{path: "/lib64", access: landlockExec, optional: true},
		{path: "/usr/lib", access: landlockExec, optional: true},
		{path: "/usr/lib32", access: landlockExec, optional: true},
		{path: "/usr/lib64", access: landlockExec, optional: true},
		{path: "/etc/ld.so.cache", access: landlockRead, optional: true},
		{path: "/etc/ld.so.conf", access: landlockRead, optional: true},
		{path: "/etc/ld.so.conf.d", access: landlockRead, optional: true},
		{path: spec.SocketDir, access: fsMask},
	}
	if spec.Network == NetworkOutbound {
		for _, p := range []string{
			"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
			"/etc/ssl", "/etc/ca-certificates", "/etc/pki", "/usr/share/ca-certificates",
		} {
			grants = append(grants, grant{path: p, access: landlockRead, optional: true})
		}
	}
	for _, p := range spec.ReadPaths {
		grants = append(grants, grant{path: p, access: landlockRead})
	}
	for _, p := range spec.WritePaths {
		grants = append(grants, grant{path: p, access: fsMask})
	}

	for _, g := range grants {
		if err := landlockAllowPath(int(fd), g.path, g.access&fsMask); err != nil {
			if g.optional && os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("landlock rule for %s: %w", g.path, err)
		}
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_NO_NEW_PRIVS: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

func landlockAllowPath(rulesetFD int, path string, access uint64) error {
	pathFD, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(pathFD)
	// A rule on a regular file may only carry file-applicable rights;
	// directory-only bits make landlock_add_rule return EINVAL.
	var st unix.Stat_t
	if err := unix.Fstat(pathFD, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		access &= landlockFileRights
	}
	if access == 0 {
		return nil
	}
	attr := unix.LandlockPathBeneathAttr{
		Allowed_access: access,
		Parent_fd:      int32(pathFD),
	}
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD), unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&attr)), 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
