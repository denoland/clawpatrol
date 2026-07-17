//go:build linux

package main

// Integration test for the DNS lockdown executor: re-execs the test
// binary into a fresh user+mount namespace (mirroring runRun's
// SysProcAttr, minus the net namespace — no TUN is involved) and
// applies a canned dnsLockdown plan, then verifies the child's view
// of /etc and the masked path. Self-skips where unprivileged user
// namespaces are unavailable (e.g. locked-down CI, docker without
// --privileged); CI's ubuntu-latest runners allow them.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const dnsLockdownHelperEnv = "CLAWPATROL_TEST_DNS_LOCKDOWN_HELPER"

// runDNSLockdownHelper re-execs the test binary pinned to the helper
// test inside new user+mount namespaces and returns its combined
// output. Skips the calling test when the namespaces can't be created.
func runDNSLockdownHelper(t *testing.T, mode string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run", "^TestHelperDNSLockdownApply$", "-test.v")
	cmd.Env = append(os.Environ(), dnsLockdownHelperEnv+"="+mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		AmbientCaps:                []uintptr{capSysAdmin},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			// The clone itself failed — user namespaces unavailable.
			t.Skipf("cannot create user namespace (%v); skipping", err)
		}
		t.Fatalf("helper failed (%v):\n%s", err, out)
	}
	return string(out)
}

func TestDNSLockdownInNamespace(t *testing.T) {
	out := runDNSLockdownHelper(t, "apply")
	if !strings.Contains(out, "LOCKDOWN-OK") {
		t.Fatalf("helper did not report success:\n%s", out)
	}
}

func TestDNSLockdownInNamespaceFailurePropagates(t *testing.T) {
	out := runDNSLockdownHelper(t, "fail")
	if !strings.Contains(out, "LOCKDOWN-ERR-OK") {
		t.Fatalf("helper did not report the expected apply error:\n%s", out)
	}
}

// TestHelperDNSLockdownApply is not a standalone test: it is the body
// executed inside the namespaces by the tests above. Without the env
// guard it skips, so a plain `go test ./...` never runs it directly.
func TestHelperDNSLockdownApply(t *testing.T) {
	mode := os.Getenv(dnsLockdownHelperEnv)
	if mode == "" {
		t.Skip("helper for TestDNSLockdownInNamespace; not a standalone test")
	}

	if mode == "fail" {
		// A target that cannot exist: bind-mounting over a missing
		// path must surface an error, which runRunChild turns fatal.
		err := applyDNSLockdown(dnsLockdown{
			Overrides: []etcOverride{{
				Target:  "/etc/clawpatrol-definitely-missing.conf",
				Pattern: "clawpatrol-test-*",
				Body:    "x\n",
			}},
		})
		if err == nil {
			t.Fatalf("applyDNSLockdown on a missing target succeeded, want error")
		}
		fmt.Printf("LOCKDOWN-ERR-OK: %v\n", err)
		return
	}

	// Stand-in for the resolved varlink socket: a host file with
	// sensitive content that the mask must hide.
	secret, err := os.CreateTemp("", "clawpatrol-secret-*")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer func() { _ = os.Remove(secret.Name()) }()
	if _, err := secret.WriteString("SECRET"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = secret.Close()

	// Stand-in for the nscd socket: a LIVE unix socket with an
	// accepting listener, the shape glibc's __nscd_getai talks to.
	// The canonical /run/nscd/socket path can't be created by an
	// unprivileged, uid-mapped test, so the mechanism is exercised at
	// a temp path; the planner tests pin the canonical paths.
	sockDir, err := os.MkdirTemp("", "clawpatrol-nscd-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()
	sockPath := filepath.Join(sockDir, "socket")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if c, err := net.Dial("unix", sockPath); err != nil {
		t.Fatalf("pre-mask dial should reach the live socket: %v", err)
	} else {
		_ = c.Close()
	}

	const resolv = "nameserver 100.100.100.100\n"
	plan := dnsLockdown{
		Overrides: []etcOverride{
			{Target: "/etc/resolv.conf", Pattern: "clawpatrol-resolv-*", Body: resolv},
			{Target: "/etc/hosts", Pattern: "clawpatrol-hosts-*", Body: minimalHostsFile("nstest")},
		},
		Masks: []string{secret.Name(), sockPath},
	}
	if err := applyDNSLockdown(plan); err != nil {
		t.Fatalf("applyDNSLockdown: %v", err)
	}

	if got, err := os.ReadFile("/etc/resolv.conf"); err != nil || string(got) != resolv {
		t.Fatalf("/etc/resolv.conf = %q, %v; want %q", got, err, resolv)
	}
	if got, err := os.ReadFile("/etc/hosts"); err != nil || !strings.Contains(string(got), "127.0.1.1 nstest") {
		t.Fatalf("/etc/hosts = %q, %v; want synthetic body", got, err)
	}
	if got, err := os.ReadFile(secret.Name()); err != nil || len(got) != 0 {
		t.Fatalf("masked file = %q, %v; want empty", got, err)
	}
	// The masked socket must be unreachable even though the listener
	// is still accepting on the inode: connect(2) now hits a regular
	// file, exactly what an in-namespace nscd client would see.
	if c, err := net.Dial("unix", sockPath); err == nil {
		_ = c.Close()
		t.Fatalf("dial on masked socket succeeded; want failure")
	}
	if got, err := os.ReadFile(sockPath); err != nil || len(got) != 0 {
		t.Fatalf("masked socket read = %q, %v; want empty regular file", got, err)
	}
	fmt.Println("LOCKDOWN-OK")
}
