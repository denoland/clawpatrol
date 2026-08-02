package sandbox

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// readInterp returns the ELF program interpreter of bin, or "" when the
// file is not an ELF or is statically linked.
func readInterp(t *testing.T, bin string) string {
	t.Helper()
	f, err := elf.Open(bin)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sec := f.Section(".interp")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		t.Fatalf("%s: read .interp: %v", bin, err)
	}
	return strings.TrimRight(string(data), "\x00")
}

// buildLoaderHelper compiles the dynamically-linked loaderhelper test
// program and returns its path.
func buildLoaderHelper(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	bin := filepath.Join(t.TempDir(), "loaderhelper")
	build := exec.Command("go", "build", "-o", bin, "./testdata/loaderhelper")
	build.Dir = filepath.Dir(thisFile)
	if out, berr := build.CombinedOutput(); berr != nil {
		t.Skipf("go build unavailable: %v\n%s", berr, out)
	}
	return bin
}

// uniqueSocketDir returns a fresh dir with a process-unique basename:
// stage1 names its staging root from the socket dir's basename and
// refuses to reuse a leftover root, so a plain t.TempDir() (".../001")
// collides across tests.
func uniqueSocketDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cp-sandboxtest-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// TestBindPlanIncludesLoader pins that bindPlan mirrors the dynamic
// loader of a dynamically-linked plugin binary into the sandbox. The
// FHS bind list covers /lib* loaders, but non-FHS distros (NixOS,
// Guix) keep the loader elsewhere — without a bind the exec of the
// plugin fails with ENOENT while the probe still reports the
// namespaces backend as available.
func TestBindPlanIncludesLoader(t *testing.T) {
	exe := buildLoaderHelper(t)
	interp := readInterp(t, exe)
	if interp == "" {
		t.Skip("helper built statically; loader discovery not exercisable")
	}
	if !filepath.IsAbs(interp) {
		t.Fatalf("unexpected relative interpreter %q", interp)
	}
	spec := Spec{PluginName: "probe", BinaryPath: exe}
	for _, b := range bindPlan(spec) {
		if b.src == interp {
			return // the loader file itself is mirrored
		}
	}
	t.Fatalf("bindPlan(%s) does not mirror the dynamic loader %q", exe, interp)
}

// TestDynamicBinaryRunsInNamespacesSandbox spawns a real
// dynamically-linked binary through the namespaces sandbox. On
// non-FHS distros this is the end-to-end failure the loader binds
// fix: exec of the plugin fails with ENOENT because the interpreter
// lives outside the FHS dirs.
func TestDynamicBinaryRunsInNamespacesSandbox(t *testing.T) {
	av, err := Probe()
	if err != nil {
		t.Skipf("no sandbox backend: %v", err)
	}
	if av.Mode != ModeNamespaces {
		t.Skipf("namespaces backend unavailable (%s); loader binds only matter there", av.Mode)
	}

	// Build a small dynamically-linked helper (cgo on by default). A
	// static build would exercise nothing.
	bin := buildLoaderHelper(t)
	if interp := readInterp(t, bin); interp == "" {
		t.Skip("helper built statically; loader discovery not exercisable")
	}

	cmd, err := Command(Spec{
		PluginName: "loaderhelper",
		BinaryPath: bin,
		SocketDir:  uniqueSocketDir(t),
	}, ModeNamespaces)
	if err != nil {
		t.Fatalf("sandbox command: %v", err)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("dynamically-linked binary failed in namespaces sandbox: %v\nstderr: %s", err, errb.String())
	}
	if got := strings.TrimSpace(out.String()); got != "ok" {
		t.Fatalf("helper stdout = %q, want %q", got, "ok")
	}
}
