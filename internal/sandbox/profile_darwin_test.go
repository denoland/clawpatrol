package sandbox

import (
	"strings"
	"testing"
)

func TestSeatbeltProfileNetworkNone(t *testing.T) {
	spec := Spec{
		PluginName: "example",
		BinaryPath: "/private/tmp/plug/example",
		SocketDir:  "/private/tmp/cp-abc",
		TmpDir:     "/private/tmp/cp-abc/tmp",
		Network:    NetworkNone,
	}
	p, err := seatbeltProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(deny default)",
		`(allow process-exec (literal "/private/tmp/plug/example"))`,
		`(allow file* (subpath "/private/tmp/cp-abc"))`,
		`(allow network* (subpath "/private/tmp/cp-abc"))`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile missing %q\n%s", want, p)
		}
	}
	if strings.Contains(p, "(allow network-outbound)") {
		t.Error("network=none profile allows outbound network")
	}
}

func TestSeatbeltProfileOutboundAndGrants(t *testing.T) {
	spec := Spec{
		BinaryPath: "/x/bin",
		SocketDir:  "/private/tmp/cp-1",
		TmpDir:     "/private/tmp/cp-1/tmp",
		Network:    NetworkOutbound,
		ReadPaths:  []string{"/Users/me/.ssh"},
		WritePaths: []string{"/Users/me/scratch"},
	}
	p, err := seatbeltProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(allow network-outbound)",
		`(allow file-read* (subpath "/Users/me/.ssh"))`,
		`(allow file* (subpath "/Users/me/scratch"))`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile missing %q", want)
		}
	}
}

func TestSeatbeltProfileRejectsHostilePaths(t *testing.T) {
	for _, bad := range []string{
		`/tmp/a"))(allow default)(deny (literal "`,
		"/tmp/new\nline",
		"relative/path",
	} {
		spec := Spec{BinaryPath: bad, SocketDir: "/private/tmp/x", TmpDir: "/private/tmp/x/tmp"}
		if _, err := seatbeltProfile(spec); err == nil {
			t.Errorf("profile accepted hostile path %q", bad)
		}
	}
}
