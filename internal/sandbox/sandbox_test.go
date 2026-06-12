package sandbox

import (
	"slices"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	Stage1()
	m.Run()
}

func TestBaseEnv(t *testing.T) {
	spec := Spec{
		SocketDir: "/tmp/cp-abc",
		TmpDir:    "/tmp/cp-abc/tmp",
	}
	env := BaseEnv(spec)
	want := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/tmp/cp-abc/tmp",
		"TMPDIR=/tmp/cp-abc/tmp",
		"PLUGIN_UNIX_SOCKET_DIR=/tmp/cp-abc",
	}
	if !slices.Equal(env, want) {
		t.Errorf("BaseEnv = %q, want %q", env, want)
	}
	for _, kv := range env {
		if strings.Contains(kv, "CLAWPATROL_SECRET") {
			t.Errorf("BaseEnv leaks secrets: %q", kv)
		}
	}
}

func TestCommandRequiresStage1Wiring(t *testing.T) {
	saved := stage1Wired
	stage1Wired = false
	defer func() { stage1Wired = saved }()

	if _, err := Command(Spec{BinaryPath: "/bin/true"}, ModeNamespaces); err == nil {
		t.Fatal("Command succeeded without Stage1 wiring")
	} else if !strings.Contains(err.Error(), "Stage1") {
		t.Errorf("error %q does not mention Stage1", err)
	}
	if _, err := Probe(); err == nil {
		t.Fatal("Probe succeeded without Stage1 wiring")
	}
}

func TestCommandOffUsesScrubbedEnv(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_FOO", "leak-canary")
	spec := Spec{
		BinaryPath: "/bin/true",
		SocketDir:  "/tmp/cp-x",
		TmpDir:     "/tmp/cp-x/tmp",
		Network:    NetworkNone,
	}
	cmd, err := Command(spec, ModeOff)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != "/bin/true" {
		t.Errorf("Path = %q, want /bin/true", cmd.Path)
	}
	for _, kv := range cmd.Env {
		if strings.Contains(kv, "leak-canary") {
			t.Errorf("ModeOff env inherited gateway secret: %q", kv)
		}
	}
	if cmd.Stdout != nil || cmd.Stderr != nil || cmd.Stdin != nil {
		t.Error("Command must leave stdio nil for go-plugin")
	}
}

func TestProbeUnknownBackend(t *testing.T) {
	t.Setenv(EnvBackend, "frobnicate")
	probeMu.Lock()
	delete(probeCache, "frobnicate")
	probeMu.Unlock()
	if _, err := Probe(); err == nil {
		t.Fatal("Probe accepted unknown forced backend")
	}
}
