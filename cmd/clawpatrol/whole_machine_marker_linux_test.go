//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWholeMachineMarkerPerProcessSwitchClearsDirectRunGate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	seedWholeMachineMarker(t)

	if err := clearWholeMachineMarker(); err != nil {
		t.Fatal(err)
	}
	assertWholeMachineMarkerAbsent(t)
}

func TestWholeMachineMarkerRejoinInvalidatesPreviousCommit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	seedWholeMachineMarker(t)

	if err := beginJoinSetup(); err != nil {
		t.Fatal(err)
	}
	assertWholeMachineMarkerAbsent(t)
}

func TestFinishJoinSetupDoesNotCommitWholeMachineMarker(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := os.MkdirAll(defaultClawpatrolDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	setup := joinSetup{caPath: filepath.Join(defaultClawpatrolDir(), "ca.crt")}
	finishJoinSetup(&setup, true, true, true)

	assertWholeMachineMarkerAbsent(t)
}

func TestCompleteWholeMachineRoutingFailureLeavesRunSandboxed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	routingErr := errors.New("wg-quick failed")

	err := completeWholeMachineRouting(func() error {
		assertWholeMachineMarkerAbsent(t)
		return routingErr
	})
	if !errors.Is(err, routingErr) {
		t.Fatalf("complete routing error = %v, want %v", err, routingErr)
	}
	assertWholeMachineMarkerAbsent(t)
}

func TestCompleteWholeMachineRoutingSuccessCommitsDirectRunGate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	routingRan := false

	if err := completeWholeMachineRouting(func() error {
		routingRan = true
		assertWholeMachineMarkerAbsent(t)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !routingRan {
		t.Fatal("routing callback did not run")
	}
	if !isWholeMachineJoin() {
		t.Fatal("successful routing did not enable direct run gate")
	}
	got, err := os.ReadFile(wholeMachineMarkerPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1\n" {
		t.Fatalf("marker content = %q, want %q", got, "1\\n")
	}
	info, err := os.Stat(wholeMachineMarkerPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode = %o, want 600", info.Mode().Perm())
	}
	temps, err := filepath.Glob(filepath.Join(defaultClawpatrolDir(), ".whole-machine-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("temporary marker files remain: %v", temps)
	}
}

func TestWholeMachineMarkerTailscaleExitNodeFailureLeavesRunSandboxed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	seedWholeMachineMarker(t)
	if err := beginJoinSetup(); err != nil {
		t.Fatal(err)
	}
	routingErr := errors.New("tailscale set failed")

	err := completeWholeMachineTailscaleRouting("gateway-node", func(exitNode string) error {
		if exitNode != "gateway-node" {
			t.Fatalf("exit node = %q, want gateway-node", exitNode)
		}
		assertWholeMachineMarkerAbsent(t)
		return routingErr
	})
	if !errors.Is(err, routingErr) {
		t.Fatalf("complete Tailscale routing error = %v, want %v", err, routingErr)
	}
	assertWholeMachineMarkerAbsent(t)
}

func TestWholeMachineMarkerWGRejoinFailureDoesNotRestoreOldCommit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	seedWholeMachineMarker(t)
	if err := beginJoinSetup(); err != nil {
		t.Fatal(err)
	}

	routingErr := errors.New("wg-quick failed")
	if err := completeWholeMachineRouting(func() error { return routingErr }); !errors.Is(err, routingErr) {
		t.Fatalf("complete routing error = %v, want %v", err, routingErr)
	}
	assertWholeMachineMarkerAbsent(t)
}

func TestWholeMachineMarkerTailscaleSuccessCommitsAfterExitNode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := completeWholeMachineTailscaleRouting("gateway-node", func(exitNode string) error {
		if exitNode != "gateway-node" {
			t.Fatalf("exit node = %q, want gateway-node", exitNode)
		}
		assertWholeMachineMarkerAbsent(t)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !isWholeMachineJoin() {
		t.Fatal("successful Tailscale exit-node setup did not enable direct run gate")
	}
}

func TestWholeMachineMarkerPerProcessSuccessNeverCommits(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	seedWholeMachineMarker(t)

	if err := beginJoinSetup(); err != nil {
		t.Fatal(err)
	}
	// The per-process branch never invokes whole-machine routing completion.
	assertWholeMachineMarkerAbsent(t)
}

func TestWholeMachineMarkerCommitFailureLeavesRunSandboxed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(defaultClawpatrolDir(), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := completeWholeMachineRouting(func() error { return nil })
	if err == nil {
		t.Fatal("marker commit unexpectedly succeeded")
	}
	if isWholeMachineJoin() {
		t.Fatal("failed marker commit enabled direct run gate")
	}
}

func TestWholeMachineMarkerRemovalFailureStopsAdmission(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(wholeMachineMarkerPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wholeMachineMarkerPath(), "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := beginJoinSetup(); err == nil {
		t.Fatal("join admission unexpectedly ignored marker removal failure")
	}
	if !isWholeMachineJoin() {
		t.Fatal("failed removal changed existing marker state")
	}
}

func TestWholeMachineMarkerInvalidCommandPreservesPreviousCommit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	seedWholeMachineMarker(t)

	runRejectedJoinSubprocess(t, "invalid")
	if !isWholeMachineJoin() {
		t.Fatal("invalid join command cleared previous whole-machine commit")
	}
}

func TestWholeMachineMarkerLocalGatewayRejectionPreservesPreviousCommit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	seedWholeMachineMarker(t)

	runRejectedJoinSubprocess(t, "local-gateway")
	if !isWholeMachineJoin() {
		t.Fatal("local-gateway rejection cleared previous whole-machine commit")
	}
}

func TestWholeMachineMarkerRejectedJoinHelper(_ *testing.T) {
	switch os.Getenv("CLAWPATROL_REJECTED_JOIN_HELPER") {
	case "invalid":
		runJoin(nil)
	case "local-gateway":
		runJoin([]string{"--whole-machine", "http://127.0.0.1:8080"})
	}
}

func runRejectedJoinSubprocess(t *testing.T, scenario string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWholeMachineMarkerRejectedJoinHelper$")
	cmd.Env = append(os.Environ(), "CLAWPATROL_REJECTED_JOIN_HELPER="+scenario)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("rejected join exit = %v, want status 2", err)
	}
}

func seedWholeMachineMarker(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(defaultClawpatrolDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wholeMachineMarkerPath(), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isWholeMachineJoin() {
		t.Fatal("seeded whole-machine marker did not enable direct run gate")
	}
}

func assertWholeMachineMarkerAbsent(t *testing.T) {
	t.Helper()
	if isWholeMachineJoin() {
		t.Fatal("whole-machine marker still enables direct run gate")
	}
	if _, err := os.Stat(wholeMachineMarkerPath()); !os.IsNotExist(err) {
		t.Fatalf("marker should be absent: %v", err)
	}
}
