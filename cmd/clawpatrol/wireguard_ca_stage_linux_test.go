//go:build linux

package main

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestWireGuardCAStageWholeMachineRejoinCommitsOnlyAfterWGSetup(t *testing.T) {
	caA, _, _ := mintCA(t, "active-ca-a", 7764)
	caB, _, _ := mintCA(t, "candidate-ca-b", 7765)
	canonicalA, err := canonicalMITMCAPEM(caA)
	if err != nil {
		t.Fatalf("canonicalize CA-A: %v", err)
	}
	canonicalB, err := canonicalMITMCAPEM(caB)
	if err != nil {
		t.Fatalf("canonicalize CA-B: %v", err)
	}
	const iface = "clawpatrol-stage-test"
	const conf = "[Interface]\nPrivateKey = test-private\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = test-public\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n"
	setupErr := errors.New("wg setup failed")

	tests := []struct {
		name      string
		callback  error
		wantError bool
	}{
		{name: "setup-fails", callback: setupErr, wantError: true},
		{name: "setup-succeeds"},
	}
	h := newWireGuardCAStageServer(t, caB, 5, func(w http.ResponseWriter) {
		writeWireGuardPollSuccess(w, iface, conf)
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.start, h.polls, h.claims = 0, 0, 0
			home := t.TempDir()
			t.Setenv("HOME", home)
			binDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(binDir, "wg-quick"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", binDir)
			installed := recordInstalls(t)
			caDir := t.TempDir()
			caPath := filepath.Join(caDir, "ca.crt")
			if err := os.WriteFile(caPath, canonicalA, 0o644); err != nil {
				t.Fatal(err)
			}
			setup, err := preJoinFetchCA(h.server.URL, caDir, h.server.Client())
			if err != nil {
				t.Fatalf("preJoinFetchCA: %v", err)
			}

			called := false
			previous := wgQuickUpFn
			wgQuickUpFn = func(gotIface, gotConf string) error {
				called = true
				if gotIface != iface || gotConf != conf {
					t.Fatalf("wg setup got iface=%q conf=%q", gotIface, gotConf)
				}
				active, err := os.ReadFile(caPath)
				if err != nil {
					t.Fatalf("read CA during wg setup: %v", err)
				}
				if !bytes.Equal(active, canonicalA) {
					t.Fatal("CA-B became active before fatal WireGuard setup completed")
				}
				if len(*installed) != 0 {
					t.Fatal("CA trust changed before fatal WireGuard setup completed")
				}
				assertWholeMachineMarkerAbsent(t)
				return tt.callback
			}
			t.Cleanup(func() { wgQuickUpFn = previous })

			wgMode, err := onboardViaDeviceFlow(h.server.URL, true, "", "stage-test", &setup, false, h.server.Client(), false)
			if !called {
				t.Fatal("WireGuard setup callback was not reached")
			}
			if !wgMode {
				t.Fatal("onboardViaDeviceFlow returned wgMode=false")
			}
			if h.start != 1 || h.polls == 0 || h.claims != 1 {
				t.Fatalf("request counts start=%d poll=%d claim=%d, want 1, >0, 1", h.start, h.polls, h.claims)
			}
			active, readErr := os.ReadFile(caPath)
			if readErr != nil {
				t.Fatalf("read active CA after onboarding: %v", readErr)
			}
			if tt.wantError {
				if !errors.Is(err, setupErr) {
					t.Fatalf("onboarding error = %v, want wrapping %v", err, setupErr)
				}
				if !bytes.Equal(active, canonicalA) {
					t.Fatal("failed WireGuard setup replaced active CA-A")
				}
				if len(*installed) != 0 {
					t.Fatalf("failed setup trust installs = %d, want 0", len(*installed))
				}
				assertWholeMachineMarkerAbsent(t)
				return
			}
			if err != nil {
				t.Fatalf("onboardViaDeviceFlow: %v", err)
			}
			if !bytes.Equal(active, canonicalB) {
				t.Fatal("successful setup did not activate exact staged CA-B")
			}
			if len(*installed) != 1 || !bytes.Equal((*installed)[0], canonicalB) {
				t.Fatalf("successful setup trust installs = %d with exact CA-B=%v", len(*installed), len(*installed) == 1 && bytes.Equal((*installed)[0], canonicalB))
			}
			if !isWholeMachineJoin() {
				t.Fatal("successful setup did not commit whole-machine marker")
			}
			if temps, err := filepath.Glob(filepath.Join(caDir, ".ca.crt-*.tmp")); err != nil || len(temps) != 0 {
				t.Fatalf("CA temp files = %v, err=%v", temps, err)
			}
		})
	}
}
