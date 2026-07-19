package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wireGuardCAStageServer struct {
	server    *httptest.Server
	caPEM     []byte
	expiresIn int
	poll      func(http.ResponseWriter)
	start     int
	polls     int
	claims    int
}

var sharedWireGuardCAStageServer *wireGuardCAStageServer

func startWireGuardCAStageServer() {
	if sharedWireGuardCAStageServer != nil {
		return
	}
	h := &wireGuardCAStageServer{}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ca.crt":
			_, _ = w.Write(h.caPEM)
		case "/api/onboard/start":
			h.start++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "device-code",
				"user_code":   "USER-CODE",
				"verify_url":  "http://100.64.0.1/approve",
				"interval":    -1,
				"expires_in":  h.expiresIn,
			})
		case "/api/onboard/poll":
			h.polls++
			h.poll(w)
		case "/api/onboard/claim":
			h.claims++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	sharedWireGuardCAStageServer = h
}

func newWireGuardCAStageServer(t *testing.T, caPEM []byte, expiresIn int, poll func(http.ResponseWriter)) *wireGuardCAStageServer {
	t.Helper()
	startWireGuardCAStageServer()
	h := sharedWireGuardCAStageServer
	h.caPEM = caPEM
	h.expiresIn = expiresIn
	h.poll = poll
	h.start, h.polls, h.claims = 0, 0, 0
	return h
}

func TestWireGuardCAStagePreservesActiveCAOnPreApprovalFailure(t *testing.T) {
	caA, _, _ := mintCA(t, "active-ca-a", 7761)
	caB, _, _ := mintCA(t, "candidate-ca-b", 7762)
	canonicalA, err := canonicalMITMCAPEM(caA)
	if err != nil {
		t.Fatalf("canonicalize CA-A: %v", err)
	}

	tests := []struct {
		name      string
		expiresIn int
		poll      func(http.ResponseWriter)
		wantErr   string
		wantPolls bool
	}{
		{
			name:      "rejected",
			expiresIn: 5,
			poll: func(w http.ResponseWriter) {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":  "access_denied",
					"detail": "operator rejected request",
				})
			},
			wantErr:   "poll: access_denied",
			wantPolls: true,
		},
		{
			name:      "timeout",
			expiresIn: 0,
			poll: func(w http.ResponseWriter) {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			},
			wantErr: "timed out waiting for approval",
		},
	}
	h := newWireGuardCAStageServer(t, caB, 5, tests[0].poll)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.expiresIn = tt.expiresIn
			h.poll = tt.poll
			h.start, h.polls, h.claims = 0, 0, 0
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
			activeAfterPrefetch, readErr := os.ReadFile(caPath)
			prefetchPreserved := readErr == nil && bytes.Equal(activeAfterPrefetch, canonicalA)

			_, err = onboardViaDeviceFlow(h.server.URL, false, "", "stage-test", &setup, false, h.server.Client(), false)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("onboardViaDeviceFlow error = %v, want containing %q", err, tt.wantErr)
			}
			if h.start != 1 {
				t.Fatalf("start requests = %d, want 1", h.start)
			}
			if tt.wantPolls && h.polls == 0 {
				t.Fatal("poll endpoint was not reached")
			}
			if !prefetchPreserved {
				t.Errorf("preJoinFetchCA replaced active ca.crt before approval")
			}
			active, err := os.ReadFile(caPath)
			if err != nil {
				t.Fatalf("read active ca.crt: %v", err)
			}
			if !bytes.Equal(active, canonicalA) {
				t.Errorf("active ca.crt changed on %s: got candidate=%v", tt.name, bytes.Equal(active, caB))
			}
			if len(*installed) != 0 {
				t.Fatalf("trust installs = %d, want 0", len(*installed))
			}
			if h.claims != 0 {
				t.Fatalf("claim requests = %d before approval, want 0", h.claims)
			}
		})
	}
}

func TestWireGuardCAStageRejectsMissingCandidateBeforeWGState(t *testing.T) {
	installed := recordInstalls(t)
	t.Setenv("HOME", t.TempDir())
	caB, _, _ := mintCA(t, "candidate-ca-b", 7766)
	conf := "[Interface]\nAddress = 10.0.0.2/32\n"
	h := newWireGuardCAStageServer(t, caB, 5, func(w http.ResponseWriter) {
		writeWireGuardPollSuccess(w, "clawpatrol-test", conf)
	})
	caDir := t.TempDir()
	setup := joinSetup{caPath: filepath.Join(caDir, "ca.crt")}

	_, err := onboardViaDeviceFlow(h.server.URL, false, "", "stage-test", &setup, false, h.server.Client(), false)
	if err == nil || !strings.Contains(err.Error(), "no staged WireGuard CA") {
		t.Fatalf("onboardViaDeviceFlow error = %v, want missing staged CA", err)
	}
	if h.start != 1 || h.polls == 0 {
		t.Fatalf("request counts start=%d poll=%d, want 1, >0", h.start, h.polls)
	}
	if h.claims != 0 {
		t.Fatalf("claim requests = %d, want 0 before WireGuard state mutation", h.claims)
	}
	if _, err := os.Stat(filepath.Join(caDir, "mode")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mode file exists before candidate validation: %v", err)
	}
	if len(*installed) != 0 {
		t.Fatalf("trust installs = %d, want 0", len(*installed))
	}
}

func TestWireGuardCAStageFreshJoinCommitsApprovedSnapshot(t *testing.T) {
	installed := recordInstalls(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	caB, _, _ := mintCA(t, "candidate-ca-b", 7763)
	canonicalB, err := canonicalMITMCAPEM(caB)
	if err != nil {
		t.Fatalf("canonicalize CA-B: %v", err)
	}
	conf := "[Interface]\nPrivateKey = test-private\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = test-public\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n"
	h := newWireGuardCAStageServer(t, caB, 5, func(w http.ResponseWriter) {
		writeWireGuardPollSuccess(w, "clawpatrol-test", conf)
	})
	caDir := t.TempDir()
	caPath := filepath.Join(caDir, "ca.crt")

	setup, err := preJoinFetchCA(h.server.URL, caDir, h.server.Client())
	if err != nil {
		t.Fatalf("preJoinFetchCA: %v", err)
	}
	_, prefetchErr := os.Stat(caPath)
	prefetchLeftAbsent := errors.Is(prefetchErr, os.ErrNotExist)

	wgMode, err := onboardViaDeviceFlow(h.server.URL, false, "", "stage-test", &setup, false, h.server.Client(), false)
	if err != nil {
		t.Fatalf("onboardViaDeviceFlow: %v", err)
	}
	if !wgMode {
		t.Fatal("onboardViaDeviceFlow returned wgMode=false")
	}
	if !prefetchLeftAbsent {
		t.Error("preJoinFetchCA created active ca.crt before approval")
	}
	if h.start != 1 || h.polls == 0 || h.claims != 1 {
		t.Fatalf("request counts start=%d poll=%d claim=%d, want 1, >0, 1", h.start, h.polls, h.claims)
	}
	active, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read active ca.crt: %v", err)
	}
	if !bytes.Equal(active, canonicalB) {
		t.Fatal("active ca.crt does not equal staged approved CA-B")
	}
	info, err := os.Stat(caPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("ca.crt mode = %o, want 644", info.Mode().Perm())
	}
	if len(*installed) != 1 || !bytes.Equal((*installed)[0], canonicalB) {
		t.Fatalf("trust installs = %d and exact candidate match = %v, want 1 and true", len(*installed), len(*installed) == 1 && bytes.Equal((*installed)[0], canonicalB))
	}
	if temps, err := filepath.Glob(filepath.Join(caDir, ".ca.crt-*.tmp")); err != nil || len(temps) != 0 {
		t.Fatalf("CA temp files = %v, err=%v", temps, err)
	}
}

func writeWireGuardPollSuccess(w http.ResponseWriter, iface, conf string) {
	_ = json.NewEncoder(w).Encode(map[string]string{
		"auth_key":     conf,
		"login_server": fmt.Sprintf("wireguard://%s", iface),
		"api_token":    "test-api-token",
	})
}
