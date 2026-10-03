package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnrollmentHTTPClientHasTimeout(t *testing.T) {
	if enrollmentHTTPClient.Timeout != enrollmentHTTPTimeout {
		t.Fatalf("HTTP client timeout = %s, want %s", enrollmentHTTPClient.Timeout, enrollmentHTTPTimeout)
	}
	if enrollmentHTTPClient.Timeout <= 0 || enrollmentHTTPClient.Timeout > 30*time.Second {
		t.Fatalf("HTTP client timeout = %s, want a bounded bootstrap request", enrollmentHTTPClient.Timeout)
	}
}

func TestEnrollmentRegisterRequest(t *testing.T) {
	var gotAuth, gotContentType string
	var gotBody enrollmentRegisterRequest
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(rw).Encode(enrollmentRegisterResponse{
			Transport:       enrollmentTransportWireGuard,
			PeerIP:          "10.55.0.2",
			ServerPublicKey: "srv-pub",
			Endpoint:        "ep.example:51820",
			APIToken:        "peer-token",
		})
	}))
	defer srv.Close()

	claims, err := json.Marshal(k8sEnrollmentClaims{
		PodName:      "agent-1",
		PodNamespace: "agents",
		PodUID:       "uid-1",
		NodeName:     "kind-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := enrollmentRegister(context.Background(), srv.URL+"/", "sa-token", enrollmentRegisterRequest{
		Transport:          enrollmentTransportWireGuard,
		Authorizer:         "agents",
		WireGuardPublicKey: keyA,
		Claims:             claims,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.PeerIP != "10.55.0.2" || resp.APIToken != "peer-token" {
		t.Fatalf("unexpected response %+v", resp)
	}
	if gotAuth != "Bearer sa-token" {
		t.Fatalf("Authorization = %q, want Bearer sa-token", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	if gotBody.Transport != enrollmentTransportWireGuard || gotBody.Authorizer != "agents" || gotBody.WireGuardPublicKey != keyA {
		t.Fatalf("unexpected request body %+v", gotBody)
	}
	var gotClaims k8sEnrollmentClaims
	if err := json.Unmarshal(gotBody.Claims, &gotClaims); err != nil {
		t.Fatalf("claims decode: %v", err)
	}
	if gotClaims.PodUID != "uid-1" || gotClaims.PodNamespace != "agents" || gotClaims.PodName != "agent-1" || gotClaims.NodeName != "kind-worker" {
		t.Fatalf("claims = %+v", gotClaims)
	}
}

func TestEnrollmentRegisterRejectsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "namespace/serviceaccount/profile is not allowed", http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := enrollmentRegister(context.Background(), srv.URL, "sa-token", enrollmentRegisterRequest{
		Transport: enrollmentTransportWireGuard, Authorizer: "agents", WireGuardPublicKey: keyA,
	}); err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestEnrollmentRegisterRejectsIncompleteResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		// Valid transport but missing peer_ip / server_public_key / token.
		_ = json.NewEncoder(rw).Encode(enrollmentRegisterResponse{
			Transport: enrollmentTransportWireGuard,
		})
	}))
	defer srv.Close()
	if _, err := enrollmentRegister(context.Background(), srv.URL, "sa-token", enrollmentRegisterRequest{
		Transport: enrollmentTransportWireGuard, Authorizer: "agents", WireGuardPublicKey: keyA,
	}); err == nil {
		t.Fatal("expected error for incomplete response")
	}
}

func TestGatherEnrollmentClaimsKubernetes(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("  sa-token-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POD_NAME", "agent-1")
	t.Setenv("POD_NAMESPACE", "agents")
	t.Setenv("POD_UID", "uid-1")
	t.Setenv("NODE_NAME", "kind-worker")

	claims, cred, err := gatherEnrollmentClaims(enrollmentAuthorizerKubernetesTokenRev, tokenPath)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if cred != "sa-token-value" {
		t.Fatalf("credential = %q, want trimmed token", cred)
	}
	var got k8sEnrollmentClaims
	if err := json.Unmarshal(claims, &got); err != nil {
		t.Fatalf("claims decode: %v", err)
	}
	if got.PodName != "agent-1" || got.PodNamespace != "agents" || got.PodUID != "uid-1" || got.NodeName != "kind-worker" {
		t.Fatalf("claims = %+v", got)
	}

	if _, _, err := gatherEnrollmentClaims("oidc", tokenPath); err == nil {
		t.Fatal("expected error for unsupported authorizer type")
	}
}
