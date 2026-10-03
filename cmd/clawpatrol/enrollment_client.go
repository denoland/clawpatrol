package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const enrollmentHTTPTimeout = 15 * time.Second

var enrollmentHTTPClient = &http.Client{Timeout: enrollmentHTTPTimeout}

// Enrollment client core used by `clawpatrol bridge`: register through the
// configured authorizer, fetch the env-pushdown, and best-effort deregister
// on shutdown. There is no heartbeat — the gateway observes liveness from
// the WireGuard device (rx_bytes), so keepalive traffic is the liveness
// signal.

func enrollmentRegister(ctx context.Context, gatewayURL, token string, reqBody enrollmentRegisterRequest) (enrollmentRegisterResponse, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(reqBody); err != nil {
		return enrollmentRegisterResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(gatewayURL, "/")+enrollmentRegisterPath, &buf)
	if err != nil {
		return enrollmentRegisterResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := enrollmentHTTPClient.Do(req)
	if err != nil {
		return enrollmentRegisterResponse{}, fmt.Errorf("register: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return enrollmentRegisterResponse{}, fmt.Errorf("register status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out enrollmentRegisterResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return enrollmentRegisterResponse{}, fmt.Errorf("register decode: %w", err)
	}
	if out.Transport != enrollmentTransportWireGuard {
		return enrollmentRegisterResponse{}, fmt.Errorf("register response has unsupported transport %q", out.Transport)
	}
	if out.PeerIP == "" || out.ServerPublicKey == "" || out.Endpoint == "" || out.APIToken == "" {
		return enrollmentRegisterResponse{}, fmt.Errorf("register response missing peer_ip, server_public_key, endpoint, or api_token")
	}
	return out, nil
}

func enrollmentFetchEnv(ctx context.Context, gatewayURL, apiToken string) ([]pushdownEnvVar, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(gatewayURL, "/")+"/api/env-pushdown", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := enrollmentHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch env-pushdown: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch env-pushdown status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseEnvPushdownJSON(raw)
}

func enrollmentDeregister(ctx context.Context, gatewayURL, apiToken string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimRight(gatewayURL, "/")+enrollmentRegisterPath, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := enrollmentHTTPClient.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}
}

// gatherEnrollmentClaims dispatches on the type label from the gateway's
// `enrollment "<type>" "<name>"` block. It returns the claims and credential
// produced by the matching client provider. v1 ships one provider.
func gatherEnrollmentClaims(authorizerType, kubeTokenPath string) (json.RawMessage, string, error) {
	switch authorizerType {
	case enrollmentAuthorizerKubernetesTokenRev:
		return kubernetesProviderClaims(kubeTokenPath)
	default:
		return nil, "", fmt.Errorf("unsupported enrollment authorizer type %q", authorizerType)
	}
}

// kubernetesProviderClaims gathers the kubernetes_token_review identity:
// claims from the downward-API POD_* env, credential from the projected
// ServiceAccount token.
func kubernetesProviderClaims(kubeTokenPath string) (json.RawMessage, string, error) {
	podName := os.Getenv("POD_NAME")
	podNamespace := os.Getenv("POD_NAMESPACE")
	podUID := os.Getenv("POD_UID")
	nodeName := os.Getenv("NODE_NAME")
	if podName == "" || podNamespace == "" || podUID == "" {
		return nil, "", fmt.Errorf("POD_NAME, POD_NAMESPACE, and POD_UID must be supplied by the Downward API")
	}
	tokenBytes, err := os.ReadFile(kubeTokenPath)
	if err != nil {
		return nil, "", fmt.Errorf("read serviceaccount token: %w", err)
	}
	claims, err := json.Marshal(k8sEnrollmentClaims{
		PodName:      podName,
		PodNamespace: podNamespace,
		PodUID:       podUID,
		NodeName:     nodeName,
	})
	if err != nil {
		return nil, "", err
	}
	return claims, strings.TrimSpace(string(tokenBytes)), nil
}
