package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

func TestNormalizeWGPublicKey(t *testing.T) {
	_, pubHex, pubB64, err := wgGenKeypair()
	if err != nil {
		t.Fatalf("wgGenKeypair: %v", err)
	}
	if got, err := normalizeWGPublicKey(pubHex); err != nil || got != pubHex {
		t.Fatalf("hex normalize = %q, %v; want %q", got, err, pubHex)
	}
	if got, err := normalizeWGPublicKey(pubB64); err != nil || got != pubHex {
		t.Fatalf("base64 normalize = %q, %v; want %q", got, err, pubHex)
	}
	if _, err := normalizeWGPublicKey("not-a-key"); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestK8sServiceAccountAndAllowlist(t *testing.T) {
	ns, sa, ok := serviceAccountFromUsername("system:serviceaccount:agents:agent-runner")
	if !ok || ns != "agents" || sa != "agent-runner" {
		t.Fatalf("serviceAccountFromUsername = %q, %q, %v", ns, sa, ok)
	}
	if _, _, ok := serviceAccountFromUsername("alice@example.com"); ok {
		t.Fatal("non-serviceaccount username accepted")
	}
	enr := &config.CompiledK8sEnrollment{
		Matches: []config.CompiledK8sMatch{{
			Namespace:      "agents",
			ServiceAccount: "agent-runner",
			ProfileLabel:   config.K8sDefaultProfileLabel,
			Profiles:       []string{"default", "prod"},
		}},
	}
	labels := map[string]string{config.K8sDefaultProfileLabel: "prod"}
	if got, err := k8sResolveProfile(enr, "agents", "agent-runner", labels); err != nil || got != "prod" {
		t.Fatalf("resolve profile = %q, %v; want prod", got, err)
	}
	if _, err := k8sResolveProfile(enr, "agents", "other", labels); err == nil {
		t.Fatal("wrong serviceaccount allowed")
	}
	adminLabels := map[string]string{config.K8sDefaultProfileLabel: "admin"}
	if _, err := k8sResolveProfile(enr, "agents", "agent-runner", adminLabels); err == nil {
		t.Fatal("wrong profile allowed")
	}
	if _, err := k8sResolveProfile(enr, "agents", "agent-runner", nil); err == nil {
		t.Fatal("missing profile label accepted")
	}
}

type fakeK8sVerifier func(context.Context, string, k8sEnrollmentClaims, *config.CompiledK8sEnrollment) (k8sVerifiedPod, error)

func (f fakeK8sVerifier) VerifyPod(ctx context.Context, token string, claims k8sEnrollmentClaims, enr *config.CompiledK8sEnrollment) (k8sVerifiedPod, error) {
	return f(ctx, token, claims, enr)
}

func TestKubernetesTokenReviewAuthorizerIdentity(t *testing.T) {
	enr := &config.CompiledK8sEnrollment{}
	claims, err := json.Marshal(k8sEnrollmentClaims{
		PodName:      "agent-1",
		PodNamespace: "agents",
		PodUID:       "uid-1",
		NodeName:     "kind-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := &kubernetesTokenReviewAuthorizer{
		name: "agents",
		enr:  enr,
		verifier: fakeK8sVerifier(func(_ context.Context, token string, got k8sEnrollmentClaims, _ *config.CompiledK8sEnrollment) (k8sVerifiedPod, error) {
			if token != "pod-token" {
				t.Fatalf("token = %q, want pod-token", token)
			}
			if got.PodUID != "uid-1" {
				t.Fatalf("claims = %+v", got)
			}
			return k8sVerifiedPod{
				Namespace:      got.PodNamespace,
				Name:           got.PodName,
				UID:            got.PodUID,
				ServiceAccount: "agent-runner",
				Profile:        "default",
				NodeName:       got.NodeName,
			}, nil
		}),
	}
	id, err := auth.Authorize(context.Background(), "pod-token", claims)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if id.SubjectKey != "kubernetes:agents:uid-1" {
		t.Fatalf("subject key = %q", id.SubjectKey)
	}
	if id.ReplacementKey != "kubernetes:agents:agent-1" {
		t.Fatalf("replacement key = %q", id.ReplacementKey)
	}
	if id.DisplayName != "agents/agent-1" || id.Owner != "system:serviceaccount:agents:agent-runner" || id.Profile != "default" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestInClusterK8sClientVerifiesBoundPodToken(t *testing.T) {
	var gotAudience string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			var review struct {
				Spec struct {
					Token     string   `json:"token"`
					Audiences []string `json:"audiences"`
				} `json:"spec"`
			}
			if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
				t.Errorf("decode TokenReview: %v", err)
				http.Error(rw, "bad review", http.StatusBadRequest)
				return
			}
			if review.Spec.Token != "pod-token" || len(review.Spec.Audiences) != 1 {
				t.Errorf("TokenReview spec = %+v", review.Spec)
			} else {
				gotAudience = review.Spec.Audiences[0]
			}
			_ = json.NewEncoder(rw).Encode(map[string]any{"status": map[string]any{
				"authenticated": true,
				"audiences":     []string{"clawpatrol"},
				"user": map[string]any{
					"username": "system:serviceaccount:agents:agent-runner",
					"extra": map[string][]string{
						"authentication.kubernetes.io/pod-name": {"agent-1"},
						"authentication.kubernetes.io/pod-uid":  {"uid-1"},
					},
				},
			}})
		case "/api/v1/namespaces/agents/pods/agent-1":
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"metadata": map[string]any{
					"uid":    "uid-1",
					"labels": map[string]string{config.K8sDefaultProfileLabel: "default"},
				},
				"spec": map[string]string{
					"serviceAccountName": "agent-runner",
					"nodeName":           "kind-worker",
				},
			})
		default:
			http.NotFound(rw, r)
		}
	}))
	defer srv.Close()

	client := &inClusterK8sClient{baseURL: srv.URL, token: "gateway-token", client: srv.Client()}
	pod, err := client.VerifyPod(context.Background(), "pod-token", k8sEnrollmentClaims{
		PodName:      "agent-1",
		PodNamespace: "agents",
		PodUID:       "uid-1",
	}, testCompiledK8sEnrollment())
	if err != nil {
		t.Fatalf("VerifyPod: %v", err)
	}
	if gotAudience != "clawpatrol" {
		t.Fatalf("TokenReview audience = %q, want clawpatrol", gotAudience)
	}
	if pod.UID != "uid-1" || pod.ServiceAccount != "agent-runner" || pod.Profile != "default" {
		t.Fatalf("verified pod = %+v", pod)
	}
}

func TestInClusterK8sClientRejectsUnboundTokenReview(t *testing.T) {
	tests := []struct {
		name       string
		audiences  []string
		extra      map[string][]string
		wantErrSub string
	}{
		{
			name:       "wrong audience",
			audiences:  []string{"kubernetes"},
			extra:      boundPodTokenExtra("agent-1", "uid-1"),
			wantErrSub: "does not include audience",
		},
		{
			name:       "missing pod binding",
			audiences:  []string{"clawpatrol"},
			wantErrSub: "not bound to a pod name",
		},
		{
			name:       "different pod binding",
			audiences:  []string{"clawpatrol"},
			extra:      boundPodTokenExtra("other-agent", "other-uid"),
			wantErrSub: "does not match submitted pod",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(rw).Encode(map[string]any{"status": map[string]any{
					"authenticated": true,
					"audiences":     tc.audiences,
					"user": map[string]any{
						"username": "system:serviceaccount:agents:agent-runner",
						"extra":    tc.extra,
					},
				}})
			}))
			defer srv.Close()
			client := &inClusterK8sClient{baseURL: srv.URL, token: "gateway-token", client: srv.Client()}
			_, err := client.VerifyPod(context.Background(), "pod-token", k8sEnrollmentClaims{
				PodName:      "agent-1",
				PodNamespace: "agents",
				PodUID:       "uid-1",
			}, testCompiledK8sEnrollment())
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("VerifyPod error = %v, want substring %q", err, tc.wantErrSub)
			}
		})
	}
}

func testCompiledK8sEnrollment() *config.CompiledK8sEnrollment {
	return &config.CompiledK8sEnrollment{
		Audience: "clawpatrol",
		Matches: []config.CompiledK8sMatch{{
			Namespace:      "agents",
			ServiceAccount: "agent-runner",
			ProfileLabel:   config.K8sDefaultProfileLabel,
			Profiles:       []string{"default"},
		}},
	}
}

func boundPodTokenExtra(name, uid string) map[string][]string {
	return map[string][]string{
		"authentication.kubernetes.io/pod-name": {name},
		"authentication.kubernetes.io/pod-uid":  {uid},
	}
}

// cleanupEnrolledPeerLocked tears down every trace of an enrolled peer:
// the WireGuard peer (and its wg_peers row), the API token, and the
// device/agent registry entries.
func TestCleanupEnrolledPeer(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	startEnrollmentTestWGServer(t, g)

	resp, err := registerFor(t, g, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := g.enrolledPeerByIP(resp.PeerIP); err != nil {
		t.Fatalf("precondition: enrolled peer not present: %v", err)
	}

	g.enrollmentMu.Lock()
	if err := g.cleanupEnrolledPeerLocked(context.Background(), resp.PeerIP); err != nil {
		t.Fatalf("cleanup enrolled peer: %v", err)
	}
	g.enrollmentMu.Unlock()

	if _, err := g.enrolledPeerByIP(resp.PeerIP); err == nil {
		t.Fatal("enrolled peer still present after cleanup")
	}
	if got := wgPeerRowsForIP(t, g, resp.PeerIP); got != 0 {
		t.Fatalf("wg_peers rows after cleanup = %d, want 0", got)
	}
	if got := peerIPForAPIToken(g.db, resp.APIToken); got != "" {
		t.Fatalf("peer API token still resolves to %q", got)
	}
	if g.onboard.HasDevice(resp.PeerIP) {
		t.Fatal("device row still present after cleanup")
	}
}
