package tunnels

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log"
	"strings"
	"testing"

	cruntime "github.com/denoland/clawpatrol/internal/config/runtime"
)

// stubKubectl swaps the package runKubectl + lookupKubectl vars for the
// duration of a test, restoring them on cleanup. The handler receives
// each kubectl arg vector and returns (stdout, err).
func stubKubectl(t *testing.T, handler func(args []string) (string, error)) {
	t.Helper()
	origRun, origLook := runKubectl, lookupKubectl
	t.Cleanup(func() { runKubectl, lookupKubectl = origRun, origLook })
	lookupKubectl = func() error { return nil }
	runKubectl = func(_ context.Context, args []string) (string, error) {
		return handler(args)
	}
}

// argsHave reports whether the arg vector contains every needle.
func argsHave(args []string, needles ...string) bool {
	for _, n := range needles {
		found := false
		for _, a := range args {
			if a == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// TestInjectManagedLabels checks the managed labels are stamped onto a
// template that has no metadata.labels, that existing labels survive,
// and that the kubectl-create round-trip still parses as a Pod.
func TestInjectManagedLabels(t *testing.T) {
	src := `apiVersion: v1
kind: Pod
metadata:
  generateName: rds-jump-
  labels:
    operator: keep-me
spec:
  containers:
  - name: socat
    image: alpine/socat
`
	out, err := injectManagedLabels(src, "rds-jump")
	if err != nil {
		t.Fatalf("injectManagedLabels: %v", err)
	}
	// Re-parse to assert structure rather than string-matching YAML.
	doc, err := podFromTemplate(out)
	if err != nil {
		t.Fatalf("result not a valid pod template: %v", err)
	}
	if doc.generate != "rds-jump-" {
		t.Errorf("generateName lost: %q", doc.generate)
	}
	for _, want := range []string{
		managedByLabelKey + ": " + managedByLabelVal,
		tunnelLabelKey + ": rds-jump",
		"operator: keep-me",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

// TestInjectManagedLabelsNoMetadata covers a template with no metadata
// block at all (generateName-less templates are rejected elsewhere, but
// the injector must not panic on a bare manifest).
func TestInjectManagedLabelsNoMetadata(t *testing.T) {
	out, err := injectManagedLabels("apiVersion: v1\nkind: Pod\n", "t1")
	if err != nil {
		t.Fatalf("injectManagedLabels: %v", err)
	}
	if !strings.Contains(out, tunnelLabelKey+": t1") {
		t.Errorf("missing tunnel label:\n%s", out)
	}
}

// TestCleanupCreatedPodReMintsBeforeDelete is the core regression test
// for the leak: cleanup must re-mint the EKS bearer (reauth) BEFORE the
// delete shells out, because the bearer cached at Open expires in ~60s.
func TestCleanupCreatedPodReMintsBeforeDelete(t *testing.T) {
	var reauthCalled, deleteSawReauth bool
	stubKubectl(t, func(args []string) (string, error) {
		if argsHave(args, "delete") {
			deleteSawReauth = reauthCalled
		}
		return "", nil
	})
	rt := &kubernetesPortForwardTunnel{
		name:       "rds-jump",
		logger:     log.New(&bytes.Buffer{}, "", 0),
		ns:         "db",
		kubeconfig: "/tmp/kc.yaml",
		createdPod: "rds-jump-abc",
		cleanup:    true,
		reauth:     func(context.Context) error { reauthCalled = true; return nil },
	}
	if err := rt.cleanupCreatedPod(context.Background()); err != nil {
		t.Fatalf("cleanupCreatedPod: %v", err)
	}
	if !reauthCalled {
		t.Error("reauth was never called — delete would use a stale bearer")
	}
	if !deleteSawReauth {
		t.Error("delete ran before reauth — bearer not refreshed in time")
	}
	if rt.createdPod != "" {
		t.Errorf("createdPod not cleared on success: %q", rt.createdPod)
	}
}

// TestCleanupCreatedPodSurfacesError verifies a failed delete is
// returned (not swallowed), logged with the pod name, and the createdPod
// name is retained so the leak stays observable / reconcilable.
func TestCleanupCreatedPodSurfacesError(t *testing.T) {
	stubKubectl(t, func(args []string) (string, error) {
		if argsHave(args, "delete") {
			return "", errors.New("Unauthorized")
		}
		return "", nil
	})
	var logBuf bytes.Buffer
	rt := &kubernetesPortForwardTunnel{
		name:       "rds-jump",
		logger:     log.New(&logBuf, "", 0),
		ns:         "db",
		kubeconfig: "/tmp/kc.yaml",
		createdPod: "rds-jump-xyz",
		cleanup:    true,
		reauth:     func(context.Context) error { return nil },
	}
	err := rt.cleanupCreatedPod(context.Background())
	if err == nil {
		t.Fatal("expected error from failed delete, got nil")
	}
	if !strings.Contains(err.Error(), "rds-jump-xyz") {
		t.Errorf("error lacks pod name for triage: %v", err)
	}
	if !strings.Contains(logBuf.String(), "rds-jump-xyz") {
		t.Errorf("log lacks pod name for triage:\n%s", logBuf.String())
	}
	if rt.createdPod != "rds-jump-xyz" {
		t.Errorf("createdPod cleared despite failure: %q", rt.createdPod)
	}
}

// TestReconcileOrphansDeletesLabeledPods covers the startup sweep:
// list pods by the managed-label selector, delete each by name.
func TestReconcileOrphansDeletesLabeledPods(t *testing.T) {
	var listSelector string
	deleted := map[string]bool{}
	stubKubectl(t, func(args []string) (string, error) {
		switch {
		case argsHave(args, "get", "pods"):
			for i, a := range args {
				if a == "-l" && i+1 < len(args) {
					listSelector = args[i+1]
				}
			}
			return "pod/rds-jump-old1\npod/rds-jump-old2\n", nil
		case argsHave(args, "delete"):
			for _, a := range args {
				if strings.HasPrefix(a, "pod/") {
					deleted[strings.TrimPrefix(a, "pod/")] = true
				}
			}
			return "", nil
		}
		return "", nil
	})
	tn := &KubernetesPortForwardTunnel{
		Template:  "apiVersion: v1\nkind: Pod\nmetadata:\n  generateName: rds-jump-\n",
		Namespace: "db",
	}
	host := cruntime.TunnelHost{Name: "rds-jump", StateDir: t.TempDir()}
	if err := tn.ReconcileOrphans(context.Background(), host); err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if want := managedBySelector("rds-jump"); listSelector != want {
		t.Errorf("list selector = %q, want %q", listSelector, want)
	}
	for _, name := range []string{"rds-jump-old1", "rds-jump-old2"} {
		if !deleted[name] {
			t.Errorf("orphan %q not deleted", name)
		}
	}
}

// TestClosePropagatesCleanupError confirms a swallowed-no-more delete
// failure travels out through Close so TunnelManager.CloseAll can log it.
func TestClosePropagatesCleanupError(t *testing.T) {
	stubKubectl(t, func(args []string) (string, error) {
		if argsHave(args, "delete") {
			return "", errors.New("Unauthorized")
		}
		return "", nil
	})
	rt := &kubernetesPortForwardTunnel{
		name:       "rds-jump",
		logger:     log.New(&bytes.Buffer{}, "", 0),
		ns:         "db",
		createdPod: "rds-jump-xyz",
		cleanup:    true,
	}
	if err := rt.Close(); err == nil {
		t.Fatal("Close swallowed the delete failure")
	}
}

// TestReconcileOrphansSkipsNonTemplate confirms the sweep is a no-op for
// modes that never create pods, and when cleanup is disabled.
func TestReconcileOrphansSkipsNonTemplate(t *testing.T) {
	called := false
	stubKubectl(t, func([]string) (string, error) { called = true; return "", nil })
	cases := []KubernetesPortForwardTunnel{
		{Pod: "p", Port: 22}, // not template mode
		{Template: "kind: Pod\n", Cleanup: "keep", Namespace: "x"}, // cleanup disabled
	}
	for _, tn := range cases {
		if err := tn.ReconcileOrphans(context.Background(), cruntime.TunnelHost{Name: "t"}); err != nil {
			t.Fatalf("ReconcileOrphans: %v", err)
		}
	}
	if called {
		t.Error("kubectl invoked for a tunnel that creates no pods")
	}
}

func TestKubernetesValidateModes(t *testing.T) {
	cases := []struct {
		name    string
		tn      KubernetesPortForwardTunnel
		wantErr string // substring; "" means no error
	}{
		{
			name: "pod mode happy",
			tn:   KubernetesPortForwardTunnel{Pod: "p", Port: 22},
		},
		{
			name: "service mode happy",
			tn:   KubernetesPortForwardTunnel{Service: "postgres", Port: 5432},
		},
		{
			name: "selector mode happy",
			tn:   KubernetesPortForwardTunnel{Selector: map[string]string{"app": "x"}, Port: 22},
		},
		{
			name: "template mode happy",
			tn:   KubernetesPortForwardTunnel{Template: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n", Port: 5432},
		},
		{
			name:    "no mode",
			tn:      KubernetesPortForwardTunnel{Port: 22},
			wantErr: "exactly one",
		},
		{
			name:    "pod and service mutex",
			tn:      KubernetesPortForwardTunnel{Pod: "p", Service: "s", Port: 22},
			wantErr: "exactly one",
		},
		{
			name:    "pod and selector mutex",
			tn:      KubernetesPortForwardTunnel{Pod: "p", Selector: map[string]string{"a": "b"}, Port: 22},
			wantErr: "exactly one",
		},
		{
			name:    "service and template mutex",
			tn:      KubernetesPortForwardTunnel{Service: "s", Template: "x", Port: 22},
			wantErr: "exactly one",
		},
		{
			name:    "pod missing port",
			tn:      KubernetesPortForwardTunnel{Pod: "p"},
			wantErr: "port",
		},
		{
			name:    "service missing port",
			tn:      KubernetesPortForwardTunnel{Service: "s"},
			wantErr: "port",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.tn.validateModes()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("got %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Errorf("got nil, want error containing %q", tc.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestPodFromTemplateRejectsNonPod validates the template guard.
func TestPodFromTemplateRejectsNonPod(t *testing.T) {
	_, err := podFromTemplate(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: x
`)
	if err == nil {
		t.Fatal("expected rejection of Deployment manifest")
	}
}

func TestPodFromTemplateRequiresName(t *testing.T) {
	_, err := podFromTemplate(`apiVersion: v1
kind: Pod
spec:
  containers:
  - name: x
    image: busybox
`)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

// TestKctlArgsKubeconfigBeatsContext verifies that when a per-tunnel
// kubeconfig is set, --context is suppressed: kubectl reads
// `current-context` from the file we just wrote, so passing both
// would either confuse it (--context unknown) or, worse, silently
// flip back to a wrong context that happens to exist by name.
func TestKctlArgsKubeconfigBeatsContext(t *testing.T) {
	got := kctlArgs("/tmp/k.yaml", "ignored-context", "default", "get", "pods")
	if got[0] != "--kubeconfig" || got[1] != "/tmp/k.yaml" {
		t.Fatalf("args = %v, want --kubeconfig /tmp/k.yaml first", got)
	}
	for _, a := range got {
		if a == "--context" {
			t.Fatalf("args = %v, must not include --context when --kubeconfig is set", got)
		}
	}
}

// TestBuildEKSKubeconfig pins the shape kubectl will see when the
// tunnel mints its own kubeconfig: cluster.server + base64'd
// certificate-authority-data, user.token, single matching context,
// current-context set.
func TestBuildEKSKubeconfig(t *testing.T) {
	out := buildEKSKubeconfig("https://eks.example", "ca-pem-bytes", "k8s-aws-v1.xxxx")
	wantCA := "certificate-authority-data: " + base64.StdEncoding.EncodeToString([]byte("ca-pem-bytes"))
	for _, want := range []string{
		"apiVersion: v1",
		"kind: Config",
		"server: https://eks.example",
		wantCA,
		"token: k8s-aws-v1.xxxx",
		"current-context: ctx",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("buildEKSKubeconfig missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestPodFromTemplateAccepts(t *testing.T) {
	src := `apiVersion: v1
kind: Pod
metadata:
  generateName: jump-
spec:
  containers:
  - name: socat
    image: alpine/socat
`
	doc, err := podFromTemplate(src)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.generate != "jump-" {
		t.Errorf("generateName = %q", doc.generate)
	}
	if doc.raw != src {
		t.Error("raw yaml not round-tripped")
	}
}
