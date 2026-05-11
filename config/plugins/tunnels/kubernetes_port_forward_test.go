package tunnels

import (
	"strings"
	"testing"
)

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
