package runtime_test

import (
	"reflect"
	"testing"

	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/runtime"
)

func TestParseK8sPath(t *testing.T) {
	cases := []struct {
		name   string
		method string
		rawURL string
		want   *match.K8sMeta
	}{
		{
			name:   "core namespaced pod get",
			method: "GET",
			rawURL: "/api/v1/namespaces/default/pods/nginx",
			want: &match.K8sMeta{
				Verb: "get", Resource: "pods", Namespace: "default", Name: "nginx",
			},
		},
		{
			name:   "pod logs subresource",
			method: "GET",
			rawURL: "/api/v1/namespaces/default/pods/nginx/log?container=app",
			want: &match.K8sMeta{
				Verb:      "get",
				Resource:  "pods/log",
				Namespace: "default",
				Name:      "nginx",
				Params:    map[string]string{"container": "app"},
			},
		},
		{
			name:   "interactive exec subresource preserves params",
			method: "POST",
			rawURL: "/api/v1/namespaces/default/pods/nginx/exec?stdin=true&tty=true&command=sh",
			want: &match.K8sMeta{
				Verb:      "create",
				Resource:  "pods/exec",
				Namespace: "default",
				Name:      "nginx",
				Params:    map[string]string{"stdin": "true", "tty": "true", "command": "sh"},
			},
		},
		{
			name:   "portforward subresource",
			method: "POST",
			rawURL: "/api/v1/namespaces/default/pods/nginx/portforward?ports=5432",
			want: &match.K8sMeta{
				Verb:      "create",
				Resource:  "pods/portforward",
				Namespace: "default",
				Name:      "nginx",
				Params:    map[string]string{"ports": "5432"},
			},
		},
		{
			name:   "named API group deployment",
			method: "PATCH",
			rawURL: "/apis/apps/v1/namespaces/default/deployments/web",
			want: &match.K8sMeta{
				Verb: "patch", Resource: "deployments", Namespace: "default", Name: "web",
			},
		},
		{
			name:   "cluster scoped list with watch param is watch verb",
			method: "GET",
			rawURL: "/api/v1/pods?watch=true&resourceVersion=123",
			want: &match.K8sMeta{
				Verb:     "watch",
				Resource: "pods",
				Params:   map[string]string{"watch": "true", "resourceVersion": "123"},
			},
		},
		{
			name:   "non k8s path returns nil",
			method: "GET",
			rawURL: "/healthz",
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runtime.ParseK8sPath(tc.method, tc.rawURL)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseK8sPath(%q, %q) = %#v, want %#v", tc.method, tc.rawURL, got, tc.want)
			}
		})
	}
}
