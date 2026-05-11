package k8s

import (
	"reflect"
	"testing"
)

func TestParsePath(t *testing.T) {
	cases := []struct {
		name   string
		method string
		rawURL string
		want   *Meta
	}{
		{
			name:   "core namespaced pod get",
			method: "GET",
			rawURL: "/api/v1/namespaces/default/pods/nginx",
			want: &Meta{
				Verb: "get", Resource: "pods", Namespace: "default", Name: "nginx",
			},
		},
		{
			name:   "pod logs subresource",
			method: "GET",
			rawURL: "/api/v1/namespaces/default/pods/nginx/log?container=app",
			want: &Meta{
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
			want: &Meta{
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
			want: &Meta{
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
			want: &Meta{
				Verb: "patch", Resource: "deployments", Namespace: "default", Name: "web",
			},
		},
		{
			name:   "cluster scoped list with watch param is watch verb",
			method: "GET",
			rawURL: "/api/v1/pods?watch=true&resourceVersion=123",
			want: &Meta{
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
			got := parsePath(tc.method, tc.rawURL)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parsePath(%q, %q) = %#v, want %#v", tc.method, tc.rawURL, got, tc.want)
			}
		})
	}
}
