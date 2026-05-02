package main

import "testing"

func TestParseK8sPath(t *testing.T) {
	tests := []struct {
		method, path string
		want         k8sMeta
	}{
		{
			"GET", "/api/v1/pods",
			k8sMeta{Verb: "list", Resource: "pods"},
		},
		{
			"GET", "/api/v1/pods/nginx-abc",
			k8sMeta{Verb: "get", Resource: "pods", Name: "nginx-abc"},
		},
		{
			"GET", "/api/v1/namespaces/default/pods",
			k8sMeta{
				Verb: "list", Resource: "pods",
				Namespace: "default",
			},
		},
		{
			"GET", "/api/v1/namespaces/kube-system/pods/coredns-1",
			k8sMeta{
				Verb: "get", Resource: "pods",
				Namespace: "kube-system", Name: "coredns-1",
			},
		},
		{
			"POST", "/api/v1/namespaces/default/pods/debug-1/exec",
			k8sMeta{
				Verb: "create", Resource: "pods/exec",
				Namespace: "default", Name: "debug-1",
			},
		},
		{
			"POST", "/api/v1/namespaces/default/pods/debug-1/portforward",
			k8sMeta{
				Verb: "create", Resource: "pods/portforward",
				Namespace: "default", Name: "debug-1",
			},
		},
		{
			"DELETE", "/api/v1/namespaces/default/pods/debug-1",
			k8sMeta{
				Verb: "delete", Resource: "pods",
				Namespace: "default", Name: "debug-1",
			},
		},
		{
			"PUT", "/api/v1/namespaces/default/configmaps/my-config",
			k8sMeta{
				Verb: "update", Resource: "configmaps",
				Namespace: "default", Name: "my-config",
			},
		},
		{
			"PATCH", "/api/v1/namespaces/default/services/nginx",
			k8sMeta{
				Verb: "patch", Resource: "services",
				Namespace: "default", Name: "nginx",
			},
		},
		// Grouped API
		{
			"GET", "/apis/apps/v1/namespaces/default/deployments",
			k8sMeta{
				Verb: "list", Resource: "deployments",
				Namespace: "default",
			},
		},
		{
			"POST", "/api/v1/namespaces/default/secrets",
			k8sMeta{
				Verb: "create", Resource: "secrets",
				Namespace: "default",
			},
		},
		// Cluster-scoped
		{
			"GET", "/api/v1/nodes",
			k8sMeta{Verb: "list", Resource: "nodes"},
		},
		// Not a k8s path
		{
			"GET", "/healthz",
			k8sMeta{},
		},
		{
			"GET", "/",
			k8sMeta{},
		},
	}
	for _, tt := range tests {
		got := parseK8sPath(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("parseK8sPath(%q, %q)\n got %+v\nwant %+v",
				tt.method, tt.path, got, tt.want)
		}
	}
}

func TestMatchSet(t *testing.T) {
	tests := []struct {
		name string
		pats []string
		got  string
		want bool
	}{
		{"empty pats", nil, "anything", true},
		{"exact", []string{"pods"}, "pods", true},
		{"no match", []string{"pods"}, "secrets", false},
		{"multi", []string{"pods", "services"}, "services", true},
		{"glob", []string{"debug-*"}, "debug-abc", true},
		{"glob miss", []string{"debug-*"}, "nginx", false},
		{"negation blocks", []string{"!secrets"}, "secrets", false},
		{"negation allows", []string{"!secrets"}, "pods", true},
		{
			"pos + neg",
			[]string{"pods", "!secrets"},
			"pods", true,
		},
		{
			"neg wins over pos",
			[]string{"*", "!secrets"},
			"secrets", false,
		},
		{
			"neg no pos = pass",
			[]string{"!secrets"},
			"configmaps", true,
		},
	}
	for _, tt := range tests {
		got := matchSet(tt.pats, tt.got)
		if got != tt.want {
			t.Errorf("%s: matchSet(%v, %q) = %v, want %v",
				tt.name, tt.pats, tt.got, got, tt.want)
		}
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pat, s string
		want   bool
	}{
		{"pods", "pods", true},
		{"pods", "secrets", false},
		{"debug-*", "debug-abc", true},
		{"debug-*", "nginx", false},
		{"*/exec", "pods/exec", true},
		{"*/exec", "pods/attach", false},
		{"*", "anything", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got := matchGlob(tt.pat, tt.s)
		if got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v",
				tt.pat, tt.s, got, tt.want)
		}
	}
}
