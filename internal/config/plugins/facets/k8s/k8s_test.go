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
			name:   "non-k8s-shaped path returns nil",
			method: "GET",
			rawURL: "/some/random/path",
			want:   nil,
		},
		{
			name:   "health probe parses as verb=meta",
			method: "GET",
			rawURL: "/healthz",
			want:   &Meta{Verb: "meta"},
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

// TestParsePathSpecialVerbs covers the path-prefix verb forms
// kube-apiserver still registers: `/api/v1/watch/<resource path>` and
// `/api/v1/proxy/<resource path>`. The prefix segment names the verb
// and must not land in Resource — a request read as
// `{verb: get, resource: watch}` slips past every rule keyed on the
// resource it actually touches.
func TestParsePathSpecialVerbs(t *testing.T) {
	cases := []struct {
		name   string
		method string
		rawURL string
		want   *Meta
	}{
		{
			name:   "legacy watch prefix on namespaced secrets",
			method: "GET",
			rawURL: "/api/v1/watch/namespaces/team-a/secrets",
			want: &Meta{
				Verb: "watch", Resource: "secrets", Namespace: "team-a",
			},
		},
		{
			name:   "legacy watch prefix under a named group",
			method: "GET",
			rawURL: "/apis/apps/v1/watch/deployments",
			want:   &Meta{Verb: "watch", Resource: "deployments"},
		},
		{
			name:   "legacy watch prefix on a single object",
			method: "GET",
			rawURL: "/api/v1/watch/namespaces/team-a/secrets/db-password",
			want: &Meta{
				Verb: "watch", Resource: "secrets",
				Namespace: "team-a", Name: "db-password",
			},
		},
		{
			name:   "watch prefix takes the verb from the path, not the method",
			method: "POST",
			rawURL: "/api/v1/watch/namespaces/team-a/secrets",
			want: &Meta{
				Verb: "watch", Resource: "secrets", Namespace: "team-a",
			},
		},
		{
			name:   "node proxy prefix reaches the kubelet",
			method: "GET",
			rawURL: "/api/v1/proxy/nodes/worker-1/runningpods",
			want:   &Meta{Verb: "proxy", Resource: "nodes", Name: "worker-1"},
		},
		{
			name:   "pod proxy prefix keeps the proxied path out of the resource",
			method: "GET",
			rawURL: "/api/v1/proxy/namespaces/team-a/pods/api-0/metrics",
			want: &Meta{
				Verb: "proxy", Resource: "pods",
				Namespace: "team-a", Name: "api-0",
			},
		},
		{
			name:   "proxy prefix with a multi-segment proxied path and query",
			method: "GET",
			rawURL: "/api/v1/proxy/nodes/worker-1/logs/pods/x.log?tailLines=5",
			want: &Meta{
				Verb: "proxy", Resource: "nodes", Name: "worker-1",
				Params: map[string]string{"tailLines": "5"},
			},
		},
		{
			name:   "proxy subresource form keeps its method-derived verb",
			method: "GET",
			rawURL: "/api/v1/namespaces/team-a/pods/api-0/proxy/metrics",
			want: &Meta{
				Verb: "get", Resource: "pods/proxy",
				Namespace: "team-a", Name: "api-0",
			},
		},
		{
			name:   "namespace object addressed by name",
			method: "DELETE",
			rawURL: "/api/v1/namespaces/team-a",
			want: &Meta{
				Verb: "delete", Resource: "namespaces",
				Namespace: "team-a", Name: "team-a",
			},
		},
		{
			name:   "namespace subresource stays on the namespace object",
			method: "PUT",
			rawURL: "/api/v1/namespaces/team-a/finalize",
			want: &Meta{
				Verb: "update", Resource: "namespaces/finalize",
				Namespace: "team-a", Name: "team-a",
			},
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

// TestParsePathRefusesUnknownShapes locks in the refusal contract: a
// shape the parser can't decompose yields no Meta, which makes every
// k8s rule Unevaluable and the dispatcher synthesize a deny. A
// populated-but-wrong tuple would instead evaluate cleanly to false
// and fall through to the default allow.
func TestParsePathRefusesUnknownShapes(t *testing.T) {
	cases := []struct {
		name   string
		method string
		rawURL string
	}{
		{"watch prefix addressing nothing", "GET", "/api/v1/watch"},
		{"proxy prefix addressing nothing", "GET", "/api/v1/proxy"},
		{"group watch prefix addressing nothing", "GET", "/apis/apps/v1/watch"},
		{"empty path segment", "GET", "/api/v1//secrets"},
		{"method with no resource verb", "OPTIONS", "/api/v1/namespaces/team-a/secrets"},
		{"unknown method on a subresource", "TRACE", "/api/v1/namespaces/team-a/pods/api-0/exec"},
		{"not a kubernetes API path", "GET", "/registry/v2/images/list"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parsePath(tc.method, tc.rawURL); got != nil {
				t.Fatalf("parsePath(%q, %q) = %#v, want nil", tc.method, tc.rawURL, got)
			}
		})
	}
}

// TestParsePathBoolParams covers the boolean query params. The
// apiserver resolves only "0" and a case-insensitive "false" to false
// and every other present value to true, so the params a rule reads
// carry that verdict rather than the spelling that happened to arrive.
func TestParsePathBoolParams(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		rawURL     string
		wantVerb   string
		wantParams map[string]string
	}{
		{
			name: "watch=1 is a watch", method: "GET",
			rawURL:   "/api/v1/namespaces/team-a/secrets?watch=1",
			wantVerb: "watch", wantParams: map[string]string{"watch": "true"},
		},
		{
			name: "watch=TRUE is a watch", method: "GET",
			rawURL:   "/api/v1/namespaces/team-a/secrets?watch=TRUE",
			wantVerb: "watch", wantParams: map[string]string{"watch": "true"},
		},
		{
			name: "bare watch param is a watch", method: "GET",
			rawURL:   "/api/v1/namespaces/team-a/secrets?watch",
			wantVerb: "watch", wantParams: map[string]string{"watch": "true"},
		},
		{
			name: "watch=off is a watch", method: "GET",
			rawURL:   "/api/v1/namespaces/team-a/secrets?watch=off",
			wantVerb: "watch", wantParams: map[string]string{"watch": "true"},
		},
		{
			name: "watch=0 is a plain list", method: "GET",
			rawURL:   "/api/v1/namespaces/team-a/secrets?watch=0",
			wantVerb: "list", wantParams: map[string]string{"watch": "false"},
		},
		{
			name: "watch=False is a plain list", method: "GET",
			rawURL:   "/api/v1/namespaces/team-a/secrets?watch=False",
			wantVerb: "list", wantParams: map[string]string{"watch": "false"},
		},
		{
			name: "exec bool params normalize, others pass through", method: "POST",
			rawURL:   "/api/v1/namespaces/team-a/pods/api-0/exec?stdin=TRUE&tty=1&stderr=false&command=sh",
			wantVerb: "create",
			wantParams: map[string]string{
				"stdin": "true", "tty": "true", "stderr": "false", "command": "sh",
			},
		},
		{
			name: "non-bool params keep their bytes", method: "GET",
			rawURL:   "/api/v1/pods?limit=1&continue=0&dryRun=All",
			wantVerb: "list",
			wantParams: map[string]string{
				"limit": "1", "continue": "0", "dryRun": "All",
			},
		},
		{
			name: "log follow normalizes", method: "GET",
			rawURL:     "/api/v1/namespaces/team-a/pods/api-0/log?follow=yes&container=app",
			wantVerb:   "get",
			wantParams: map[string]string{"follow": "true", "container": "app"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePath(tc.method, tc.rawURL)
			if got == nil {
				t.Fatalf("parsePath(%q, %q) = nil", tc.method, tc.rawURL)
			}
			if got.Verb != tc.wantVerb {
				t.Errorf("verb = %q, want %q", got.Verb, tc.wantVerb)
			}
			if !reflect.DeepEqual(got.Params, tc.wantParams) {
				t.Errorf("params = %#v, want %#v", got.Params, tc.wantParams)
			}
		})
	}
}

// TestParsePathNamedWatch pins the one place the parser is
// deliberately broader than the apiserver's own labelling: a
// single-object read with a truthy `watch` param is reported as a
// watch, so a rule banning `watch` covers it. The apiserver keeps
// such a request as `get` and elevates only a nameless read.
func TestParsePathNamedWatch(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		rawURL   string
		wantVerb string
	}{
		{
			"named read with watch", "GET",
			"/api/v1/namespaces/team-a/secrets/db-password?watch=1", "watch",
		},
		{
			"nameless read with watch", "GET",
			"/api/v1/namespaces/team-a/secrets?watch=1", "watch",
		},
		{
			"named read without watch", "GET",
			"/api/v1/namespaces/team-a/secrets/db-password", "get",
		},
		{
			"a path-prefix verb is not elevated", "GET",
			"/api/v1/proxy/nodes/worker-1/runningpods?watch=true", "proxy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePath(tc.method, tc.rawURL)
			if got == nil {
				t.Fatalf("parsePath(%q, %q) = nil", tc.method, tc.rawURL)
			}
			if got.Verb != tc.wantVerb {
				t.Errorf("verb = %q, want %q", got.Verb, tc.wantVerb)
			}
		})
	}
}
