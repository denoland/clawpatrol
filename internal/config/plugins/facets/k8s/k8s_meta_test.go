package k8s

import "testing"

// TestParsePathMeta covers the non-resource URIs kubectl/client-go
// probes reflexively. They must all parse to verb=meta with empty
// resource so a single `k8s.verb == "meta"` rule covers the set.
func TestParsePathMeta(t *testing.T) {
	meta := []string{
		"/api", "/apis",
		"/api/v1",
		"/apis/apps", "/apis/apps/v1",
		"/healthz", "/livez", "/readyz",
		"/version", "/metrics",
		"/openapi/v2", "/openapi/v3", "/openapi/v3/apis/apps/v1",
	}
	for _, u := range meta {
		m := parsePath("GET", u)
		if m == nil {
			t.Errorf("%s: got nil, want verb=meta", u)
			continue
		}
		if m.Verb != "meta" {
			t.Errorf("%s: verb=%q, want meta", u, m.Verb)
		}
		if m.Resource != "" || m.Namespace != "" || m.Name != "" {
			t.Errorf("%s: meta path leaked resource/ns/name: %+v", u, m)
		}
	}

	// Resource calls must NOT collapse into meta — they need to
	// keep flowing through the regular list/get path so deny rules
	// keyed on a specific resource still fire.
	resource := []struct{ url, verb, res string }{
		{"/api/v1/pods", "list", "pods"},
		{"/api/v1/namespaces", "list", "namespaces"},
		{"/api/v1/namespaces/foo/pods", "list", "pods"},
		{"/apis/apps/v1/deployments", "list", "deployments"},
	}
	for _, c := range resource {
		m := parsePath("GET", c.url)
		if m == nil {
			t.Errorf("%s: nil meta on resource URL", c.url)
			continue
		}
		if m.Verb != c.verb || m.Resource != c.res {
			t.Errorf("%s: got verb=%q resource=%q, want %q/%q",
				c.url, m.Verb, m.Resource, c.verb, c.res)
		}
	}
}
