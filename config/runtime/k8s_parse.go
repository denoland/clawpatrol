package runtime

import (
	"net/url"
	"strings"

	"github.com/denoland/clawpatrol/config/match"
)

// ParseK8sPath best-effort decomposes a Kubernetes API request into
// the (verb, resource, namespace, name, params) tuple the K8sMatcher
// walks. Returns nil when the URL isn't k8s-shaped.
//
// Supported shapes:
//
//	/api/v1/<resource>                              → list
//	/api/v1/<resource>/<name>                       → get / update / patch / delete
//	/api/v1/namespaces/<ns>/<resource>              → list in ns
//	/api/v1/namespaces/<ns>/<resource>/<name>       → single resource
//	/api/v1/namespaces/<ns>/<resource>/<name>/<sub> → subresource (exec / portforward / etc.)
//	/apis/<group>/<v>/...                           → same shapes under named groups
//
// Verb derives from the HTTP method (GET → list/get, POST → create,
// PUT → update, PATCH → patch, DELETE → delete) — kubectl uses POST
// to /api/v1/.../<name>/exec so the matcher relies on Resource ending
// in "/exec" rather than special-casing the verb.
func ParseK8sPath(method, rawURL string) *match.K8sMeta {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return nil
	}
	switch parts[0] {
	case "api":
		parts = parts[2:]
	case "apis":
		if len(parts) < 3 {
			return nil
		}
		parts = parts[3:]
	default:
		return nil
	}
	if len(parts) == 0 {
		return nil
	}
	m := &match.K8sMeta{}
	if parts[0] == "namespaces" && len(parts) >= 2 {
		m.Namespace = parts[1]
		parts = parts[2:]
	}
	if len(parts) == 0 {
		return m
	}
	m.Resource = parts[0]
	parts = parts[1:]
	if len(parts) > 0 {
		m.Name = parts[0]
		parts = parts[1:]
	}
	if len(parts) > 0 {
		m.Resource = m.Resource + "/" + parts[0]
	}
	switch strings.ToUpper(method) {
	case "GET":
		if m.Name == "" {
			m.Verb = "list"
		} else {
			m.Verb = "get"
		}
	case "POST":
		m.Verb = "create"
	case "PUT":
		m.Verb = "update"
	case "PATCH":
		m.Verb = "patch"
	case "DELETE":
		m.Verb = "delete"
	}
	if q := u.Query(); len(q) > 0 {
		m.Params = make(map[string]string, len(q))
		for k, v := range q {
			if len(v) > 0 {
				m.Params[k] = v[0]
			}
		}
	}
	return m
}
