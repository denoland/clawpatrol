package main

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"
)

// Match is a per-protocol predicate. HTTP fields are evaluated against
// req method/path/query/headers/body. K8s fields require the rule's
// host to look like a Kubernetes API server — verb/resource/namespace/
// name are derived from the request path at MITM time. SQL fields are
// declared but inert until the postgres gateway lands; rules using
// them today never fire.
type Match struct {
	// --- HTTP --------------------------------------------------------
	Method   []string            `hcl:"method,optional" yaml:"method,omitempty" json:"method,omitempty"`
	Path     string              `hcl:"path,optional" yaml:"path,omitempty" json:"path,omitempty"`
	Query    map[string][]string `hcl:"query,optional" yaml:"query,omitempty" json:"query,omitempty"`
	Headers  map[string]string   `hcl:"headers,optional" yaml:"headers,omitempty" json:"headers,omitempty"`
	BodyJSON map[string]string   `hcl:"body_json,optional" yaml:"body_json,omitempty" json:"body_json,omitempty"`
	// BodyContains: substring check on raw body. Cheap fallback when
	// body_json's exact-shape match is overkill.
	BodyContains string `hcl:"body_contains,optional" yaml:"body_contains,omitempty" json:"body_contains,omitempty"`

	// --- Kubernetes --------------------------------------------------
	// Globs supported. Prefix a value with "!" to negate.
	Resource  []string `hcl:"resource,optional" yaml:"resource,omitempty" json:"resource,omitempty"`
	Verb      []string `hcl:"verb,optional" yaml:"verb,omitempty" json:"verb,omitempty"`
	Namespace []string `hcl:"namespace,optional" yaml:"namespace,omitempty" json:"namespace,omitempty"`
	Name      []string `hcl:"name,optional" yaml:"name,omitempty" json:"name,omitempty"`
	// Params: arbitrary k8s query params (e.g. `stdin = "true"` for
	// `kubectl exec --stdin`).
	Params map[string]string `hcl:"params,optional" yaml:"params,omitempty" json:"params,omitempty"`

	// --- SQL (postgres / clickhouse) — declared but inert today.
	// Postgres wire protocol gateway is TBD; rules using these
	// fields parse but never fire at MITM time.
	SQLVerb        []string `hcl:"sql_verb,optional" yaml:"sql_verb,omitempty" json:"sql_verb,omitempty"`
	SQLTables      []string `hcl:"tables,optional" yaml:"tables,omitempty" json:"tables,omitempty"`
	SQLFunction    []string `hcl:"function,optional" yaml:"function,omitempty" json:"function,omitempty"`
	Statement      string   `hcl:"statement,optional" yaml:"statement,omitempty" json:"statement,omitempty"`
	StatementRegex string   `hcl:"statement_regex,optional" yaml:"statement_regex,omitempty" json:"statement_regex,omitempty"`
	Account        string   `hcl:"account,optional" yaml:"account,omitempty" json:"account,omitempty"`
}

// k8sMeta is the (verb, resource, namespace, name) tuple derived from
// a Kubernetes API path. Empty fields when the path isn't k8s-shaped.
type k8sMeta struct {
	Verb      string // get | list | watch | create | update | patch | delete | <subresource>
	Resource  string // "pods", "secrets", or "<resource>/<subresource>" (e.g. "pods/exec")
	Namespace string
	Name      string
}

// parseK8sPath best-effort decomposes a request path into k8s metadata.
// Handles core (`/api/v1/...`) and grouped (`/apis/<group>/<v>/...`)
// API styles. Cluster-scoped resources have empty Namespace.
//
// Supported shapes:
//
//	/api/v1/<resource>                              — list
//	/api/v1/<resource>/<name>                       — get/update/patch/delete
//	/api/v1/namespaces/<ns>/<resource>              — list in ns
//	/api/v1/namespaces/<ns>/<resource>/<name>       — single resource
//	/api/v1/namespaces/<ns>/<resource>/<name>/<sub> — subresource (exec/portforward/etc)
//	/apis/<group>/<v>/...                           — same shapes under groups
func parseK8sPath(method, p string) k8sMeta {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) < 2 {
		return k8sMeta{}
	}
	// Skip past `api/v1` or `apis/<group>/<v>`.
	switch parts[0] {
	case "api":
		if len(parts) < 2 {
			return k8sMeta{}
		}
		parts = parts[2:]
	case "apis":
		if len(parts) < 3 {
			return k8sMeta{}
		}
		parts = parts[3:]
	default:
		return k8sMeta{}
	}
	if len(parts) == 0 {
		return k8sMeta{}
	}
	var m k8sMeta
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
		// subresource — append: pods + exec → pods/exec
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
	return m
}

// matchSet runs each pattern in pats against got with glob matching;
// "!pattern" negates. Returns true when got matches at least one
// non-negated pattern AND no negated pattern.
func matchSet(pats []string, got string) bool {
	if len(pats) == 0 {
		return true
	}
	hasPos, anyPos := false, false
	for _, p := range pats {
		if strings.HasPrefix(p, "!") {
			if matchGlob(p[1:], got) {
				return false
			}
			continue
		}
		hasPos = true
		if matchGlob(p, got) {
			anyPos = true
		}
	}
	return !hasPos || anyPos
}

// check decides whether req (with optional already-read body) matches
// m. body may be nil — body_json / body_contains clauses fail-closed
// when no body was captured.
func (m *Match) check(req *http.Request, body []byte) bool {
	if m == nil {
		return true
	}
	if len(m.Method) > 0 {
		ok := false
		for _, x := range m.Method {
			if strings.EqualFold(x, req.Method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if m.Path != "" {
		ok, _ := path.Match(m.Path, req.URL.Path)
		if !ok {
			return false
		}
	}
	if len(m.Query) > 0 {
		q := req.URL.Query()
		for k, vs := range m.Query {
			got := q.Get(k)
			if got == "" {
				return false
			}
			ok := false
			for _, v := range vs {
				if matchGlob(v, got) {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		}
	}
	for k, v := range m.Headers {
		if !strings.EqualFold(req.Header.Get(k), v) {
			return false
		}
	}
	if len(m.BodyJSON) > 0 {
		if len(body) == 0 {
			return false
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(body, &obj); err != nil {
			return false
		}
		for k, want := range m.BodyJSON {
			raw, ok := obj[k]
			if !ok {
				return false
			}
			if want == "" {
				continue
			}
			if strings.TrimSpace(string(raw)) != want {
				return false
			}
		}
	}
	if m.BodyContains != "" {
		if len(body) == 0 || !strings.Contains(string(body), m.BodyContains) {
			return false
		}
	}
	// Kubernetes facets — only evaluate if any are set, since k8sMeta
	// parsing has cost and most rules don't need it.
	if len(m.Resource) > 0 || len(m.Verb) > 0 ||
		len(m.Namespace) > 0 || len(m.Name) > 0 || len(m.Params) > 0 {
		k := parseK8sPath(req.Method, req.URL.Path)
		if k.Resource == "" {
			return false // not a k8s API path
		}
		if !matchSet(m.Resource, k.Resource) {
			return false
		}
		if !matchSet(m.Verb, k.Verb) {
			return false
		}
		if !matchSet(m.Namespace, k.Namespace) {
			return false
		}
		if !matchSet(m.Name, k.Name) {
			return false
		}
		if len(m.Params) > 0 {
			q := req.URL.Query()
			for pk, want := range m.Params {
				if q.Get(pk) != want {
					return false
				}
			}
		}
	}
	// SQL facets are evaluated on the postgres path (postgres.go's
	// checkSQL). On the HTTP path (this method) any rule whose Match
	// is purely SQL-shaped doesn't apply — but a rule that ALSO
	// declares HTTP facets (e.g. host + sql_verb) gets here and we
	// just ignore the SQL bits. Postgres rule selection (selectPgRule)
	// only considers rules with at least one SQL facet.
	return true
}

func matchGlob(pat, s string) bool {
	if pat == s {
		return true
	}
	ok, _ := path.Match(pat, s)
	return ok
}

// selectHostRule returns the first matching rule for (host, peerIP)
// scoped to `profile`. Device-scoped rules (Device==peerIP) are checked
// before globals so per-device overrides win. Profile filter: empty
// Profile = applies to any profile.
func selectHostRule(rules []Rule, host, peerIP, profile string) *Rule {
	if r := scanHostRule(rules, host, peerIP, profile, true); r != nil {
		return r
	}
	return scanHostRule(rules, host, peerIP, profile, false)
}

func scanHostRule(rules []Rule, host, peerIP, profile string, deviceOnly bool) *Rule {
	for i := range rules {
		if rules[i].Profile != "" && rules[i].Profile != profile {
			continue
		}
		if deviceOnly {
			if rules[i].Device == "" || rules[i].Device != peerIP {
				continue
			}
		} else {
			if rules[i].Device != "" {
				continue
			}
		}
		if rules[i].matches(host) {
			return &rules[i]
		}
	}
	return nil
}

// selectRequestRule precedence (highest → lowest):
//  1. device-scoped + has Match (most specific override)
//  2. device-scoped + no Match (per-device catch-all)
//  3. global + has Match
//  4. global + no Match (catch-all / integration auto-rules)
func selectRequestRule(rules []Rule, host, peerIP, profile string, req *http.Request, body []byte) *Rule {
	for _, dev := range []bool{true, false} {
		for _, mustMatch := range []bool{true, false} {
			if r := scanReqRuleStrict(rules, host, peerIP, profile, req, body, dev, mustMatch); r != nil {
				return r
			}
		}
	}
	return nil
}

func scanReqRuleStrict(rules []Rule, host, peerIP, profile string, req *http.Request, body []byte, deviceOnly, requireMatch bool) *Rule {
	for i := range rules {
		if rules[i].Profile != "" && rules[i].Profile != profile {
			continue
		}
		if deviceOnly {
			if rules[i].Device == "" || rules[i].Device != peerIP {
				continue
			}
		} else {
			if rules[i].Device != "" {
				continue
			}
		}
		hasMatch := rules[i].Match != nil
		if requireMatch != hasMatch {
			continue
		}
		if !rules[i].matches(host) {
			continue
		}
		if !rules[i].Match.check(req, body) {
			continue
		}
		return &rules[i]
	}
	return nil
}

// rulesNeedBody reports whether any host-matching rule for the given
// (profile, peerIP) uses body_json — caller (mitm) should pre-read
// the request body before scanning rules.
func rulesNeedBody(rules []Rule, host, peerIP, profile string) bool {
	for i := range rules {
		if rules[i].Profile != "" && rules[i].Profile != profile {
			continue
		}
		if rules[i].Device != "" && rules[i].Device != peerIP {
			continue
		}
		if !rules[i].matches(host) {
			continue
		}
		if rules[i].Match != nil && len(rules[i].Match.BodyJSON) > 0 {
			return true
		}
	}
	return false
}
