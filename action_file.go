package main

// Action-fixture format for `clawpatrol test`. Top-level shape:
//
//	{ "match": { ... }, "action": { ... } }
//
// `match` is the runner's assertion (verdict + rule + endpoint).
// `action` is the recorded request: a host, optional credential /
// peer_ip, and exactly one facet-keyed block (`http`, `k8s`, `sql`).
// Each facet block carries ONLY that facet's CEL-visible fields —
// the same vocabulary rules read in `condition = "<facet>.<field>"`.
// Connection-level fields (host, credential, peer_ip) sit outside
// the facet block on `action` itself. See site/doc/clawpatrol-test.md.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	k8sfacet "github.com/denoland/clawpatrol/config/plugins/facets/k8s"
	sqlfacet "github.com/denoland/clawpatrol/config/plugins/facets/sql"
)

// Fixture is the on-disk shape. Field order matters for marshalling:
// `action` (what happened) reads first, `match` (what the runner
// asserts about it) reads second.
type Fixture struct {
	Action Action `json:"action"`
	Match  Match  `json:"match"`
}

// Match is what the rule engine produced (or what the runner
// should assert). Approve is terminal — see site/doc/clawpatrol-test.md.
type Match struct {
	Verdict  string `json:"verdict"` // allow | deny | approve | passthrough
	Rule     string `json:"rule,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Action is the recorded request. Exactly one of HTTP / K8s / SQL
// is set (validated by UnmarshalJSON).
type Action struct {
	Host       string      `json:"host,omitempty"`
	Credential string      `json:"credential,omitempty"`
	PeerIP     string      `json:"peer_ip,omitempty"`
	HTTP       *HTTPAction `json:"http,omitempty"`
	K8s        *K8sAction  `json:"k8s,omitempty"`
	SQL        *SQLAction  `json:"sql,omitempty"`
}

// HTTPAction carries the `http.*` CEL view: method / path / query /
// headers / body. body_b64 is the alternative byte-encoded form.
type HTTPAction struct {
	Method  string              `json:"method,omitempty"`
	Path    string              `json:"path,omitempty"`
	Query   map[string][]string `json:"query,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    string              `json:"body,omitempty"`
	BodyB64 string              `json:"body_b64,omitempty"`
}

// K8sAction carries the `k8s.*` CEL view.
type K8sAction struct {
	Verb      string            `json:"verb,omitempty"`
	Resource  string            `json:"resource,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
}

// SQLAction carries the `sql.*` CEL view. Only `statement` needs to
// be set in practice; the loader derives verb / tables / functions
// via the endpoint's runtime.SQLParser. Explicit verb / tables /
// functions / database are accepted and take precedence over
// derivation. Database is session-scoped on the wire (postgres
// StartupMessage, clickhouse Hello, clickhouse_https URL/header)
// and not derivable from the statement text alone.
type SQLAction struct {
	Statement string   `json:"statement,omitempty"`
	Verb      string   `json:"verb,omitempty"`
	Tables    []string `json:"tables,omitempty"`
	Functions []string `json:"functions,omitempty"`
	Database  string   `json:"database,omitempty"`
}

var validVerdicts = map[string]bool{
	"allow": true, "deny": true, "approve": true, "passthrough": true,
}

// UnmarshalJSON enforces: exactly one facet block under `action`,
// body xor body_b64, valid match.verdict, no unknown keys anywhere.
func (f *Fixture) UnmarshalJSON(data []byte) error {
	type rawFixture struct {
		Match  json.RawMessage `json:"match"`
		Action json.RawMessage `json:"action"`
	}
	var raw rawFixture
	if err := strictDecode(data, "fixture", &raw); err != nil {
		return err
	}
	if len(raw.Match) == 0 {
		return fmt.Errorf("fixture: match is required")
	}
	if err := strictDecode(raw.Match, "match", &f.Match); err != nil {
		return err
	}
	if !validVerdicts[f.Match.Verdict] {
		return fmt.Errorf("fixture: match.verdict %q must be one of allow|deny|approve|passthrough", f.Match.Verdict)
	}
	if len(raw.Action) == 0 {
		return fmt.Errorf("fixture: action is required")
	}
	return f.Action.unmarshal(raw.Action)
}

func (a *Action) unmarshal(data []byte) error {
	type rawAction struct {
		Host       string          `json:"host"`
		Credential string          `json:"credential"`
		PeerIP     string          `json:"peer_ip"`
		HTTP       json.RawMessage `json:"http,omitempty"`
		K8s        json.RawMessage `json:"k8s,omitempty"`
		SQL        json.RawMessage `json:"sql,omitempty"`
	}
	var raw rawAction
	if err := strictDecode(data, "action", &raw); err != nil {
		return err
	}
	a.Host = raw.Host
	a.Credential = raw.Credential
	a.PeerIP = raw.PeerIP
	count := 0
	if len(raw.HTTP) > 0 {
		count++
		if err := strictDecode(raw.HTTP, "http", &a.HTTP); err != nil {
			return err
		}
		if a.HTTP.Body != "" && a.HTTP.BodyB64 != "" {
			return fmt.Errorf("http: body and body_b64 are mutually exclusive")
		}
	}
	if len(raw.K8s) > 0 {
		count++
		if err := strictDecode(raw.K8s, "k8s", &a.K8s); err != nil {
			return err
		}
	}
	if len(raw.SQL) > 0 {
		count++
		if err := strictDecode(raw.SQL, "sql", &a.SQL); err != nil {
			return err
		}
		if a.SQL.Statement == "" {
			return fmt.Errorf("sql: statement is required")
		}
	}
	if count != 1 {
		return fmt.Errorf("action: exactly one of http/k8s/sql is required, found %d", count)
	}
	return nil
}

func strictDecode(raw json.RawMessage, block string, out any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%s: %w", block, err)
	}
	return nil
}

func decodedBody(body, b64 string) ([]byte, error) {
	switch {
	case body != "":
		return []byte(body), nil
	case b64 != "":
		return base64.StdEncoding.DecodeString(b64)
	}
	return nil, nil
}

// encodeBody picks `body` when bytes are printable UTF-8, else
// `body_b64`. Returns exactly one non-empty (or both empty when b
// is empty).
func encodeBody(b []byte) (body, b64 string) {
	if len(b) == 0 {
		return "", ""
	}
	if utf8.Valid(b) && !hasBinaryControlBytes(b) {
		return string(b), ""
	}
	return "", base64.StdEncoding.EncodeToString(b)
}

func hasBinaryControlBytes(b []byte) bool {
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			return true
		}
	}
	return false
}

// MatchFromCompiledRule produces the Match a fixture should carry
// given a dispatch outcome. Approve-chain rules collapse to
// `approve` (the human chain is never invoked under the runner).
func MatchFromCompiledRule(cr *config.CompiledRule, ep *config.CompiledEndpoint) Match {
	m := Match{}
	if ep != nil {
		m.Endpoint = ep.Name
	}
	if cr == nil {
		m.Verdict = "allow"
		return m
	}
	m.Rule = cr.Name
	m.Reason = cr.Outcome.Reason
	switch {
	case len(cr.Outcome.Approve) > 0:
		m.Verdict = "approve"
	case cr.Outcome.Verdict == "deny":
		m.Verdict = "deny"
	case cr.Outcome.Verdict == "allow":
		m.Verdict = "allow"
	default:
		panic(fmt.Sprintf("rule %q has unknown Outcome.Verdict %q", cr.Name, cr.Outcome.Verdict))
	}
	return m
}

// ResolveEndpoint picks the CompiledEndpoint to dispatch into.
// match.endpoint wins when set; otherwise action.host is scanned
// against policy.Endpoints for a unique match. Ambiguous hosts
// error with the candidate list.
func (f *Fixture) ResolveEndpoint(policy *config.CompiledPolicy) (*config.CompiledEndpoint, error) {
	if f.Match.Endpoint != "" {
		ep := policy.Endpoints[f.Match.Endpoint]
		if ep == nil {
			return nil, fmt.Errorf("endpoint %q not in compiled policy", f.Match.Endpoint)
		}
		return ep, nil
	}
	host := f.Action.Host
	if host == "" {
		return nil, fmt.Errorf("cannot resolve endpoint: no `action.host` and no `match.endpoint`")
	}
	var matches []*config.CompiledEndpoint
	for _, ep := range policy.Endpoints {
		if endpointClaimsHost(ep, host) {
			matches = append(matches, ep)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no endpoint claims host %q", host)
	case 1:
		return matches[0], nil
	}
	names := make([]string, 0, len(matches))
	for _, ep := range matches {
		names = append(names, ep.Name)
	}
	return nil, fmt.Errorf("host %q is claimed by multiple endpoints %v; set `match.endpoint` to disambiguate", host, names)
}

// endpointClaimsHost matches `host` and `host:port` forms either
// way (mirrors compile.go's HostIndex normalisation).
func endpointClaimsHost(ep *config.CompiledEndpoint, host string) bool {
	hostBare := stripPort(host)
	for _, h := range ep.Hosts {
		hBare := stripPort(h)
		if h == host || h == hostBare || hBare == host || hBare == hostBare {
			return true
		}
	}
	return false
}

func stripPort(s string) string {
	if !strings.Contains(s, ":") {
		return s
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		return s[:i]
	}
	return s
}

// ToMatchRequest builds the match.Request the rule engine sees.
// For SQL fixtures with only `statement` set, parseSQL is called
// to derive verb / tables / function plus the unparseable flag.
// Explicit fields on the fixture take precedence over derivation;
// the unparseable flag is propagated to match.Request.Unparseable
// only when no explicit verb/tables/functions override the parser
// (since an explicit override means the fixture author was telling
// us the facets, regardless of what the parser thought).
func (f *Fixture) ToMatchRequest(family string, parseSQL func(string) (any, bool)) (*match.Request, error) {
	a := &f.Action
	req := &match.Request{Family: family, Credential: a.Credential, PeerIP: a.PeerIP}
	switch {
	case a.HTTP != nil:
		req.Method = a.HTTP.Method
		req.Headers = http.Header(a.HTTP.Headers)
		b, err := decodedBody(a.HTTP.Body, a.HTTP.BodyB64)
		if err != nil {
			return nil, fmt.Errorf("http.body_b64: %w", err)
		}
		req.Body = b
		req.URL = &url.URL{
			Scheme:   "https",
			Host:     a.Host,
			Path:     a.HTTP.Path,
			RawQuery: url.Values(a.HTTP.Query).Encode(),
		}
	case a.K8s != nil:
		req.URL = &url.URL{Scheme: "https", Host: a.Host}
		req.Meta = &k8sfacet.Meta{
			Verb: a.K8s.Verb, Resource: a.K8s.Resource,
			Namespace: a.K8s.Namespace, Name: a.K8s.Name,
			Params: a.K8s.Params,
		}
	case a.SQL != nil:
		stmt := a.SQL.Statement
		if stmt == "" {
			break
		}
		if parseSQL == nil {
			return nil, fmt.Errorf("sql: endpoint runtime does not implement SQLParser")
		}
		// Parser is authoritative for verb / tables / functions —
		// they're derivable from the statement. If a fixture also
		// declares them, they must agree; otherwise the rule
		// evaluator would silently see a fiction. database isn't
		// in the statement (PG StartupMessage / CH session), so it
		// stays a fixture-provided override.
		//
		// When the parser couldn't extract a facet (unparseable
		// statement, or the parser produced no value for that
		// facet) a fixture override fills it in instead of
		// requiring agreement: the fixture is then asserting what
		// the parser failed to derive, which also clears the
		// unparseable flag for the rule evaluator.
		meta, unparseable := parseSQL(stmt)
		if m, ok := meta.(*sqlfacet.Meta); ok {
			if a.SQL.Verb != "" {
				if m.Verb == "" {
					m.Verb = a.SQL.Verb
					unparseable = false
				} else if !strings.EqualFold(a.SQL.Verb, m.Verb) {
					return nil, fmt.Errorf(
						"sql.verb mismatch: fixture=%q parser=%q (statement=%q)",
						a.SQL.Verb, m.Verb, stmt)
				}
			}
			if len(a.SQL.Tables) > 0 {
				if len(m.Tables) == 0 {
					m.Tables = a.SQL.Tables
					unparseable = false
				} else if !sameStringSet(a.SQL.Tables, m.Tables) {
					return nil, fmt.Errorf(
						"sql.tables mismatch: fixture=%v parser=%v (statement=%q)",
						a.SQL.Tables, m.Tables, stmt)
				}
			}
			if len(a.SQL.Functions) > 0 {
				if len(m.Functions) == 0 {
					m.Functions = a.SQL.Functions
					unparseable = false
				} else if !sameStringSet(a.SQL.Functions, m.Functions) {
					return nil, fmt.Errorf(
						"sql.functions mismatch: fixture=%v parser=%v (statement=%q)",
						a.SQL.Functions, m.Functions, stmt)
				}
			}
			if a.SQL.Database != "" {
				m.Database = a.SQL.Database
			}
		}
		req.Meta = meta
		req.Unparseable = unparseable
	}
	return req, nil
}

// sameStringSet treats two []string as equal-as-sets. Used to compare
// fixture-declared table/function lists against the parser's output:
// order is incidental, presence is what matters for rule matching.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a_ := append([]string(nil), a...)
	b_ := append([]string(nil), b...)
	sort.Strings(a_)
	sort.Strings(b_)
	for i := range a_ {
		if a_[i] != b_[i] {
			return false
		}
	}
	return true
}
