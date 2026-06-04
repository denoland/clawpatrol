package main

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type RuleGenOptions struct {
	Verdict string
	Scope   string
}

type GeneratedRule struct {
	RuleName              string   `json:"rule_name"`
	EndpointName          string   `json:"endpoint_name,omitempty"`
	HCL                   string   `json:"hcl"`
	ConfigRevision        string   `json:"config_revision,omitempty"`
	DashboardConfigWrites bool     `json:"dashboard_config_writes"`
	Warnings              []string `json:"warnings,omitempty"`
}

func GenerateRuleFromEvent(
	policy *config.CompiledPolicy,
	ev *Event,
	opts RuleGenOptions,
) (*GeneratedRule, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy not loaded")
	}
	if ev == nil {
		return nil, fmt.Errorf("event is required")
	}
	if ev.Endpoint == "" {
		return generateBlockHostRule(policy, ev, opts)
	}
	ep := policy.Endpoints[ev.Endpoint]
	if ep == nil {
		return nil, fmt.Errorf("endpoint %q no longer in policy", ev.Endpoint)
	}
	if opts.Verdict == "" {
		opts.Verdict = "deny"
	}
	if opts.Scope == "" {
		opts.Scope = "exact"
	}
	if opts.Verdict != "deny" {
		return nil, fmt.Errorf("unsupported verdict %q", opts.Verdict)
	}
	if opts.Scope != "exact" {
		return nil, fmt.Errorf("unsupported scope %q", opts.Scope)
	}

	condition, warnings, err := ruleConditionFromEvent(ep.Family, ev)
	if err != nil {
		return nil, err
	}
	name := generatedRuleName(ev, ep)
	hcl, err := generatedRuleHCL(name, endpointRef(ep), condition)
	if err != nil {
		return nil, err
	}
	return &GeneratedRule{
		RuleName:     name,
		EndpointName: ep.Name,
		HCL:          hcl,
		Warnings:     warnings,
	}, nil
}

func generateBlockHostRule(policy *config.CompiledPolicy, ev *Event, opts RuleGenOptions) (*GeneratedRule, error) {
	if opts.Verdict == "" {
		opts.Verdict = "deny"
	}
	if opts.Scope == "" {
		opts.Scope = "exact"
	}
	if opts.Verdict != "deny" {
		return nil, fmt.Errorf("unsupported verdict %q", opts.Verdict)
	}
	if opts.Scope != "exact" {
		return nil, fmt.Errorf("unsupported scope %q", opts.Scope)
	}
	host := canonicalObservedHost(ev.Host)
	if host == "" {
		return nil, fmt.Errorf("action has no endpoint or host")
	}
	endpointName := generatedEndpointName(policy, host)
	credName := generatedPassthroughCredName(policy, endpointName)
	ruleName := generatedHostBlockRuleName(ev, endpointName, host)
	profiles := generatedProfileNames(policy)
	hcl, err := generatedEndpointBlockRuleHCL(endpointName, credName, host, profiles, ruleName)
	if err != nil {
		return nil, err
	}
	return &GeneratedRule{
		RuleName:     ruleName,
		EndpointName: endpointName,
		HCL:          hcl,
		Warnings: []string{
			"This action did not match a configured endpoint. Generated HCL creates a new HTTPS endpoint for the observed host, claims it from existing profiles via a passthrough credential, and adds a catch-all deny rule.",
		},
	}, nil
}

func ruleConditionFromEvent(family string, ev *Event) (string, []string, error) {
	switch family {
	case "http":
		return httpRuleCondition(ev)
	case "sql":
		return sqlRuleCondition(ev)
	case "k8s":
		return k8sRuleCondition(ev)
	default:
		return "", nil, fmt.Errorf("endpoint family %q is not supported for rule generation", family)
	}
}

func httpRuleCondition(ev *Event) (string, []string, error) {
	method := strings.ToUpper(strings.TrimSpace(ev.Method))
	path, _ := splitPathQuery(ev.Path)
	path = strings.TrimSpace(path)
	parts := []string{}
	if method != "" {
		parts = append(parts, "http.method == "+celString(method))
	}
	warnings := []string{}
	if path != "" {
		parts = append(parts, "http.path == "+celString(path))
	} else {
		warnings = append(warnings, "Generated rule matches only the HTTP method because no request path was recorded.")
	}
	if len(parts) == 0 {
		return "", warnings, fmt.Errorf("http action has no method or path")
	}
	return strings.Join(parts, " && "), warnings, nil
}

func sqlRuleCondition(ev *Event) (string, []string, error) {
	verb, _ := ev.Facets["verb"].(string)
	verb = strings.ToLower(strings.TrimSpace(verb))
	tables := stringSliceFromFacet(ev.Facets["tables"])
	sort.Strings(tables)
	if verb != "" {
		parts := []string{"sql.verb == " + celString(verb)}
		if len(tables) == 1 {
			parts = append(parts, celString(tables[0])+" in sql.tables")
		} else if len(tables) > 1 {
			tableParts := make([]string, 0, len(tables))
			for _, table := range tables {
				tableParts = append(tableParts, celString(table)+" in sql.tables")
			}
			parts = append(parts, "("+strings.Join(tableParts, " || ")+")")
		}
		return strings.Join(parts, " && "), nil, nil
	}
	stmt, _ := ev.Facets["statement"].(string)
	if stmt == "" {
		stmt = ev.ReqBody
	}
	if strings.TrimSpace(stmt) == "" {
		return "", nil, fmt.Errorf("sql action has no structured facets or statement")
	}
	return "sql.statement == " + celString(stmt), []string{
		"Generated rule matches the full SQL statement because no structured SQL facets were available. Consider broadening it manually.",
	}, nil
}

func k8sRuleCondition(ev *Event) (string, []string, error) {
	fields := []struct {
		Name string
		CEL  string
	}{
		{"verb", "k8s.verb"},
		{"resource", "k8s.resource"},
		{"namespace", "k8s.namespace"},
		{"name", "k8s.name"},
	}
	parts := []string{}
	for _, field := range fields {
		v, _ := ev.Facets[field.Name].(string)
		if v == "" {
			continue
		}
		parts = append(parts, field.CEL+" == "+celString(v))
	}
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("kubernetes action has no structured facets")
	}
	return strings.Join(parts, " && "), nil, nil
}

func generatedRuleHCL(name, endpoint, condition string) (string, error) {
	f := hclwrite.NewEmptyFile()
	b := f.Body().AppendNewBlock("rule", []string{name}).Body()
	b.SetAttributeRaw("endpoint", config.TraversalTokens(endpoint))
	b.SetAttributeValue("priority", cty.NumberIntVal(100))
	if condition != "" {
		setCELCondition(b, condition)
	}
	b.SetAttributeValue("verdict", cty.StringVal("deny"))
	b.SetAttributeValue("reason", cty.StringVal("Blocked from dashboard: generated from observed action"))
	return string(f.Bytes()), nil
}

// setCELCondition writes `condition = ...` either as a plain quoted
// string for single-clause expressions or as a `<<-CEL ... CEL`
// heredoc when the expression has multiple `&&`-joined clauses,
// matching the convention in examples/*.hcl. Splitting on ` && `
// keeps the marker line-anchored so future readers diff each clause
// independently.
func setCELCondition(b *hclwrite.Body, condition string) {
	parts := strings.Split(condition, " && ")
	if len(parts) < 2 {
		b.SetAttributeValue("condition", cty.StringVal(condition))
		return
	}
	var body strings.Builder
	for i, p := range parts {
		body.WriteString("    ")
		if i > 0 {
			body.WriteString("&& ")
		}
		body.WriteString(p)
		body.WriteString("\n")
	}
	b.SetAttributeRaw("condition", hclwrite.Tokens{
		{Type: hclsyntax.TokenOHeredoc, Bytes: []byte("<<-CEL\n")},
		{Type: hclsyntax.TokenStringLit, Bytes: []byte(body.String())},
		{Type: hclsyntax.TokenCHeredoc, Bytes: []byte("  CEL")},
	})
}

func generatedEndpointBlockRuleHCL(endpointName, credName, host string, profiles []string, ruleName string) (string, error) {
	f := hclwrite.NewEmptyFile()
	endpointRef := "https." + endpointName
	credRef := "passthrough." + credName

	eb := f.Body().AppendNewBlock("endpoint", []string{"https", endpointName}).Body()
	eb.SetAttributeValue("hosts", cty.ListVal([]cty.Value{cty.StringVal(host)}))

	f.Body().AppendNewline()
	cb := f.Body().AppendNewBlock("credential", []string{"passthrough", credName}).Body()
	cb.SetAttributeRaw("endpoint", config.TraversalTokens(endpointRef))

	f.Body().AppendNewline()
	rb := f.Body().AppendNewBlock("rule", []string{ruleName}).Body()
	rb.SetAttributeRaw("endpoint", config.TraversalTokens(endpointRef))
	rb.SetAttributeValue("priority", cty.NumberIntVal(100))
	rb.SetAttributeValue("verdict", cty.StringVal("deny"))
	rb.SetAttributeValue("reason", cty.StringVal("Blocked from dashboard: generated from observed passthrough host"))

	for _, profile := range profiles {
		f.Body().AppendNewline()
		pb := f.Body().AppendNewBlock("profile", []string{profile}).Body()
		config.SetIdentList(pb, "credentials", []string{credRef})
	}
	return string(f.Bytes()), nil
}

var generatedRuleNameChars = regexp.MustCompile(`[^A-Za-z0-9_]+`)

func generatedRuleName(ev *Event, ep *config.CompiledEndpoint) string {
	base := "block_" + safeRuleNamePart(ep.Name) + "_" + safeRuleNamePart(ep.Family)
	sumInput := ev.ID
	if sumInput == "" {
		sumInput = ev.Endpoint + "\x00" + ev.Family + "\x00" + ev.Method + "\x00" + ev.Path
	}
	sum := sha256.Sum256([]byte(sumInput))
	return fmt.Sprintf("%s_%x", base, sum[:3])
}

func generatedHostBlockRuleName(ev *Event, endpointName, host string) string {
	base := "block_" + safeRuleNamePart(endpointName)
	sumInput := ev.ID
	if sumInput == "" {
		sumInput = host
	}
	sum := sha256.Sum256([]byte(sumInput))
	return fmt.Sprintf("%s_%x", base, sum[:3])
}

func generatedProfileNames(policy *config.CompiledPolicy) []string {
	if policy == nil || len(policy.Profiles) == 0 {
		return nil
	}
	names := make([]string, 0, len(policy.Profiles))
	for name := range policy.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func generatedPassthroughCredName(policy *config.CompiledPolicy, endpointName string) string {
	base := endpointName + "_passthrough"
	if policy == nil || policy.Credentials[base] == nil {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		if policy.Credentials[candidate] == nil {
			return candidate
		}
	}
}

func generatedEndpointName(policy *config.CompiledPolicy, host string) string {
	base := safeRuleNamePart(strings.ToLower(host))
	if base == "action" {
		base = "host"
	}
	name := base
	if policy == nil || policy.Endpoints[name] == nil {
		return name
	}
	sum := sha256.Sum256([]byte(host))
	name = fmt.Sprintf("%s_%x", base, sum[:3])
	if policy.Endpoints[name] == nil {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%x_%d", base, sum[:3], i)
		if policy.Endpoints[candidate] == nil {
			return candidate
		}
	}
}

func canonicalObservedHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end >= 0 {
			return strings.Trim(host[:end+1], "[]")
		}
	}
	if strings.Count(host, ":") == 1 {
		if i := strings.LastIndexByte(host, ':'); i > 0 {
			return host[:i]
		}
	}
	return host
}

func safeRuleNamePart(s string) string {
	s = generatedRuleNameChars.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "action"
	}
	return s
}

// celString quotes s as a CEL string literal. CEL accepts both ' and "
// quoting; we prefer single quotes so the surrounding HCL string
// (double-quoted) doesn't need backslash-escaped inner quotes. Values
// containing a single quote or backslash fall back to strconv.Quote,
// which produces a valid (if escape-heavy) CEL double-quoted string.
func celString(s string) string {
	if !strings.ContainsAny(s, "'\\") {
		return "'" + s + "'"
	}
	return strconv.Quote(s)
}
