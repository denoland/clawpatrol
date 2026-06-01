package main

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type RuleGenOptions struct {
	Verdict string
	Scope   string
}

type GeneratedRule struct {
	RuleName              string   `json:"rule_name"`
	HCL                   string   `json:"hcl"`
	Patch                 string   `json:"patch,omitempty"`
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
		return nil, fmt.Errorf("action has no endpoint")
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
		RuleName: name,
		HCL:      hcl,
		Patch:    generatedAppendPatch("gateway.hcl", hcl),
		Warnings: warnings,
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
	b.SetAttributeValue("condition", cty.StringVal(condition))
	b.SetAttributeValue("verdict", cty.StringVal("deny"))
	b.SetAttributeValue("reason", cty.StringVal("Blocked from dashboard: generated from observed action"))
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

func safeRuleNamePart(s string) string {
	s = generatedRuleNameChars.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "action"
	}
	return s
}

func celString(s string) string {
	return strconv.Quote(s)
}

func generatedAppendPatch(path, hcl string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "diff --git a/%s b/%s\n", path, path)
	fmt.Fprintf(&b, "--- a/%s\n", path)
	fmt.Fprintf(&b, "+++ b/%s\n", path)
	b.WriteString("@@ -0,0 +1 @@\n")
	for _, line := range strings.Split(strings.TrimRight(hcl, "\n"), "\n") {
		b.WriteString("+")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func generatedAppendPatchFromBytes(path string, current []byte, hcl string) string {
	added := strings.Split(strings.TrimRight(string(appendConfigSnippet(current, hcl)), "\n"), "\n")
	if len(current) > 0 {
		prefix := strings.Split(strings.TrimRight(string(current), "\n"), "\n")
		if len(prefix) <= len(added) {
			added = added[len(prefix):]
		}
	}
	oldLine := 0
	if len(current) > 0 {
		oldLine = strings.Count(string(current), "\n")
		if current[len(current)-1] != '\n' {
			oldLine++
		}
	}
	newStart := oldLine + 1
	if oldLine == 0 {
		newStart = 1
	}
	var b strings.Builder
	fmt.Fprintf(&b, "diff --git a/%s b/%s\n", path, path)
	fmt.Fprintf(&b, "--- a/%s\n", path)
	fmt.Fprintf(&b, "+++ b/%s\n", path)
	fmt.Fprintf(&b, "@@ -%d,0 +%d,%d @@\n", oldLine, newStart, len(added))
	for _, line := range added {
		b.WriteString("+")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
