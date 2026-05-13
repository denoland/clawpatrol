package approvers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/runtime"
)

// templateVarRe matches {{var}} placeholders, capturing the var name.
var templateVarRe = regexp.MustCompile(`\{\{([^{}]+)\}\}`)

// expandMessage substitutes {{var}} placeholders in tmpl using fields
// from req. Supported vars:
//
//   - Common (no prefix): profile, host, endpoint, reason, body, method, path
//   - Facet-prefixed (mirror CEL namespace):
//     http.method, http.path
//     k8s.verb, k8s.resource, k8s.namespace, k8s.name
//     sql.verb, sql.tables, sql.functions, sql.statement
//   - JSON body access: body_json.<field> or body_json.<a>.<b>...
//
// Unknown vars are left as-is. Expansions are not recursed.
func expandMessage(tmpl string, req runtime.ApproveRequest) string {
	vars := buildTemplateVars(req)
	return templateVarRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		key := strings.TrimSpace(m[2 : len(m)-2])
		if v, ok := vars[key]; ok {
			return v
		}
		return m
	})
}

func buildTemplateVars(req runtime.ApproveRequest) map[string]string {
	vars := map[string]string{
		"profile":  req.Profile,
		"host":     req.Host,
		"endpoint": runtime.HITLEndpointLabel(req),
		"reason":   req.Reason,
		"body":     req.BodySample,
		"method":   req.Method,
		"path":     req.Path,
	}

	// Facet-specific fields under the facet's own namespace prefix.
	if req.Endpoint != nil && req.Request != nil {
		if f := facet.Lookup(req.Endpoint.Family); f != nil {
			prefix := f.Name() + "."
			for k, v := range f.Report(req.Request) {
				vars[prefix+k] = stringify(v)
				// Also expose without prefix when it doesn't collide.
				if _, exists := vars[k]; !exists {
					vars[k] = stringify(v)
				}
			}
		}
	}

	// JSON body fields under body_json.<path>.
	var bodyRaw []byte
	if req.Request != nil {
		bodyRaw = req.Request.Body
	}
	if len(bodyRaw) > 0 {
		var bodyMap map[string]any
		if json.Unmarshal(bodyRaw, &bodyMap) == nil {
			addJSONVars(vars, "body_json", bodyMap, 3)
		}
	}

	return vars
}

// addJSONVars flattens a JSON object into dot-path vars under prefix,
// up to maxDepth levels deep to avoid infinite recursion on cycles.
func addJSONVars(vars map[string]string, prefix string, m map[string]any, maxDepth int) {
	if maxDepth == 0 {
		return
	}
	for k, v := range m {
		key := prefix + "." + k
		switch val := v.(type) {
		case map[string]any:
			vars[key] = "" // intermediate node — empty string
			addJSONVars(vars, key, val, maxDepth-1)
		default:
			vars[key] = stringify(v)
		}
	}
}

func stringify(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []string:
		return strings.Join(val, ", ")
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}
