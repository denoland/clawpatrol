// Package render builds the auto-generated HCL config reference from
// the live plugin registry plus Go-source comments. The output is a
// Markdown document picked up by site/build-docs.ts.
//
// Generate() is the only entry point — it returns the rendered
// document so both the CLI generator and the drift test can consume
// the same value.
package render

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"

	// Side-effect import: every plugin's init() calls config.Register
	// so AllPlugins(kind) returns the full set during generation.
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

// Generate renders the full reference. Returns the document text;
// the caller writes it (or diffs it).
func Generate() (string, error) {
	docs, err := loadGoDocs()
	if err != nil {
		return "", fmt.Errorf("load go docs: %w", err)
	}
	r := &renderer{docs: docs}
	return r.run()
}

type renderer struct {
	docs *goDocs
	out  strings.Builder
}

func (r *renderer) run() (string, error) {
	r.writeHeader()
	r.writeOperational()
	r.writeFixedKind("defaults", "config", "Defaults", "")
	r.writeFixedKind("policy", "config", "PolicyText", `policy "<name>"`)
	r.writeProfile()

	for _, kind := range []config.Kind{
		config.KindApprover,
		config.KindCredential,
		config.KindEndpoint,
		config.KindRule,
	} {
		r.writeKind(kind)
	}
	return r.out.String(), nil
}

func (r *renderer) writeHeader() {
	r.out.WriteString(`# HCL config reference

> **This page is auto-generated** from the plugin registry under
> ` + "`config/plugins/`" + ` and the operational structs in ` + "`config/`" + `.
> Do not hand-edit. Re-run ` + "`go run ./tools/docgen`" + ` after changing any
> ` + "`hcl:\"...\"`" + ` tag, plugin registration, or struct field comment.

A clawpatrol gateway config mixes **operational** fields (top-level
plumbing) with **policy** blocks. Operational fields decode statically
into ` + "`config.Gateway`" + `; policy blocks dispatch to plugins by their
first label.

For prose context (references, namespaces, design rationale) see
[` + "`config/README.md`" + `](https://github.com/denoland/clawpatrol/blob/main/config/README.md);
the page you're reading is the field-by-field reference.

## How to read this page

Each block section lists the attributes the loader accepts, with:

- **Type** — Go type after HCL decode. ` + "`string`" + `, ` + "`bool`" + `, ` + "`int`" + ` map to
  the obvious HCL kinds; ` + "`[]string`" + ` is an HCL list of strings;
  ` + "`object`" + ` denotes a nested block / object whose shape is
  described inline.
- **Required** — ` + "`yes`" + ` if the loader rejects the block when the
  attribute is missing.
- **Reference** — when set, the value is a bare-name reference to
  another block of the named kind (e.g. ` + "`credential = github-pat`" + `).

Plugin-dispatched kinds (` + "`approver`, `credential`, `endpoint`, `rule`" + `)
list one subsection per registered type.

`)
}

// ── operational top-level + tailscale ───────────────────────────────

func (r *renderer) writeOperational() {
	r.out.WriteString("## Top-level operational fields\n\n")
	if doc := r.docs.typeDoc("config", "Gateway"); doc != "" {
		r.out.WriteString(doc)
		r.out.WriteString("\n\n")
	}
	r.writeStructTable("config", "Gateway", reflect.TypeOf(config.Gateway{}))

	r.out.WriteString("### `gateway {}` block\n\n")
	if doc := r.docs.typeDoc("config", "Tailscale"); doc != "" {
		r.out.WriteString(doc)
		r.out.WriteString("\n\n")
	}
	r.writeStructTable("config", "Tailscale", reflect.TypeOf(config.Tailscale{}))
}

// writeFixedKind documents a one-label kind with a fixed, non-plugin
// schema (defaults, policy). The body struct lives in package
// `config`.
func (r *renderer) writeFixedKind(kind, pkg, typeName, headerSuffix string) {
	header := fmt.Sprintf("`%s {}`", kind)
	if headerSuffix != "" {
		header = fmt.Sprintf("`%s { ... }`", headerSuffix)
	}
	fmt.Fprintf(&r.out, "## %s\n\n", header)
	if doc := r.docs.typeDoc(pkg, typeName); doc != "" {
		r.out.WriteString(doc)
		r.out.WriteString("\n\n")
	}
	rt := reflectTypeFor(pkg, typeName)
	r.writeStructTable(pkg, typeName, rt)
	r.writeExample(kind, "", rt, false)
}

func reflectTypeFor(pkg, name string) reflect.Type {
	switch pkg + "." + name {
	case "config.Gateway":
		return reflect.TypeOf(config.Gateway{})
	case "config.Tailscale":
		return reflect.TypeOf(config.Tailscale{})
	case "config.Defaults":
		return reflect.TypeOf(config.Defaults{})
	case "config.PolicyText":
		return reflect.TypeOf(config.PolicyText{})
	}
	return nil
}

// writeProfile documents the `profile "<name>" {}` block. The body
// struct is unexported (config.profileBody), so we inline its single
// field rather than going through reflection.
func (r *renderer) writeProfile() {
	r.out.WriteString("## `profile \"<name>\" { ... }`\n\n")
	r.out.WriteString("Names a set of endpoints. Profiles bind to dashboard owners; an owner's profile determines which endpoints their gateway requests can reach. Rules ride along automatically because they're attached to endpoints.\n\n")
	r.out.WriteString("| Attribute | Type | Required | Reference | Description |\n")
	r.out.WriteString("|-----------|------|----------|-----------|-------------|\n")
	r.out.WriteString("| `endpoints` | `[]string` | yes | endpoint | Bare-name endpoint references included in this profile. |\n\n")
	r.out.WriteString("```hcl\nprofile \"default\" {\n  endpoints = [github, postgres-prod]\n}\n```\n\n")
}

// ── plugin-dispatched kinds ─────────────────────────────────────────

func (r *renderer) writeKind(kind config.Kind) {
	plugins := config.AllPlugins(kind)
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].Type < plugins[j].Type })

	syntax := kindSyntax(kind)
	fmt.Fprintf(&r.out, "## `%s` blocks\n\n", kind)
	fmt.Fprintf(&r.out, "Block syntax: `%s`\n\n", syntax)
	fmt.Fprintf(&r.out, "Registered types: ")
	for i, p := range plugins {
		if i > 0 {
			r.out.WriteString(", ")
		}
		fmt.Fprintf(&r.out, "[`%s`](#%s-%s)", p.Type, kind, anchor(p.Type))
	}
	r.out.WriteString(".\n\n")

	for _, p := range plugins {
		r.writePlugin(kind, p)
	}
}

func (r *renderer) writePlugin(kind config.Kind, p *config.Plugin) {
	fmt.Fprintf(&r.out, "### `%s \"%s\"`\n\n", kind, p.Type)

	rt := pluginStructType(p)
	pkgName := pkgNameOf(rt)
	typeName := rt.Name()

	if doc := r.docs.typeDoc(pkgName, typeName); doc != "" {
		r.out.WriteString(doc)
		r.out.WriteString("\n\n")
	}

	if kind == config.KindEndpoint && p.Family != "" {
		fmt.Fprintf(&r.out, "Family: `%s`.\n\n", p.Family)
	}
	if kind == config.KindRule && len(p.Families) > 0 {
		fmt.Fprintf(&r.out, "Targets endpoints of family: %s.\n\n", joinTicked(p.Families))
	}

	r.writeStructTable(pkgName, typeName, rt)

	// Reference list: cross-reference fields driven by RefSpec.
	if len(p.Refs) > 0 {
		r.out.WriteString("**References:** ")
		for i, ref := range p.Refs {
			if i > 0 {
				r.out.WriteString("; ")
			}
			fmt.Fprintf(&r.out, "`%s` → %s", ref.Path, ref.Kind)
			if ref.Optional {
				r.out.WriteString(" (optional)")
			}
		}
		r.out.WriteString(".\n\n")
	}

	// Rule plugins: enumerate per-family valid match keys.
	if kind == config.KindRule {
		r.writeRuleMatchKeys(p)
	}

	r.writeExample(string(kind), p.Type, rt, true)
}

func (r *renderer) writeRuleMatchKeys(p *config.Plugin) {
	if len(p.Families) == 0 {
		return
	}
	r.out.WriteString("**`match` keys** (single string or list of strings each):\n\n")
	for _, fam := range p.Families {
		keys := match.KnownKeys(fam)
		if len(keys) == 0 {
			continue
		}
		fmt.Fprintf(&r.out, "- family `%s`: %s\n", fam, joinTicked(keys))
	}
	r.out.WriteString("\n")
}

// pluginStructType invokes plugin.New() and returns the underlying
// struct reflect.Type. New() returns a pointer to the body struct.
func pluginStructType(p *config.Plugin) reflect.Type {
	v := reflect.ValueOf(p.New())
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	return v.Type()
}

func pkgNameOf(rt reflect.Type) string {
	pp := rt.PkgPath()
	if i := strings.LastIndex(pp, "/"); i >= 0 {
		return pp[i+1:]
	}
	return pp
}

// ── struct → markdown table ─────────────────────────────────────────

type fieldRow struct {
	Name        string
	Type        string
	Required    bool
	Reference   string
	Doc         string
	Block       bool
	Skip        bool
	IsLabel     bool
	GoFieldName string
}

func (r *renderer) writeStructTable(pkgName, typeName string, rt reflect.Type) {
	rows := r.collectFields(pkgName, typeName, rt)
	if len(rows) == 0 {
		r.out.WriteString("_No configurable attributes._\n\n")
		return
	}

	r.out.WriteString("| Attribute | Type | Required | Reference | Description |\n")
	r.out.WriteString("|-----------|------|----------|-----------|-------------|\n")
	for _, f := range rows {
		req := "no"
		if f.Required {
			req = "yes"
		}
		ref := f.Reference
		if ref == "" {
			ref = "—"
		}
		fmt.Fprintf(&r.out, "| `%s` | `%s` | %s | %s | %s |\n",
			f.Name, f.Type, req, ref, mdEscape(oneLine(f.Doc)))
	}
	r.out.WriteString("\n")

	// Inline nested struct blocks. Skip Gateway's `gateway {}` field
	// (Tailscale) — it gets a dedicated top-level section.
	if typeName == "Gateway" {
		return
	}
	for _, f := range rows {
		if !f.Block {
			continue
		}
		blockType := blockElemType(rt, f.GoFieldName)
		if blockType == nil {
			continue
		}
		bp := pkgNameOf(blockType)
		bn := blockType.Name()
		fmt.Fprintf(&r.out, "**Nested block `%s {}`:**\n\n", f.Name)
		if doc := r.docs.typeDoc(bp, bn); doc != "" {
			r.out.WriteString(doc)
			r.out.WriteString("\n\n")
		}
		r.writeStructTable(bp, bn, blockType)
	}
}

// collectFields walks rt and produces a row per HCL-tagged attribute.
// Skips fields with hcl:"-", json:"-", or no hcl tag at all.
func (r *renderer) collectFields(pkgName, typeName string, rt reflect.Type) []fieldRow {
	var rows []fieldRow

	// refs by Go path → kind, for annotating reference columns.
	refByPath := r.fieldRefs(pkgName, typeName)

	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		hclTag, ok := f.Tag.Lookup("hcl")
		if !ok {
			continue
		}
		jsonTag := f.Tag.Get("json")
		// Fields populated post-decode (CredentialEntry slice on
		// HTTPSEndpoint) carry json:"-" or no hcl tag — skip.
		if hclTag == "" || hclTag == "-" {
			continue
		}
		parts := strings.Split(hclTag, ",")
		name := parts[0]
		opts := parts[1:]
		if hasOpt(opts, "remain") || hasOpt(opts, "label") {
			continue
		}

		typeStr := formatGoType(f.Type)
		if hasOpt(opts, "block") {
			typeStr = "block"
		}
		row := fieldRow{
			Name:        name,
			Type:        typeStr,
			Required:    !hasOpt(opts, "optional"),
			Block:       hasOpt(opts, "block"),
			GoFieldName: f.Name,
			Doc:         r.docs.fieldDoc(pkgName, typeName, f.Name),
		}
		if jsonTag == "-" && row.Block {
			// jsonTag "-" + block is unusual; keep but don't skip.
		}
		// Reference annotation: a RefSpec path either exactly equals
		// the Go field name (singular) or starts with "<field>[*]"
		// (slice of refs).
		if kindRef, ok := refByPath[f.Name]; ok {
			row.Reference = kindRef
		} else if kindRef, ok := refByPath[f.Name+"[*]"]; ok {
			row.Reference = kindRef
		}
		rows = append(rows, row)
	}
	return rows
}

// fieldRefs returns Go-field-path → "kind" annotations sourced from
// the Plugin.Refs RefSpec list. Only meaningful when typeName is a
// plugin body struct.
func (r *renderer) fieldRefs(pkgName, typeName string) map[string]string {
	out := map[string]string{}
	for _, kind := range []config.Kind{
		config.KindApprover, config.KindCredential, config.KindEndpoint, config.KindRule,
	} {
		for _, p := range config.AllPlugins(kind) {
			rt := pluginStructType(p)
			if pkgNameOf(rt) != pkgName || rt.Name() != typeName {
				continue
			}
			for _, ref := range p.Refs {
				out[ref.Path] = string(ref.Kind)
			}
		}
	}
	return out
}

// blockElemType returns the underlying struct type of a `hcl:"...,block"`
// field, peeling pointer / slice indirections. Returns nil if not a
// recognizable struct.
func blockElemType(rt reflect.Type, fieldName string) reflect.Type {
	f, ok := rt.FieldByName(fieldName)
	if !ok {
		return nil
	}
	t := f.Type
	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	if t == reflect.TypeOf(cty.Value{}) {
		return nil
	}
	return t
}

// ── examples ────────────────────────────────────────────────────────

// writeExample emits a tiny synthetic HCL example. For plugin-
// dispatched kinds (typed=true) the block carries `<kind> "<type>"
// "example"`; otherwise just `<kind> { ... }` (defaults, policy).
func (r *renderer) writeExample(kind, typ string, rt reflect.Type, typed bool) {
	if rt == nil {
		return
	}
	var head string
	switch {
	case typ != "" && typed:
		head = fmt.Sprintf(`%s "%s" "example"`, kind, typ)
	case kind == "policy":
		head = `policy "example"`
	default:
		head = kind
	}

	body := exampleBody(rt)
	if strings.TrimSpace(body) == "" {
		fmt.Fprintf(&r.out, "```hcl\n%s {}\n```\n\n", head)
		return
	}
	fmt.Fprintf(&r.out, "```hcl\n%s {\n%s}\n```\n\n", head, body)
}

func exampleBody(rt reflect.Type) string {
	var sb strings.Builder
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		hclTag, ok := f.Tag.Lookup("hcl")
		if !ok || hclTag == "" || hclTag == "-" {
			continue
		}
		parts := strings.Split(hclTag, ",")
		name := parts[0]
		opts := parts[1:]
		if hasOpt(opts, "label") || hasOpt(opts, "remain") {
			continue
		}
		// Skip optional fields in the synthetic example to keep
		// it terse. Required fields show the canonical value.
		if hasOpt(opts, "optional") {
			continue
		}
		val := exampleValue(f.Type, name)
		if val == "" {
			continue
		}
		fmt.Fprintf(&sb, "  %s = %s\n", name, val)
	}
	return sb.String()
}

func exampleValue(t reflect.Type, fieldName string) string {
	switch t.Kind() {
	case reflect.String:
		switch fieldName {
		case "model":
			return `"claude-haiku-4-5-20251001"`
		case "channel":
			return `"#approvals"`
		case "host":
			return `"db.internal:5432"`
		case "database":
			return `"appdb"`
		case "server":
			return `"https://kube.internal:6443"`
		case "header":
			return `"X-API-Key"`
		case "cookie_name":
			return `"session"`
		case "credential":
			return "example-credential"
		case "endpoint":
			return "example-endpoint"
		case "policy":
			return "example-policy"
		case "verdict":
			return `"deny"`
		case "reason":
			return `"example reason"`
		case "text":
			return "<<-EOT\n    Example policy text.\n  EOT"
		}
		return `"example"`
	case reflect.Bool:
		return "true"
	case reflect.Int, reflect.Int32, reflect.Int64:
		return "30"
	case reflect.Slice:
		if t.Elem().Kind() == reflect.String {
			switch fieldName {
			case "hosts":
				return `["api.example.com"]`
			case "endpoints":
				return "[example-endpoint]"
			case "tags":
				return `["tag:gateway"]`
			}
			return `["example"]`
		}
	}
	return ""
}

// ── helpers ─────────────────────────────────────────────────────────

func hasOpt(opts []string, want string) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}

// formatGoType renders a Go type for the docs table. cty.Value is
// rendered as `object` (its shape is described in prose). Pointers,
// slices, and maps recurse.
func formatGoType(t reflect.Type) string {
	if t == reflect.TypeOf(cty.Value{}) {
		return "object"
	}
	switch t.Kind() {
	case reflect.Ptr:
		return formatGoType(t.Elem())
	case reflect.Slice:
		return "[]" + formatGoType(t.Elem())
	case reflect.Map:
		return "map[" + formatGoType(t.Key()) + "]" + formatGoType(t.Elem())
	case reflect.Struct:
		if t.Name() == "" {
			return "object"
		}
		return t.Name()
	}
	return t.String()
}

func anchor(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "_", "")
	return s
}

func joinTicked(xs []string) string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = "`" + x + "`"
	}
	return strings.Join(out, ", ")
}

func kindSyntax(k config.Kind) string {
	if k.LabelCount() == 2 {
		return string(k) + ` "<type>" "<name>" { ... }`
	}
	return string(k) + ` "<name>" { ... }`
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Collapse newlines (typical Go comment wrap) into single spaces.
	s = strings.ReplaceAll(s, "\n", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return s
}

func mdEscape(s string) string {
	// Pipe characters break Markdown tables; escape them. Backticks
	// in field comments are kept since they render as code in cells.
	return strings.ReplaceAll(s, "|", `\|`)
}
