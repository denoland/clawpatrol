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
	r.writeFixedKind("policy", "config", "PolicyText", `policy "<name>"`)
	r.writeProfile()

	for _, kind := range []config.Kind{
		config.KindApprover,
		config.KindCredential,
		config.KindEndpoint,
		config.KindRule,
		config.KindTunnel,
	} {
		r.writeKind(kind)
	}
	return r.out.String(), nil
}

func (r *renderer) writeHeader() {
	r.out.WriteString(`# HCL config reference

A clawpatrol gateway config mixes **operational** fields (top-level
plumbing) with **policy** blocks. Operational fields are top-level
attributes; policy blocks (` + "`approver`, `credential`, `tunnel`, `endpoint`, `rule`" + `)
dispatch to a plugin chosen by the block's first label.

## How to read this page

Each block section lists the attributes the loader accepts, with:

- **Type** — the HCL value type. ` + "`string`" + `, ` + "`bool`" + `, ` + "`int`" + ` are scalar
  literals; ` + "`[]string`" + ` is a list of strings; ` + "`ref(<kind>)`" + ` is a
  bare-name reference to another block of that kind (e.g.
  ` + "`credential = github-pat`" + `); ` + "`[]ref(<kind>)`" + ` is a list of such
  references; nested blocks have their shape described inline.
- **Required** — ` + "`yes`" + ` if the loader rejects the block when the
  attribute is missing.

Plugin-dispatched kinds (` + "`approver`, `credential`, `tunnel`, `endpoint`, `rule`" + `)
list one subsection per registered type.

`)
}

// ── operational top-level + tailscale ───────────────────────────────

// stripIdentPrefix drops a leading "<ident> " (and the common Go-doc
// "<ident> is "/"<ident> are " linking verb) from a doc comment, then
// re-capitalises the next word so the sentence still reads cleanly.
// Go convention starts every godoc with the identifier name; in HCL
// reference output that name is rarely meaningful (the user knows the
// HCL attribute, not the Go field), so we elide it.
func stripIdentPrefix(doc, ident string) string {
	if doc == "" || ident == "" {
		return doc
	}
	prefix := ident + " "
	if !strings.HasPrefix(doc, prefix) {
		return doc
	}
	rest := doc[len(prefix):]
	// Drop the common "<Ident> is/are <article>" linker so the
	// remaining sentence reads as a noun phrase ("The shared body
	// shape...") rather than a fragment ("Is the shared body shape...").
	linkers := []struct{ from, to string }{
		{"is the ", "The "},
		{"is a ", "A "},
		{"is an ", "An "},
		{"are the ", "The "},
		{"are ", ""},
	}
	for _, l := range linkers {
		if strings.HasPrefix(rest, l.from) {
			return l.to + rest[len(l.from):]
		}
	}
	if rest == "" {
		return rest
	}
	first := rest[0]
	if first >= 'a' && first <= 'z' {
		rest = strings.ToUpper(rest[:1]) + rest[1:]
	}
	// Drop the stub "Is part of the clawpatrol plugin API." sentence
	// that's auto-generated as a placeholder doc-comment on plugin
	// types. It conveys nothing to a reader of the HCL reference.
	if rest == "Is part of the clawpatrol plugin API." {
		return ""
	}
	return rest
}

func (r *renderer) writeOperational() {
	r.out.WriteString("## Top-level fields\n\n")
	r.out.WriteString("Every singleton gateway attribute — listen addresses, paths, control-plane joining, WireGuard endpoint, and policy fallbacks — is set directly at the top of `gateway.hcl`. Labeled blocks (`policy`, `profile`, `approver`, `credential`, `endpoint`, `rule`, `tunnel`) are documented in their own sections.\n\n")
	r.writeStructTable("config", "Gateway", reflect.TypeOf(config.Gateway{}))
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
	if doc := stripIdentPrefix(r.docs.typeDoc(pkg, typeName), typeName); doc != "" {
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
	r.out.WriteString("| Attribute | Type | Required | Description |\n")
	r.out.WriteString("|-----------|------|----------|-------------|\n")
	r.out.WriteString("| `endpoints` | `[]ref(endpoint)` | yes | Bare-name endpoint references included in this profile. |\n\n")
	r.out.WriteString("```hcl\nprofile \"default\" {\n  endpoints = [github, postgres-prod]\n}\n```\n\n")
}

// ── plugin-dispatched kinds ─────────────────────────────────────────

func (r *renderer) writeKind(kind config.Kind) {
	plugins := config.AllPlugins(kind)
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].Type < plugins[j].Type })

	syntax := kindSyntax(kind)
	fmt.Fprintf(&r.out, "## `%s` blocks\n\n", kind)
	fmt.Fprintf(&r.out, "Block syntax: `%s`\n\n", syntax)
	// Single-label kinds with one registered plugin (rule today) have
	// no type discriminator — skip the type-link line entirely.
	if !(len(plugins) == 1 && plugins[0].Type == "") {
		fmt.Fprintf(&r.out, "Registered types: ")
		for i, p := range plugins {
			if i > 0 {
				r.out.WriteString(", ")
			}
			fmt.Fprintf(&r.out, "[`%s`](#%s-%s)", p.Type, kind, anchor(p.Type))
		}
		r.out.WriteString(".\n\n")
	}

	for _, p := range plugins {
		r.writePlugin(kind, p)
	}
}

func (r *renderer) writePlugin(kind config.Kind, p *config.Plugin) {
	// Plugins with an empty Type (rule today) take a single label —
	// render `rule "<name>"`, not `rule "" "<name>"`.
	if p.Type == "" {
		fmt.Fprintf(&r.out, "### `%s \"<name>\"`\n\n", kind)
	} else {
		fmt.Fprintf(&r.out, "### `%s \"%s\" \"<name>\"`\n\n", kind, p.Type)
	}

	rt := pluginStructType(p)
	pkgName := pkgNameOf(rt)
	typeName := rt.Name()

	if doc := stripIdentPrefix(r.docs.typeDoc(pkgName, typeName), typeName); doc != "" {
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

	r.writeExample(string(kind), p.Type, rt, true)
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
	Doc         string
	Block       bool
	GoFieldName string
}

func (r *renderer) writeStructTable(pkgName, typeName string, rt reflect.Type) {
	rows := r.collectFields(pkgName, typeName, rt)
	if len(rows) == 0 {
		r.out.WriteString("_No configurable attributes._\n\n")
		return
	}

	r.out.WriteString("| Attribute | Type | Required | Description |\n")
	r.out.WriteString("|-----------|------|----------|-------------|\n")
	for _, f := range rows {
		req := "no"
		if f.Required {
			req = "yes"
		}
		fmt.Fprintf(&r.out, "| `%s` | `%s` | %s | %s |\n",
			f.Name, f.Type, req, mdEscape(oneLine(f.Doc)))
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
		if doc := stripIdentPrefix(r.docs.typeDoc(bp, bn), bn); doc != "" {
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
		// Reference annotation: a RefSpec path either exactly equals
		// the Go field name (singular) or starts with "<field>[*]"
		// (slice of refs). When set, fold the kind into the type as
		// `ref(<kind>)` (or `[]ref(<kind>)` for list-valued refs).
		if kindRef, ok := refByPath[f.Name]; ok {
			typeStr = fmt.Sprintf("ref(%s)", kindRef)
		} else if kindRef, ok := refByPath[f.Name+"[*]"]; ok {
			typeStr = fmt.Sprintf("[]ref(%s)", kindRef)
		} else if override := ctyTypeOverride(name); override != "" && typeStr == "object" {
			typeStr = override
		}
		row := fieldRow{
			Name:        name,
			Type:        typeStr,
			Required:    !hasOpt(opts, "optional"),
			Block:       hasOpt(opts, "block"),
			GoFieldName: f.Name,
			Doc:         stripIdentPrefix(r.docs.fieldDoc(pkgName, typeName, f.Name), f.Name),
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
		config.KindApprover, config.KindCredential, config.KindTunnel, config.KindEndpoint, config.KindRule,
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

	body := exampleBody(kind, typ, rt)
	if strings.TrimSpace(body) == "" {
		fmt.Fprintf(&r.out, "```hcl\n%s {}\n```\n\n", head)
		return
	}
	fmt.Fprintf(&r.out, "```hcl\n%s {\n%s}\n```\n\n", head, body)
}

func exampleBody(kind, typ string, rt reflect.Type) string {
	var sb strings.Builder
	if kind == "tunnel" && typ == "ssh_port_forward" {
		// bastion is optional in HCL because it can be replaced by via, but a
		// standalone generated example needs one or the runtime rejects it.
		fmt.Fprintln(&sb, `  bastion = "bastion.example:22"`)
	}
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

// ctyTypeOverride spells out a more specific type for HCL fields
// decoded as raw cty.Value, where the loader interprets a per-shape
// schema after gohcl. Returns "" when no override is known and the
// generic `object` should stand. Keyed by HCL attribute name; safe
// because these names are unique across the registry.
func ctyTypeOverride(hclName string) string {
	switch hclName {
	case "credentials":
		return "[]credential"
	case "approve":
		return "[]ref(approver)"
	case "match":
		return "block"
	}
	return ""
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
