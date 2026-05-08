// docgen renders site/doc/15-config-reference.md from the live plugin
// registry. Run via `go run ./tools/docgen -out site/doc/15-config-reference.md`
// (or `go generate ./...` — see tools/docgen/gen.go).
//
// Why a hand-rolled generator (and not terraform-docs / gomarkdoc / hcldec):
//
//   - terraform-docs is wired to Terraform's variable / output / resource
//     shape. Clawpatrol's grammar is a typed-block dialect with custom
//     two-label kinds (`endpoint "<type>" "<name>"`, `credential "<type>"
//     "<name>"`, etc.) dispatched to plugins by their first label. There's
//     no template hook in terraform-docs that lets you re-shape that.
//   - gomarkdoc renders Go package API docs. It can't see HCL field tags,
//     and the output (a Go-API reference) isn't what a config author wants.
//   - hcldec is a runtime spec library; nothing in the HCL ecosystem
//     ships a maintained doc generator that consumes plugin-dispatched
//     custom block kinds.
//   - terraform-plugin-docs is hard-coded to Terraform provider schemas.
//     Wrong shape.
//
// The plugin registry already has every fact we need: each plugin's
// `New() any` returns a struct whose fields carry `hcl:"..."` tags, and
// the file's Go doc comments describe the block. Reflection + go/parser
// is the smallest faithful path; emitting our own Markdown costs ~400
// lines and stays in lock-step with the source of truth.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

func main() {
	out := flag.String("out", "", "output file (defaults to stdout)")
	root := flag.String("root", ".", "repo root (must contain go.mod)")
	flag.Parse()

	rootAbs, err := filepath.Abs(*root)
	if err != nil {
		die("resolve root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rootAbs, "go.mod")); err != nil {
		die("root %q does not contain go.mod: %v", rootAbs, err)
	}

	idx, err := indexDocs(rootAbs)
	if err != nil {
		die("index docs: %v", err)
	}

	md, err := render(idx)
	if err != nil {
		die("render: %v", err)
	}

	if *out == "" {
		os.Stdout.Write(md)
		return
	}
	if err := os.WriteFile(*out, md, 0o644); err != nil {
		die("write %s: %v", *out, err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "docgen: "+format+"\n", args...)
	os.Exit(1)
}

// ---------------------------------------------------------------------
// Doc index — built from go/parser AST traversal of source dirs.
// ---------------------------------------------------------------------

type structDoc struct {
	GoTypeName  string
	PackagePath string
	Description string                  // doc comment immediately above the struct
	FileLead    string                  // file-level lead comment (used as fallback)
	Fields      map[string]fieldDocText // keyed by Go field name
}

type fieldDocText struct {
	Name        string
	Description string
}

// docIndex maps `<pkgPath>.<TypeName>` → structDoc.
type docIndex struct {
	structs map[string]structDoc
}

// dirsToIndex returns every source directory we need to read comments
// from. Tied to where plugins live + where the operational structs live.
var dirsToIndex = []string{
	"config",
	"config/plugins/credentials",
	"config/plugins/endpoints",
	"config/plugins/approvers",
	"config/plugins/rules",
}

func indexDocs(root string) (*docIndex, error) {
	idx := &docIndex{structs: map[string]structDoc{}}
	for _, rel := range dirsToIndex {
		dir := filepath.Join(root, rel)
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
			// Skip _test.go — they don't carry config schema.
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", rel, err)
		}
		// Map dir → import path. We rely on the project layout
		// (rel path under module = import path under module path).
		for _, pkg := range pkgs {
			pkgPath := "github.com/denoland/clawpatrol/" + filepath.ToSlash(rel)
			collectStructs(idx, pkg, pkgPath)
		}
	}
	return idx, nil
}

func collectStructs(idx *docIndex, pkg *ast.Package, pkgPath string) {
	for _, file := range pkg.Files {
		fileLead := fileLeadComment(file)
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			// A GenDecl can hold one or more TypeSpecs. The doc lives
			// on the GenDecl when it has a single spec, on the spec
			// otherwise.
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				doc := ts.Doc
				if doc == nil && len(gd.Specs) == 1 {
					doc = gd.Doc
				}
				sd := structDoc{
					GoTypeName:  ts.Name.Name,
					PackagePath: pkgPath,
					Description: textFromCommentGroup(doc),
					FileLead:    fileLead,
					Fields:      map[string]fieldDocText{},
				}
				for _, f := range st.Fields.List {
					if len(f.Names) == 0 {
						continue
					}
					for _, n := range f.Names {
						sd.Fields[n.Name] = fieldDocText{
							Name:        n.Name,
							Description: textFromCommentGroup(f.Doc),
						}
					}
				}
				idx.structs[pkgPath+"."+ts.Name.Name] = sd
			}
		}
	}
}

// fileLeadComment returns the first orphan comment group in a file —
// the comment that sits between the package clause and the first
// declaration, conventionally describing what the file is about. Used
// as a fallback when a struct has no doc comment of its own (the
// pattern in config/plugins/*/<name>.go).
func fileLeadComment(file *ast.File) string {
	if len(file.Comments) == 0 {
		return ""
	}
	pkgEnd := file.Name.End()
	var firstDeclStart token.Pos
	if len(file.Decls) > 0 {
		firstDeclStart = file.Decls[0].Pos()
	}
	for _, cg := range file.Comments {
		if cg.Pos() <= pkgEnd {
			continue
		}
		if firstDeclStart != token.NoPos && cg.End() >= firstDeclStart {
			return ""
		}
		return textFromCommentGroup(cg)
	}
	return ""
}

func textFromCommentGroup(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	var lines []string
	for _, c := range g.List {
		t := c.Text
		switch {
		case strings.HasPrefix(t, "// "):
			lines = append(lines, t[3:])
		case strings.HasPrefix(t, "//"):
			lines = append(lines, t[2:])
		case strings.HasPrefix(t, "/*"):
			t = strings.TrimPrefix(t, "/*")
			t = strings.TrimSuffix(t, "*/")
			lines = append(lines, strings.TrimSpace(t))
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// ---------------------------------------------------------------------
// HCL tag parsing.
// ---------------------------------------------------------------------

type hclTag struct {
	Name     string
	Optional bool
	Block    bool
	Label    bool
	Remain   bool
	Skip     bool
}

func parseHCLTag(tag reflect.StructTag) (hclTag, bool) {
	raw, ok := tag.Lookup("hcl")
	if !ok {
		return hclTag{}, false
	}
	parts := strings.Split(raw, ",")
	t := hclTag{Name: parts[0]}
	for _, p := range parts[1:] {
		switch strings.TrimSpace(p) {
		case "optional":
			t.Optional = true
		case "block":
			t.Block = true
		case "label":
			t.Label = true
		case "remain":
			t.Remain = true
		}
	}
	if t.Name == "-" || (t.Name == "" && !t.Remain) {
		t.Skip = true
	}
	return t, true
}

// ---------------------------------------------------------------------
// Field rendering.
// ---------------------------------------------------------------------

type renderedField struct {
	HCLName     string
	HCLType     string
	Required    bool
	Description string
}

func describeStruct(idx *docIndex, st reflect.Type) (description string, fields []renderedField, blockFields []blockSubField) {
	if st.Kind() == reflect.Pointer {
		st = st.Elem()
	}
	key := st.PkgPath() + "." + st.Name()
	sd, ok := idx.structs[key]
	if ok {
		description = sd.Description
		if description == "" {
			description = sd.FileLead
		}
	}
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		tag, ok := parseHCLTag(f.Tag)
		if !ok || tag.Skip || tag.Remain || tag.Label {
			continue
		}
		fdoc := ""
		if sd.Fields != nil {
			if d, ok := sd.Fields[f.Name]; ok {
				fdoc = d.Description
			}
		}
		if tag.Block {
			blockFields = append(blockFields, blockSubField{
				HCLName:     tag.Name,
				StructType:  f.Type,
				Description: fdoc,
			})
			continue
		}
		fields = append(fields, renderedField{
			HCLName:     tag.Name,
			HCLType:     hclTypeName(f.Type, tag.Name),
			Required:    !tag.Optional,
			Description: fdoc,
		})
	}
	return description, fields, blockFields
}

type blockSubField struct {
	HCLName     string
	StructType  reflect.Type
	Description string
}

// hclTypeName renders a Go type as an HCL-friendly type label. cty.Value
// fields are deliberately heterogeneous and surface as "object" or "list"
// based on how the plugin uses them; we look at a small number of known
// HCL field names to give a useful hint instead of "value".
func hclTypeName(t reflect.Type, hclName string) string {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.PkgPath() == "github.com/zclconf/go-cty/cty" && t.Name() == "Value" {
		switch hclName {
		case "match":
			return "object"
		case "approve":
			return "list"
		case "credentials":
			return "list of object"
		}
		return "value"
	}
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "number"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice:
		return "list of " + hclTypeName(t.Elem(), "")
	case reflect.Map:
		return fmt.Sprintf("map[%s]%s", hclTypeName(t.Key(), ""), hclTypeName(t.Elem(), ""))
	case reflect.Struct:
		return "block"
	}
	return strings.ToLower(t.Kind().String())
}

// ---------------------------------------------------------------------
// Markdown rendering.
// ---------------------------------------------------------------------

func render(idx *docIndex) ([]byte, error) {
	var b strings.Builder

	b.WriteString(`# Configuration reference

Auto-generated from the source of truth in ` + "`config/plugins/`" + `.
Do not hand-edit; run ` + "`go run ./tools/docgen -out site/doc/15-config-reference.md`" + ` to regenerate.

A clawpatrol gateway loads one HCL file (typically ` + "`/etc/clawpatrol/gateway.hcl`" + `).
The file mixes **operational** fields (gateway plumbing) with **policy** blocks. Operational
fields decode statically; policy blocks dispatch to plugins by their first label. References
between named entities are bare names — no kind prefix, no type prefix — and the namespace
is flat.

For a worked tour of the grammar, see ` + "`config/README.md`" + `; this page is the
exhaustive field reference.

`)

	b.WriteString("## Top-level fields\n\n")
	gwType := reflect.TypeOf(config.Gateway{})
	desc, fields, blocks := describeStruct(idx, gwType)
	if desc != "" {
		b.WriteString(paragraphify(desc) + "\n\n")
	}
	writeFieldTable(&b, fields)

	for _, sub := range blocks {
		b.WriteString(fmt.Sprintf("\n### `%s {}` block\n\n", sub.HCLName))
		if sub.Description != "" {
			b.WriteString(paragraphify(sub.Description) + "\n\n")
		}
		_, subFields, _ := describeStruct(idx, sub.StructType)
		writeFieldTable(&b, subFields)
	}

	// defaults {}
	b.WriteString("\n## `defaults {}`\n\n")
	defType := reflect.TypeOf(config.Defaults{})
	defDesc, defFields, _ := describeStruct(idx, defType)
	if defDesc != "" {
		b.WriteString(paragraphify(defDesc) + "\n\n")
	}
	writeFieldTable(&b, defFields)
	b.WriteString("\nExample:\n\n```hcl\n")
	b.WriteString(synthExampleSimple("defaults", "", defFields))
	b.WriteString("```\n")

	// policy "<name>" {}
	b.WriteString("\n## `policy \"<name>\" {}`\n\n")
	b.WriteString("Reusable LLM proctor prompt. Referenced by name from `approver` blocks (LLM judges) and `rule` `approve` chains. Heredoc-friendly.\n\n")
	ptType := reflect.TypeOf(config.PolicyText{})
	_, ptFields, _ := describeStruct(idx, ptType)
	writeFieldTable(&b, ptFields)
	b.WriteString("\nExample:\n\n```hcl\npolicy \"k8s-exec-content\" {\n  text = <<-EOT\n    Inspect the kubectl exec command (each ?command= argv element).\n    Deny if it dumps env vars, reads sensitive host-mount files...\n  EOT\n}\n```\n")

	// profile "<name>" {}
	b.WriteString("\n## `profile \"<name>\" {}`\n\n")
	b.WriteString("Endpoint membership list. A device's profile gets exactly the endpoints its profile names; rules ride along automatically because they're attached to endpoints.\n\n")
	b.WriteString("| Field | Type | Required | Description |\n|---|---|---|---|\n")
	b.WriteString("| `endpoints` | list of string | yes | Bare-name references to declared endpoints. |\n")
	b.WriteString("\nExample:\n\n```hcl\nprofile \"kaju\" {\n  endpoints = [github-kaju, slack-kaju, grafana]\n}\n```\n")

	// device "<ip>" {}
	b.WriteString("\n## `device \"<ip>\" {}`\n\n")
	b.WriteString("Per-device rule overrides. Nested `rule \"<type>\" \"<name>\"` blocks decode through the same plugin pipeline as top-level rules; the compiler pins each rule to the device IP automatically and adds a +1000 priority bump so device overrides win against profile rules at the same explicit priority.\n\n")
	b.WriteString("- Nested rules reference the device's IP implicitly. Do **not** add `peer_ip = ...` — the dispatcher handles peer scoping.\n")
	b.WriteString("- An endpoint referenced by a device rule is auto-added to every profile's HostIndex so dispatch finds it. Other devices' traffic to those hosts gets MITM'd but no rule fires.\n")
	b.WriteString("- The dashboard's per-device editor accepts `device {}` blocks alongside `endpoint`, `credential`, `approver`, and `policy` blocks.\n\n")
	b.WriteString("Example:\n\n```hcl\ndevice \"10.55.0.2\" {\n  rule \"http_rule\" \"deny-tinyclouds\" {\n    endpoint = github-api\n    match    = { path = \"/tinyclouds/*\" }\n    verdict  = \"deny\"\n    reason   = \"this device shouldn't reach tinyclouds\"\n  }\n}\n```\n")

	// Per-kind plugin sections.
	type kindSection struct {
		Heading  string
		Kind     config.Kind
		Labels   string // e.g. `"<type>" "<name>"`
		Preamble string
	}
	sections := []kindSection{
		{
			Heading:  "Approvers",
			Kind:     config.KindApprover,
			Labels:   `"<type>" "<name>"`,
			Preamble: "Who arbitrates `approve = [...]` chains. Reference an approver by its bare name from a rule's `approve` list. The built-in `dashboard` approver does not require a block — `approve = [dashboard]` resolves to the built-in.",
		},
		{
			Heading:  "Credentials",
			Kind:     config.KindCredential,
			Labels:   `"<type>" "<name>"`,
			Preamble: "Typed handle to a secret. The actual secret bytes live in the gateway's secret store (env vars by default, keyed by `CLAWPATROL_SECRET_<UPPER_NAME>`); the credential block carries only how-to-inject parameters.",
		},
		{
			Heading:  "Endpoints",
			Kind:     config.KindEndpoint,
			Labels:   `"<type>" "<name>"`,
			Preamble: "Typed upstream binding. Each endpoint type maps to a protocol family (`https`, `sql`, `k8s`, `ssh`); rules constrain themselves to a matching family.",
		},
		{
			Heading:  "Rules",
			Kind:     config.KindRule,
			Labels:   `"<type>" "<name>"`,
			Preamble: "One policy decision targeting one or more endpoints. Each rule type is constrained to a matching endpoint family. The shared `RuleBody` schema below applies to all rule types; the per-family match keys are listed under each type.",
		},
	}

	for _, sec := range sections {
		b.WriteString("\n## " + sec.Heading + "\n\n")
		b.WriteString(sec.Preamble + "\n")
		plugins := config.AllPlugins(sec.Kind)
		for _, p := range plugins {
			renderPlugin(&b, idx, p, string(sec.Kind), sec.Labels)
		}
	}

	return []byte(b.String()), nil
}

func renderPlugin(b *strings.Builder, idx *docIndex, p *config.Plugin, kindWord, labels string) {
	body := p.New()
	t := reflect.TypeOf(body)
	desc, fields, _ := describeStruct(idx, t)

	header := fmt.Sprintf("\n### `%s \"%s\" \"<name>\"`\n\n", kindWord, p.Type)
	if labels == `"<name>"` {
		header = fmt.Sprintf("\n### `%s \"<name>\"` (type `%s`)\n\n", kindWord, p.Type)
	}
	b.WriteString(header)

	var meta []string
	if p.Family != "" {
		meta = append(meta, fmt.Sprintf("**Family:** `%s`", p.Family))
	}
	if len(p.Families) > 0 {
		meta = append(meta, fmt.Sprintf("**Endpoint families:** `%s`", strings.Join(p.Families, "`, `")))
	}
	if len(meta) > 0 {
		b.WriteString(strings.Join(meta, ". ") + ".\n\n")
	}

	if desc != "" {
		b.WriteString(paragraphify(desc) + "\n\n")
	}

	if len(fields) == 0 {
		b.WriteString("_No body attributes._\n")
	} else {
		writeFieldTable(b, fields)
	}

	// Special-case the rules grammar: the rule body is `RuleBody` and
	// the per-family `match` keys live in config/match. We surface
	// match keys in a follow-up subsection rather than duplicating the
	// shared field table per type.
	if p.Kind == config.KindRule {
		writeRuleMatchKeys(b, p)
	}

	b.WriteString("\nExample:\n\n```hcl\n")
	b.WriteString(synthExample(kindWord, p.Type, fields))
	b.WriteString("```\n")
}

// writeRuleMatchKeys lists the family-specific `match = { ... }` keys
// the rule type accepts. Sourced from config/match's KnownKeys via the
// rules plugin's plugin metadata.
func writeRuleMatchKeys(b *strings.Builder, p *config.Plugin) {
	keys := matchKeysForRule(p.Type)
	if len(keys) == 0 {
		return
	}
	b.WriteString(fmt.Sprintf("\n**`match` keys (%s):** ", p.Type))
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = "`" + k + "`"
	}
	b.WriteString(strings.Join(out, ", "))
	b.WriteString(". Each value accepts a single string or a list (any-of). Strings starting with `!` are negated.\n")
}

func writeFieldTable(b *strings.Builder, fields []renderedField) {
	if len(fields) == 0 {
		b.WriteString("_No fields._\n\n")
		return
	}
	b.WriteString("| Field | Type | Required | Description |\n|---|---|---|---|\n")
	for _, f := range fields {
		req := "no"
		if f.Required {
			req = "yes"
		}
		desc := strings.ReplaceAll(f.Description, "|", `\|`)
		desc = strings.ReplaceAll(desc, "\n", " ")
		b.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n",
			f.HCLName, f.HCLType, req, desc))
	}
}

// synthExample emits a minimal HCL block populated with required-only
// fields. Default values are placeholder idents — the goal is to teach
// shape, not be valid out of the box.
func synthExample(kindWord, typ string, fields []renderedField) string {
	var b strings.Builder
	if typ == "" {
		fmt.Fprintf(&b, "%s {\n", kindWord)
	} else {
		fmt.Fprintf(&b, "%s %q \"<name>\" {\n", kindWord, typ)
	}
	hasReq := false
	for _, f := range fields {
		if !f.Required {
			continue
		}
		fmt.Fprintf(&b, "  %-12s = %s\n", f.HCLName, exampleValue(f.HCLType))
		hasReq = true
	}
	if !hasReq {
		// Show one-line empty form — common for empty-struct credentials.
		return strings.TrimRight(b.String(), "{\n") + "{}\n"
	}
	b.WriteString("}\n")
	return b.String()
}

func synthExampleSimple(kindWord, typ string, fields []renderedField) string {
	var b strings.Builder
	if typ == "" {
		fmt.Fprintf(&b, "%s {\n", kindWord)
	} else {
		fmt.Fprintf(&b, "%s %q \"<name>\" {\n", kindWord, typ)
	}
	for _, f := range fields {
		fmt.Fprintf(&b, "  %-18s = %s\n", f.HCLName, exampleValue(f.HCLType))
	}
	b.WriteString("}\n")
	return b.String()
}

func exampleValue(typ string) string {
	switch typ {
	case "string":
		return `"<value>"`
	case "bool":
		return "false"
	case "number":
		return "0"
	case "list of string":
		return `["<value>"]`
	case "object":
		return "{}"
	case "list", "list of object":
		return "[]"
	}
	if strings.HasPrefix(typ, "list of ") {
		return "[]"
	}
	return `"<value>"`
}

// paragraphify normalizes a block of "//" comment text: collapses
// single-newline soft-wraps inside paragraphs but preserves blank-line
// paragraph breaks. Indented blocks (start with two spaces) and lines
// inside a fenced code block stay as-is.
func paragraphify(s string) string {
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	var out []string
	var paragraph []string
	flush := func() {
		if len(paragraph) > 0 {
			out = append(out, strings.Join(paragraph, " "))
			paragraph = paragraph[:0]
		}
	}
	for _, ln := range lines {
		trim := strings.TrimSpace(ln)
		switch {
		case trim == "":
			flush()
			out = append(out, "")
		case strings.HasPrefix(ln, "  ") || strings.HasPrefix(ln, "\t"):
			flush()
			out = append(out, ln)
		default:
			paragraph = append(paragraph, trim)
		}
	}
	flush()
	// Trim leading/trailing blanks
	for len(out) > 0 && out[0] == "" {
		out = out[1:]
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return strings.Join(out, "\n")
}

// matchKeysForRule returns the per-family `match` keys for a rule
// type, sourced from config/match.KnownKeys (the same table the
// matcher itself reads, so docs and validator can't drift).
func matchKeysForRule(ruleType string) []string {
	family := ruleTypeToFamily[ruleType]
	if family == "" {
		return nil
	}
	keys := match.KnownKeys(family)
	out := append([]string(nil), keys...)
	sort.Strings(out)
	return out
}

var ruleTypeToFamily = map[string]string{
	"http_rule": "https",
	"sql_rule":  "sql",
	"k8s_rule":  "k8s",
}
