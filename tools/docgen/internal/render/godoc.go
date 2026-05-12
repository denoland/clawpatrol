package render

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
)

// goDocs holds Go source comments extracted from the packages whose
// types are exposed in the HCL config. We index by qualified type
// name (`config.Gateway`, `endpoints.HTTPSEndpoint`) and by field
// (`endpoints.HTTPSEndpoint.Hosts`).
type goDocs struct {
	types  map[string]string // pkgName.TypeName → leading doc
	fields map[string]string // pkgName.TypeName.FieldName → leading doc
}

// loadGoDocs parses every Go file under config/ that holds an HCL-
// tagged struct and extracts the leading doc comments. We walk the
// AST manually rather than going through go/doc because we want
// per-field comments, including comments above struct fields.
//
// Source lookup is anchored at runtime.Caller so the generator can
// be invoked from any working directory (notably `go test` from a
// subpackage).
func loadGoDocs() (*goDocs, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	dirs := []string{
		filepath.Join(root, "config"),
		filepath.Join(root, "config", "plugins", "approvers"),
		filepath.Join(root, "config", "plugins", "credentials"),
		filepath.Join(root, "config", "plugins", "tunnels"),
		filepath.Join(root, "config", "plugins", "endpoints"),
		filepath.Join(root, "config", "plugins", "rules"),
	}

	docs := &goDocs{
		types:  map[string]string{},
		fields: map[string]string{},
	}

	fset := token.NewFileSet()
	for _, dir := range dirs {
		pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
			n := fi.Name()
			return strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go")
		}, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", dir, err)
		}
		for _, pkg := range pkgs {
			extractPkg(pkg, docs)
		}
	}
	return docs, nil
}

func extractPkg(pkg *ast.Package, out *goDocs) {
	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				typeKey := pkg.Name + "." + ts.Name.Name
				doc := commentText(ts.Doc)
				if doc == "" {
					// Type doc may be on the GenDecl rather than
					// the TypeSpec when the type is the only spec
					// in the decl.
					doc = commentText(gd.Doc)
				}
				if doc != "" {
					out.types[typeKey] = doc
				}
				if st.Fields != nil {
					for _, f := range st.Fields.List {
						fieldDoc := commentText(f.Doc)
						if fieldDoc == "" {
							fieldDoc = commentText(f.Comment)
						}
						for _, name := range f.Names {
							out.fields[typeKey+"."+name.Name] = fieldDoc
						}
					}
				}
			}
		}
	}
}

func commentText(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	return strings.TrimSpace(g.Text())
}

// repoRoot resolves to the clawpatrol repo root by walking up from
// this file's location at compile time.
func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	// .../tools/docgen/internal/render/godoc.go → repo root is 4 levels up.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

func (d *goDocs) typeDoc(pkg, name string) string { return d.types[pkg+"."+name] }
func (d *goDocs) fieldDoc(pkg, typ, f string) string {
	return d.fields[pkg+"."+typ+"."+f]
}
