package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// expandFileIncludes walks every entity body via the FileIncludable
// optional interface and substitutes `<<file:NAME>>` markers with the
// named file's contents, read relative to the loaded config file's
// directory.
//
// The marker shape mirrors HCL heredocs visually (`<< ... >>`) but is
// not actual HCL syntax — it's a string-level convention so plugins
// don't have to invent their own escape for "this is a path, inline
// it." Each plugin opts in by implementing FileIncludable on its body
// type and listing which fields to scan.
//
// Diagnostics surface unreadable files / mismatched markers per
// (entity, field). Pinned to the entity's block range since we don't
// have field-precise positions at this layer.
func expandFileIncludes(p *Policy, configDir string) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, group := range []map[string]*Entity{p.Endpoints, p.Credentials, p.Approvers, p.Rules} {
		for name, ent := range group {
			fi, ok := ent.Body.(FileIncludable)
			if !ok {
				continue
			}
			for _, field := range fi.FileIncludeFields() {
				val := field.Get()
				resolved, d := resolveFileIncludes(val, configDir, name, ent.Symbol.Block.DefRange)
				diags = append(diags, d...)
				if resolved != val {
					field.Set(resolved)
				}
			}
		}
	}
	return diags
}

// FileIncludable is the optional interface a plugin's body type
// implements to expose string fields the loader should scan for
// `<<file:NAME>>` markers. Only fields whose value the user might
// reasonably write as a file path (CA cert PEMs, certificate
// chains, large prompts) need it; the rest stay literal.
type FileIncludable interface {
	FileIncludeFields() []FileIncludeField
}

// FileIncludeField is a getter / setter pair pointing at one string
// field on a plugin body. Plugins return a slice so multiple fields
// (e.g. kubernetes endpoint's ca_cert + client_cert) can opt in.
type FileIncludeField struct {
	Get func() string
	Set func(string)
}

// resolveFileIncludes scans s for `<<file:NAME>>` markers and
// substitutes each with the contents of NAME read relative to
// configDir. Multiple markers in one string are supported. Markers
// with absolute paths are read as-is (no configDir join).
func resolveFileIncludes(s, configDir, entityName string, blockRange hcl.Range) (string, hcl.Diagnostics) {
	if !strings.Contains(s, "<<file:") {
		return s, nil
	}
	var diags hcl.Diagnostics
	out := s
	for {
		i := strings.Index(out, "<<file:")
		if i < 0 {
			break
		}
		j := strings.Index(out[i:], ">>")
		if j < 0 {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unterminated <<file:...>> marker",
				Detail:   fmt.Sprintf("Entity %q: marker starting at index %d has no closing `>>`.", entityName, i),
				Subject:  &blockRange,
			})
			break
		}
		name := out[i+len("<<file:") : i+j]
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(configDir, name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Cannot inline file %q", name),
				Detail:   fmt.Sprintf("Entity %q referenced %q via <<file:...>> but reading %s failed: %v.", entityName, name, path, err),
				Subject:  &blockRange,
			})
			// Replace the marker with empty string to avoid loops; the
			// emitted diagnostic surfaces the failure.
			out = out[:i] + out[i+j+2:]
			continue
		}
		out = out[:i] + string(data) + out[i+j+2:]
	}
	return out, diags
}
