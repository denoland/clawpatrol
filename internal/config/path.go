package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// pathValue is one resolved (string) value plucked out of a decoded
// struct via a RefSpec.Path traversal.
type pathValue struct {
	value    string
	rangePtr *hcl.Range // nil → use the enclosing block's range
}

// readPath walks the decoded struct following a dot-separated path
// with [*] markers for slice fan-out, returning every string value
// it found. The fallback range (typically the block range) is used
// for diagnostics; field-precise ranges aren't extractable from
// gohcl-decoded structs without going back to the hcl.Body.
//
// Examples of supported paths:
//
//	"Endpoint"                     // singular ref on a struct field
//	"Endpoints[*]"                 // slice of strings
//	"Credentials[*].Credential"    // slice of structs, ref field on each
//
// Unknown paths return a structural diagnostic — that's a programming
// error in the plugin's RefSpec, not a user error.
func readPath(decoded any, path string, fallback hcl.Range) ([]pathValue, hcl.Diagnostics) {
	rv := reflect.ValueOf(decoded)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, nil
		}
		rv = rv.Elem()
	}
	parts := splitPath(path)
	values, err := walkPath(rv, parts, fallback)
	if err != nil {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Plugin RefSpec error",
			Detail:   fmt.Sprintf("RefSpec path %q on %s: %v", path, rv.Type(), err),
			Subject:  &fallback,
		}}
	}
	return values, nil
}

func splitPath(path string) []string {
	// Path components are separated by "."; "[*]" attaches to the
	// preceding component as a marker.
	return strings.Split(path, ".")
}

func walkPath(rv reflect.Value, parts []string, fallback hcl.Range) ([]pathValue, error) {
	if len(parts) == 0 {
		// Terminal: rv must be string-valued.
		s, err := asString(rv)
		if err != nil {
			return nil, err
		}
		return []pathValue{{value: s, rangePtr: &fallback}}, nil
	}
	head, fanout := parts[0], false
	if strings.HasSuffix(head, "[*]") {
		head = strings.TrimSuffix(head, "[*]")
		fanout = true
	}
	field := rv.FieldByName(head)
	if !field.IsValid() {
		return nil, fmt.Errorf("no field %q on %s", head, rv.Type())
	}
	if fanout {
		if field.Kind() != reflect.Slice {
			return nil, fmt.Errorf("[*] requires a slice but %s.%s is %s", rv.Type(), head, field.Kind())
		}
		var out []pathValue
		for i := 0; i < field.Len(); i++ {
			sub, err := walkPath(field.Index(i), parts[1:], fallback)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
		}
		return out, nil
	}
	return walkPath(field, parts[1:], fallback)
}

func asString(rv reflect.Value) (string, error) {
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return "", nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.String {
		return "", fmt.Errorf("terminal path is %s, expected string", rv.Kind())
	}
	return rv.String(), nil
}
