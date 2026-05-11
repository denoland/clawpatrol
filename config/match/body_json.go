package match

import "encoding/json"

// BodyJSON reports whether every key/value pair in want is present
// in the JSON document body. It's a structural subset check, not deep
// equality — extra keys in the body are fine, missing keys fail.
//
// Values match in three modes:
//   - want is a string / number / bool: shallow equality with the body
//     value at the same key (after json.Unmarshal coercion).
//   - want is a nested map: recurse; nested keys must all match.
//   - want is a slice: order-insensitive subset (every want element
//     must appear in the body slice, equality at the leaf).
//
// Returns false on JSON parse errors so a malformed body never
// accidentally matches a rule.
func BodyJSON(body []byte, want map[string]any) bool {
	if len(body) == 0 {
		return false
	}
	var got any
	if err := json.Unmarshal(body, &got); err != nil {
		return false
	}
	return jsonSubset(got, want)
}

func jsonSubset(got, want any) bool {
	switch w := want.(type) {
	case map[string]any:
		gm, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for k, wv := range w {
			gv, present := gm[k]
			if !present {
				return false
			}
			if !jsonSubset(gv, wv) {
				return false
			}
		}
		return true
	case []any:
		gs, ok := got.([]any)
		if !ok {
			return false
		}
		for _, wv := range w {
			found := false
			for _, gv := range gs {
				if jsonSubset(gv, wv) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	// Primitive equality. JSON numbers come back as float64, booleans
	// as bool, strings as string. We compare raw — callers writing
	// `body_json = { archived = true }` rely on bool↔bool match.
	return got == want
}
