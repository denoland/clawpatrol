package match

import (
	"path/filepath"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// GlobOption returns a cel.EnvOption registering `glob(pattern, value)
// bool` on the env. Pattern uses path/filepath.Match semantics:
//
//   - `*` matches any run of non-separator characters
//   - `?` matches a single non-separator character
//   - `[...]` is a character class
//   - the entire candidate must match (no implicit anchoring suffix)
//
// Both arguments must be strings; non-strings (or a malformed pattern
// — filepath.Match returns ErrBadPattern) yield false rather than a
// CEL error, so a typo in a glob can never crash the matcher at
// request time.
func GlobOption() cel.EnvOption {
	return cel.Function("glob",
		cel.Overload("glob_string_string",
			[]*cel.Type{cel.StringType, cel.StringType},
			cel.BoolType,
			cel.BinaryBinding(globMatch),
		),
	)
}

func globMatch(pat, val ref.Val) ref.Val {
	p, ok := pat.Value().(string)
	if !ok {
		return types.Bool(false)
	}
	v, ok := val.Value().(string)
	if !ok {
		return types.Bool(false)
	}
	matched, err := filepath.Match(p, v)
	if err != nil {
		return types.Bool(false)
	}
	return types.Bool(matched)
}
