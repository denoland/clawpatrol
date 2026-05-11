// Command docgen generates site/doc/config-reference.md from the
// clawpatrol HCL config plugin registry. Schema source of truth is
// the Go structs under config/plugins/ and the operational structs
// in config/. Field documentation is read from Go source comments.
//
// The generator is idempotent: re-running on an unchanged tree
// produces a byte-identical file. A drift test (docgen_test.go)
// re-runs the generator and diffs against the committed output to
// catch schemas that changed without doc updates.
//
// Why hand-rolled (not terraform-docs / gomarkdoc / etc.):
// clawpatrol's HCL is a plugin-dispatched DSL — `<kind> "<type>"
// "<name>" { ... }` blocks dispatch to a runtime-registered Go
// struct via config.Register. No off-the-shelf HCL doc tool walks
// a custom plugin registry; terraform-docs targets Terraform module
// variables, gomarkdoc emits Go API docs, and hcldec/hclspec carry
// no doc generator. The generator is small (≈500 LOC) and has a
// drift test, so the maintenance cost is bounded.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/denoland/clawpatrol/tools/docgen/internal/render"
)

func main() {
	out := flag.String("o", "site/doc/config-reference.md", "output file (relative to repo root)")
	check := flag.Bool("check", false, "exit non-zero if the generated content differs from the file at -o")
	flag.Parse()

	got, err := render.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "docgen:", err)
		os.Exit(2)
	}

	if *check {
		want, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "docgen --check: read", *out, ":", err)
			os.Exit(2)
		}
		if string(want) != got {
			fmt.Fprintf(os.Stderr,
				"docgen --check: %s is stale; re-run `go run ./tools/docgen` and commit the result\n",
				*out)
			os.Exit(1)
		}
		return
	}

	if err := os.WriteFile(*out, []byte(got), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "docgen:", err)
		os.Exit(2)
	}
}
