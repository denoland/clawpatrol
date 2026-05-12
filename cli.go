package main

import (
	"flag"
	"fmt"
	"strconv"
)

// newFlagSet keeps subcommand help consistent with the documented CLI style.
// Go's flag package accepts both -flag and --flag, but its default help prints
// single-dash flags. Claw Patrol documents long options with double dashes.
func newFlagSet(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s\n\noptions:\n", usage)
		fs.VisitAll(func(f *flag.Flag) {
			// Keep short aliases accepted but out of long-option help.
			if len(f.Name) == 1 {
				return
			}
			value := ""
			if _, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok {
				value = " VALUE"
			}
			fmt.Fprintf(fs.Output(), "  --%s%s\n", f.Name, value)
			fmt.Fprintf(fs.Output(), "    \t%s", f.Usage)
			if f.DefValue != "" && f.DefValue != "false" {
				fmt.Fprintf(fs.Output(), " (default %s)", strconv.Quote(f.DefValue))
			}
			fmt.Fprintln(fs.Output())
		})
	}
	return fs
}
