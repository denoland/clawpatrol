//go:build !dev

package main

import (
	"context"
	"flag"
)

// Default build: the dev seeder is excluded. The hook holds nothing
// and Run is a no-op, so main.go's wiring stays unconditional and
// the prod binary ships zero seeder code, strings, or flags.

type devSeedHook struct{}

func devSeedAttach(*flag.FlagSet) devSeedHook     { return devSeedHook{} }
func (devSeedHook) Run(context.Context, *Gateway) {}
