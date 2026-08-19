//go:build !linux

package main

import (
	"context"
	"fmt"
)

func bridgeRun(_ context.Context, _ bridgeOptions) error {
	return fmt.Errorf("clawpatrol bridge is only supported on Linux")
}
