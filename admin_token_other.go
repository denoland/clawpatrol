//go:build !linux && !darwin

package main

// chownToStateDirOwner is a no-op on platforms without POSIX
// ownership semantics. The admin token lands with whatever
// uid/gid os.WriteFile produced.
func chownToStateDirOwner(path, stateDir string) error {
	_ = path
	_ = stateDir
	return nil
}
