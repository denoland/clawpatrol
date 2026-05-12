//go:build linux || darwin

package main

import (
	"os"
	"syscall"
)

// chownToStateDirOwner copies the state directory's owning uid/gid
// to path. Called only when the caller is root, so the file ends up
// readable by whichever user owns the gateway state (typically the
// clawpatrol service account). Best-effort: any failure short of
// catastrophic returns nil so the CLI still prints the token.
func chownToStateDirOwner(path, stateDir string) error {
	info, err := os.Stat(stateDir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Chown(path, int(st.Uid), int(st.Gid))
}
