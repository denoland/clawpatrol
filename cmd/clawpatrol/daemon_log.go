package main

import (
	"bytes"
	"io"
	"os"
	"strings"
)

// lastLogLineSince returns the last non-empty line written to path at
// or after byte offset off, or "" when there is none or the file
// cannot be read. daemonSpawn uses it to fold the daemon's own fatal
// message into the error the user sees: the daemon logs to a file
// that is shared across respawns and opened O_APPEND, so reading
// from the offset recorded before the spawn (rather than tailing the
// whole file) keeps an older daemon's last words out of the report.
func lastLogLineSince(path string, off int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return ""
		}
	}
	const maxRead = 64 << 10
	buf, err := io.ReadAll(io.LimitReader(f, maxRead))
	if err != nil && len(buf) == 0 {
		return ""
	}
	buf = bytes.TrimRight(buf, "\r\n")
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	}
	return strings.TrimSpace(string(buf))
}
