// Package dashboard ships the SPA + login page that the gateway
// serves. The Go file sits next to www/ so //go:embed can resolve
// without crossing package boundaries; the binary in cmd/clawpatrol
// imports it.
package dashboard

import (
	"embed"
)

//go:embed all:dist
var DistFS embed.FS

//go:embed login.html
var LoginHTML string
