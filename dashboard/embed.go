// Package dashboard ships the SPA + login page that the gateway
// serves. The Go file sits next to www/ so //go:embed can resolve
// without crossing package boundaries; the binary in cmd/clawpatrol
// imports it.
package dashboard

import (
	"embed"
)

// DistFS is the built SPA bundle (`dashboard/dist`) embedded at
// compile time. The gateway serves these assets from the dashboard
// HTTP handler.
//
//go:embed all:dist
var DistFS embed.FS

// LoginHTML is the standalone login page served before a dashboard
// session cookie is established.
//
//go:embed login.html
var LoginHTML string
