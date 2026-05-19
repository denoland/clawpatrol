// Package extplugin spawns and proxies clawpatrol's Terraform-style
// external plugins. The gateway uses HashiCorp go-plugin for
// subprocess lifecycle and gRPC for the wire protocol; the
// gateway-side Manager registers a virtual *config.Plugin per type
// the subprocess declares in its Manifest, so the rest of the
// loader (symbol table, framework attrs, ref resolution, dispatch)
// stays unaware that any of these plugins is out-of-process.
package extplugin

import (
	"github.com/hashicorp/go-plugin"
)

// HandshakeConfig is the magic-cookie pair every clawpatrol plugin
// subprocess must echo back. A mismatch means the gateway is
// invoking the wrong binary, or the binary is from an incompatible
// build of the SDK; go-plugin refuses to start in either case.
//
// ProtocolVersion bumps when the wire protocol breaks compatibility.
var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "CLAWPATROL_PLUGIN",
	MagicCookieValue: "clawpatrol-plugin-v1",
}

// PluginName is the registered plugin name in go-plugin's plugin map.
// Every clawpatrol plugin exports a single entry under this key whose
// gRPC service set covers Manifest / Build / HandleConn / Tunnel.
const PluginName = "clawpatrol"
