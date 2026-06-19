// Package extplugin spawns and proxies clawpatrol's Terraform-style
// external plugins. The gateway uses HashiCorp go-plugin for
// subprocess lifecycle and gRPC for the wire protocol; the
// gateway-side Manager registers a virtual *config.Plugin per type
// the subprocess declares in its Manifest, so the rest of the
// loader (symbol table, framework attrs, ref resolution, dispatch)
// stays unaware that any of these plugins is out-of-process.
package extplugin

import (
	"github.com/denoland/clawpatrol/internal/config/extplugin/wire"
)

// HandshakeConfig and PluginName are the go-plugin handshake shared by the
// gateway and every plugin. The canonical definitions live in the wire
// leaf package — kept dependency-light so the SDK (and thus a plugin's
// binary) doesn't pull the manager's graph just to name them. These
// aliases keep extplugin's many in-package references unchanged.
var HandshakeConfig = wire.HandshakeConfig

// PluginName is the registered plugin name in go-plugin's plugin map.
const PluginName = wire.PluginName
