// Package wire holds the small set of protocol constants shared between
// the gateway-side plugin manager (extplugin) and the plugin SDK
// (pluginsdk): the go-plugin handshake, the dispensed plugin name, the
// host-services broker stream id, and the per-call session metadata key.
//
// It is deliberately a leaf with a single dependency (go-plugin). The SDK
// references these constants, but a plugin author's binary must not pull
// the manager's transitive graph — CEL, Sigstore, OpenAPI — into itself
// just to name them. Keeping them here is what lets a plugin's dependency
// closure (and its compiled size) stay small.
package wire

import "github.com/hashicorp/go-plugin"

// HandshakeConfig is the magic-cookie pair every clawpatrol plugin
// subprocess must echo back. A mismatch means the gateway is invoking the
// wrong binary, or the binary is from an incompatible build of the SDK;
// go-plugin refuses to start in either case.
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

// HostServicesBrokerID is the go-plugin broker stream id the gateway
// serves host services (HostState / HostControl / HostTunnel) on and the
// plugin dials back through.
const HostServicesBrokerID uint32 = 1

// SessionMetadataKey is the gRPC metadata key the per-connection session
// token rides under on every HostControl call. Lower-case per gRPC's
// metadata convention.
const SessionMetadataKey = "clawpatrol-session"
