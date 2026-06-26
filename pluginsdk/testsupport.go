package pluginsdk

import (
	"sync"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	goplugin "github.com/hashicorp/go-plugin"
)

// NewEndpointServerForTest builds the SDK's in-process gRPC dispatcher for a
// Plugin and returns it as a pb.EndpointServer. It exists so the gateway's
// extplugin package can wire a real SDK endpoint (HandleConn, Conn.Evaluate,
// Conn.SetResult) into a broker-backed integration test without spawning a
// subprocess. Not part of the plugin-author API; the production entry point
// is Run.
func NewEndpointServerForTest(p *Plugin) pb.EndpointServer {
	return newServer(p)
}

// SetHostBrokerForTest installs the go-plugin broker the SDK dials for host
// services (HostControl / HostState), the same wiring grpcServer.GRPCServer
// performs in production. It also resets the cached host-services connection
// so a fresh test dials anew. Test-only.
func SetHostBrokerForTest(b *goplugin.GRPCBroker) {
	hostBrokerMu.Lock()
	hostBroker = b
	hostBrokerMu.Unlock()
	hostConnOnce = sync.Once{}
	hostConn = nil
	hostConnErr = nil
}
