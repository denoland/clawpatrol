package pluginsdk

import (
	"context"
	"errors"
	"sync"

	"github.com/denoland/clawpatrol/internal/config/extplugin"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// StateStore is the handle to the gateway's per-plugin persistent byte
// store. Values survive plugin restarts and are namespaced to this plugin
// by the gateway, so keys are private — one plugin can never read
// another's. Use it for the small amount of identity a plugin must
// remember across boots: an SSH endpoint host key, a signing keypair, a
// dynamically registered client_id.
//
// Obtain it with the package-level State() accessor. The first call dials
// the gateway over the go-plugin broker; the connection is cached for the
// life of the process.
//
// Use it from a runtime callback — HandleConn, InjectHTTP, OpenTunnel, or
// Dial. It is NOT guaranteed during a Build callback on the gateway's
// first config load: the gateway's state store lives in the state dir,
// which is itself part of the config being loaded, so it is wired only
// after that load completes. A Build-time Get on first boot may return an
// "unavailable" error; persist and read identity from a runtime callback
// (which is where host keys, signing material, and the like are actually
// needed) rather than from Build.
type StateStore struct{}

// State returns the handle to the gateway's per-plugin persistent store.
func State() *StateStore { return &StateStore{} }

// Get returns the stored value for key and whether it was present.
func (StateStore) Get(ctx context.Context, key string) (value []byte, found bool, err error) {
	cli, err := hostStateClient()
	if err != nil {
		return nil, false, err
	}
	resp, err := cli.Get(ctx, &pb.StateGetRequest{Key: key})
	if err != nil {
		return nil, false, err
	}
	return resp.GetValue(), resp.GetFound(), nil
}

// Put stores value under key, overwriting any previous value. Values are
// capped by the gateway (1 MiB); this is for identity, not bulk data.
func (StateStore) Put(ctx context.Context, key string, value []byte) error {
	cli, err := hostStateClient()
	if err != nil {
		return err
	}
	_, err = cli.Put(ctx, &pb.StatePutRequest{Key: key, Value: value})
	return err
}

// hostBroker is captured once when the plugin's gRPC server starts (see
// grpcServer.GRPCServer). There is exactly one plugin server per process,
// so a package-level handle is the natural home; it lets State() work
// from any callback without threading a handle through every request.
var (
	hostBrokerMu sync.Mutex
	hostBroker   *plugin.GRPCBroker

	// The gateway serves HostState and HostControl on one broker stream
	// (HostServicesBrokerID), so the plugin dials it once and builds both
	// stubs over the single connection — AcceptAndServe accepts that id
	// only once.
	hostConnOnce sync.Once
	hostConn     *grpc.ClientConn
	hostConnErr  error
)

func setHostBroker(b *plugin.GRPCBroker) {
	hostBrokerMu.Lock()
	hostBroker = b
	hostBrokerMu.Unlock()
}

// hostServicesConn lazily dials the gateway's host-services broker stream
// and caches the connection. It errors when the plugin is running without a
// gateway broker (a unit test, or an old gateway), so plugin code can
// degrade gracefully.
func hostServicesConn() (*grpc.ClientConn, error) {
	hostConnOnce.Do(func() {
		hostBrokerMu.Lock()
		b := hostBroker
		hostBrokerMu.Unlock()
		if b == nil {
			hostConnErr = errors.New("pluginsdk: host services unavailable (no gateway broker)")
			return
		}
		hostConn, hostConnErr = b.Dial(extplugin.HostServicesBrokerID)
	})
	return hostConn, hostConnErr
}

func hostStateClient() (pb.HostStateClient, error) {
	c, err := hostServicesConn()
	if err != nil {
		return nil, err
	}
	return pb.NewHostStateClient(c), nil
}

func hostControlClient() (pb.HostControlClient, error) {
	c, err := hostServicesConn()
	if err != nil {
		return nil, err
	}
	return pb.NewHostControlClient(c), nil
}
