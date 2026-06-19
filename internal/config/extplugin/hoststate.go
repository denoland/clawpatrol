package extplugin

import (
	"context"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/extplugin/wire"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HostState is the gateway-served, plugin-called persistent byte store
// (the v2 "state service"). Unlike the credential / endpoint / tunnel
// services — which the gateway calls on the plugin — this one runs on
// the gateway and a sandboxed plugin calls it over the go-plugin broker,
// so a plugin can remember opaque bytes (SSH host keys, signing
// material, a dynamic client_id) across restarts without a writable
// filesystem of its own.
//
// Every instance is bound to ONE plugin at spawn time: the gateway
// namespaces all reads and writes by that plugin, so a plugin can never
// address another's keys, and the namespace is never taken from the
// wire.

// HostServicesBrokerID is the fixed go-plugin broker stream id the
// gateway serves host services on and the plugin dials. A constant is
// safe because clawpatrol never calls GRPCBroker.NextId() — the brokered
// upstream dial multiplexes over the HandleConn stream, not the broker —
// so nothing else competes for stream ids. Canonical definition in wire.
const HostServicesBrokerID = wire.HostServicesBrokerID

// maxStateValueBytes caps a single stored value. The known consumers
// (host keys, key material, a client_id) are well under a kilobyte; the
// cap bounds any one value so a buggy plugin can't store something huge.
// Note this is a per-value cap only — it does not bound the number of
// distinct keys a plugin may write, so it is not a total-storage quota.
// A per-namespace key/byte quota is a follow-up (the BlobStore contract
// has no count/list to enforce one against today).
const maxStateValueBytes = 1 << 20 // 1 MiB

// blobNamespacePrefix isolates external-plugin state from the built-in
// plugins' BlobStore kinds ("ssh_host_key", "codex_jwt_keys"). The
// gateway forms the BlobStore kind as "<prefix><plugin>" so an external
// plugin named "ssh_host_key" still can't reach a built-in's blobs.
const blobNamespacePrefix = "extplugin:"

// hostState implements pb.HostStateServer for one plugin, backed by the
// gateway's BlobStore and namespaced by the plugin's name. The store is
// resolved lazily per call (via blobs) rather than captured at spawn: the
// gateway's blob store isn't ready until after the first config load
// (the state dir it lives in is itself part of the config), so a plugin
// spawned during that load must still see the store once it is wired.
//
// The namespace is the plugin's HCL block label (the operator-chosen
// `plugin "<name>"`), set at spawn — the manifest name isn't known yet,
// since spawning is what fetches the manifest. It matches the key the
// permission lockfile already uses, and is operator-controlled, never
// taken from the wire. (Two plugin blocks sharing one label would share
// state; rejecting duplicate labels is a separate config-validation
// concern.)
type hostState struct {
	pb.UnimplementedHostStateServer
	blobs  func() runtime.BlobStore
	plugin string // namespace; the HCL block label, never from the wire
}

func newHostState(blobs func() runtime.BlobStore, pluginName string) *hostState {
	return &hostState{blobs: blobs, plugin: pluginName}
}

func (h *hostState) kind() string { return blobNamespacePrefix + h.plugin }

// store resolves the backing blob store, or an Unavailable error when the
// gateway has none wired yet (early boot, or the CLI/probe paths).
func (h *hostState) store() (runtime.BlobStore, error) {
	if b := h.blobs(); b != nil {
		return b, nil
	}
	return nil, status.Error(codes.Unavailable, "plugin state service is not available on this gateway")
}

func (h *hostState) Get(_ context.Context, req *pb.StateGetRequest) (*pb.StateGetResponse, error) {
	if err := validateStateKey(req.GetKey()); err != nil {
		return nil, err
	}
	b, err := h.store()
	if err != nil {
		return nil, err
	}
	v, ok, err := b.Get(h.kind(), req.GetKey())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "state get %q: %v", req.GetKey(), err)
	}
	return &pb.StateGetResponse{Value: v, Found: ok}, nil
}

func (h *hostState) Put(_ context.Context, req *pb.StatePutRequest) (*pb.StatePutResponse, error) {
	if err := validateStateKey(req.GetKey()); err != nil {
		return nil, err
	}
	if n := len(req.GetValue()); n > maxStateValueBytes {
		return nil, status.Errorf(codes.InvalidArgument,
			"state value for %q is %d bytes, over the %d-byte limit", req.GetKey(), n, maxStateValueBytes)
	}
	b, err := h.store()
	if err != nil {
		return nil, err
	}
	if err := b.Put(h.kind(), req.GetKey(), req.GetValue()); err != nil {
		return nil, status.Errorf(codes.Internal, "state put %q: %v", req.GetKey(), err)
	}
	return &pb.StatePutResponse{}, nil
}

// validateStateKey rejects empty or over-long keys. The key is a plugin-
// chosen sub-key within the plugin's namespace; it is opaque to the
// gateway otherwise.
func validateStateKey(key string) error {
	if key == "" {
		return status.Error(codes.InvalidArgument, "state key must not be empty")
	}
	if len(key) > 512 {
		return status.Error(codes.InvalidArgument, "state key too long (max 512 bytes)")
	}
	return nil
}

// ensure hostState satisfies the generated server interface.
var _ pb.HostStateServer = (*hostState)(nil)
