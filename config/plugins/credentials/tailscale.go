package credentials

// tailscale credential: persists tsnet node identity through the
// gateway secret store so a `tunnel "tailscale"` block can join a
// tailnet via the interactive login flow (`tailscale up` semantics)
// instead of a pre-minted authkey. Operator-visible body is empty —
// the credential's only HCL job is to (a) attest a tunnel's intent
// to authenticate as a node in *some* tailnet and (b) own a stable
// name under which the gateway persists node state.
//
// HCL:
//
//   credential "tailscale" "my-tailnet" {}
//
//   tunnel "tailscale" "my-tunnel" {
//     credential = my-tailnet
//   }
//
// On first boot, tsnet emits a login URL captured into the
// tailscaleproto.PendingNodeAuth side-channel. The dashboard's Connect
// button reads the URL and redirects the operator to tailscale.com.
// Once the node is approved, tsnet writes the identity through the
// credential's ipn.StateStore — backed by credential_secrets in sqlite
// — and subsequent restarts re-use the identity silently.

import (
	"errors"
	"fmt"

	"tailscale.com/ipn"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/plugins/tailscaleproto"
	"github.com/denoland/clawpatrol/config/runtime"
)

// TailscaleCredential is part of the clawpatrol plugin API. The body
// is intentionally empty — there is nothing for the operator to paste.
// Per-tailnet selection (control_url, tags) lives on the tunnel block.
type TailscaleCredential struct{}

// StateStore returns an ipn.StateStore that persists tsnet's identity
// through the gateway secret store. The credential owns persistence;
// the tunnel hands the result to tsnet.Server.Store and leaves AuthKey
// empty so tsnet drives the interactive login flow on first boot.
func (*TailscaleCredential) StateStore(name string, store runtime.SecretStore) (ipn.StateStore, error) {
	if name == "" {
		return nil, errors.New("tailscale credential: empty name")
	}
	if store == nil {
		return nil, errors.New("tailscale credential: nil secret store")
	}
	writer, ok := store.(tailscaleproto.SecretWriter)
	if !ok {
		return nil, fmt.Errorf("tailscale credential %q: secret store %T cannot persist tsnet identity (db-backed store required)", name, store)
	}
	return &secretStateStore{name: name, store: store, writer: writer}, nil
}

// TailscaleAuth signals to the dashboard that this credential surfaces
// a tailscale-node Connect flow. BeginURL is filled in by the dashboard
// handler at render time — the credential body doesn't know its own
// bare name.
func (*TailscaleCredential) TailscaleAuth() *tailscaleproto.TailscaleAuthIntegration {
	return &tailscaleproto.TailscaleAuthIntegration{}
}

// secretStateStore adapts the gateway's credential_secrets store to
// tsnet's ipn.StateStore. Every tsnet identity blob is one slot row;
// slot name = the StateKey string. Owner is "" — node identity is
// gateway-wide, not per-owner.
type secretStateStore struct {
	name   string
	store  runtime.SecretStore
	writer tailscaleproto.SecretWriter
}

func (s *secretStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	sec, err := s.store.Get(s.name, "")
	if err != nil {
		return nil, err
	}
	if v, ok := sec.Extras[string(id)]; ok {
		return []byte(v), nil
	}
	return nil, ipn.ErrStateNotExist
}

func (s *secretStateStore) WriteState(id ipn.StateKey, bs []byte) error {
	return s.writer.SetCredentialSlot(s.name, "", string(id), string(bs))
}

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "tailscale",
		New:     newer[TailscaleCredential](),
		Runtime: (*TailscaleCredential)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
