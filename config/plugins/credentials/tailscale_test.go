package credentials

import (
	"bytes"
	"errors"
	"testing"

	"tailscale.com/ipn"

	"github.com/denoland/clawpatrol/config/plugins/tailscaleproto"
	"github.com/denoland/clawpatrol/config/runtime"
)

// fakeWritableStore is a minimal SecretStore that also satisfies
// tailscaleproto.SecretWriter, so the tailscale credential's
// StateStore can round-trip ipn state through it without needing a
// real sqlite-backed gatewaySecretStore.
type fakeWritableStore struct {
	slots map[string]map[string]string // name -> slot -> value
}

func newFakeStore() *fakeWritableStore {
	return &fakeWritableStore{slots: map[string]map[string]string{}}
}

func (f *fakeWritableStore) Get(name string) (runtime.Secret, error) {
	m, ok := f.slots[name]
	if !ok {
		return runtime.Secret{}, nil
	}
	sec := runtime.Secret{Kind: "dashboard", Extras: map[string]string{}}
	for k, v := range m {
		sec.Extras[k] = v
	}
	return sec, nil
}

func (f *fakeWritableStore) SetCredentialSlot(name, slot, value string) error {
	m, ok := f.slots[name]
	if !ok {
		m = map[string]string{}
		f.slots[name] = m
	}
	m[slot] = value
	return nil
}

func TestTailscaleStateStoreRoundTrip(t *testing.T) {
	cred := &TailscaleCredential{}
	store := newFakeStore()
	ss, err := cred.StateStore("my-tailnet", store)
	if err != nil {
		t.Fatalf("StateStore: %v", err)
	}

	// Read before write returns ErrStateNotExist.
	if _, err := ss.ReadState(ipn.MachineKeyStateKey); !errors.Is(err, ipn.ErrStateNotExist) {
		t.Fatalf("ReadState empty: want ErrStateNotExist, got %v", err)
	}

	want := []byte("machine-key-bytes-\x00\x01\x02")
	if err := ss.WriteState(ipn.MachineKeyStateKey, want); err != nil {
		t.Fatalf("WriteState: %v", err)
	}
	got, err := ss.ReadState(ipn.MachineKeyStateKey)
	if err != nil {
		t.Fatalf("ReadState: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, want)
	}

	// Second credential name is isolated in the same store.
	ss2, err := cred.StateStore("other-tailnet", store)
	if err != nil {
		t.Fatalf("StateStore other: %v", err)
	}
	if _, err := ss2.ReadState(ipn.MachineKeyStateKey); !errors.Is(err, ipn.ErrStateNotExist) {
		t.Fatalf("other tailnet should not see first tailnet's state: %v", err)
	}
}

func TestTailscaleStateStoreRequiresWriter(t *testing.T) {
	cred := &TailscaleCredential{}
	_, err := cred.StateStore("ts", runtime.EnvSecretStore{})
	if err == nil {
		t.Fatal("StateStore with EnvSecretStore: want error, got nil")
	}
}

func TestTailscaleAuthIntegrationSurfaces(t *testing.T) {
	cred := &TailscaleCredential{}
	var _ tailscaleproto.TailscaleAuthProvider = cred
	if got := cred.TailscaleAuth(); got == nil {
		t.Fatal("TailscaleAuth returned nil")
	}
}
