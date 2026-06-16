package extplugin

import (
	"context"
	"net"
	"sync"
	"testing"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// memBlobs is an in-memory runtime.BlobStore for tests, keyed by
// (kind, name) — exactly how the gateway namespaces plugin state.
type memBlobs struct {
	mu sync.Mutex
	m  map[[2]string][]byte
}

func newMemBlobs() *memBlobs { return &memBlobs{m: map[[2]string][]byte{}} }

func (b *memBlobs) Get(kind, name string) ([]byte, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[[2]string{kind, name}]
	return v, ok, nil
}

func (b *memBlobs) Put(kind, name string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[[2]string{kind, name}] = data
	return nil
}

// startHostState serves a hostState for pluginName over an in-memory
// bufconn and returns a connected HostStateClient. blobs may be nil to
// exercise the not-ready path.
func startHostState(t *testing.T, pluginName string, blobs runtime.BlobStore) pb.HostStateClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterHostStateServer(srv, newHostState(func() runtime.BlobStore { return blobs }, pluginName))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewHostStateClient(conn)
}

func TestHostStateGetPutRoundTrip(t *testing.T) {
	blobs := newMemBlobs()
	cli := startHostState(t, "aws", blobs)
	ctx := context.Background()

	// Missing key -> found=false.
	if r, err := cli.Get(ctx, &pb.StateGetRequest{Key: "host_key"}); err != nil || r.Found {
		t.Fatalf("get missing = %+v err=%v, want not found", r, err)
	}
	// Put then get.
	if _, err := cli.Put(ctx, &pb.StatePutRequest{Key: "host_key", Value: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	r, err := cli.Get(ctx, &pb.StateGetRequest{Key: "host_key"})
	if err != nil || !r.Found || string(r.Value) != "abc" {
		t.Fatalf("get = %+v err=%v, want abc", r, err)
	}
	// Overwrite.
	if _, err := cli.Put(ctx, &pb.StatePutRequest{Key: "host_key", Value: []byte("xyz")}); err != nil {
		t.Fatal(err)
	}
	if r, _ := cli.Get(ctx, &pb.StateGetRequest{Key: "host_key"}); string(r.Value) != "xyz" {
		t.Fatalf("overwrite get = %q, want xyz", r.Value)
	}

	// The value is stored under the namespaced kind, not the bare key, so
	// a different plugin can't see it.
	if _, ok, _ := blobs.Get(blobNamespacePrefix+"aws", "host_key"); !ok {
		t.Fatal("value not stored under the plugin namespace")
	}
	if _, ok, _ := blobs.Get("host_key", "host_key"); ok {
		t.Fatal("value leaked to the bare kind")
	}
}

func TestHostStateNamespaceIsolation(t *testing.T) {
	blobs := newMemBlobs()
	aws := startHostState(t, "aws", blobs)
	evil := startHostState(t, "evil", blobs)
	ctx := context.Background()

	if _, err := aws.Put(ctx, &pb.StatePutRequest{Key: "secret", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	// Same key, different plugin -> not found (separate namespace).
	if r, err := evil.Get(ctx, &pb.StateGetRequest{Key: "secret"}); err != nil || r.Found {
		t.Fatalf("cross-plugin get = %+v err=%v, want not found", r, err)
	}
}

func TestHostStateValidation(t *testing.T) {
	cli := startHostState(t, "p", newMemBlobs())
	ctx := context.Background()

	if _, err := cli.Get(ctx, &pb.StateGetRequest{Key: ""}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty key get err = %v, want InvalidArgument", err)
	}
	if _, err := cli.Put(ctx, &pb.StatePutRequest{Key: "", Value: []byte("v")}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty key put err = %v, want InvalidArgument", err)
	}
	// Over the size cap.
	big := make([]byte, maxStateValueBytes+1)
	if _, err := cli.Put(ctx, &pb.StatePutRequest{Key: "k", Value: big}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversize put err = %v, want InvalidArgument", err)
	}
	// Exactly at the cap is fine.
	if _, err := cli.Put(ctx, &pb.StatePutRequest{Key: "k", Value: make([]byte, maxStateValueBytes)}); err != nil {
		t.Fatalf("at-cap put err = %v, want ok", err)
	}
}

func TestHostStateUnavailableWithoutStore(t *testing.T) {
	cli := startHostState(t, "p", nil) // no blob store wired
	ctx := context.Background()
	if _, err := cli.Get(ctx, &pb.StateGetRequest{Key: "k"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("get without store err = %v, want Unavailable", err)
	}
	if _, err := cli.Put(ctx, &pb.StatePutRequest{Key: "k", Value: []byte("v")}); status.Code(err) != codes.Unavailable {
		t.Fatalf("put without store err = %v, want Unavailable", err)
	}
}
