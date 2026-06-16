package pluginsdk

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// TestSDKTransformHTTP drives the real SDK TransformHTTP handler (the
// plugin-author io.Reader contract) with a hand-written gRPC client,
// exercising the streaming round trip from the plugin side.
func TestSDKTransformHTTP(t *testing.T) {
	var gotBody []byte
	var gotSecret []byte
	p := &Plugin{
		Name: "p",
		Credentials: []CredentialDef{{
			TypeName:      "signer",
			HTTPTransform: true,
			TransformHTTP: func(_ context.Context, req HTTPTransformRequest) (*HTTPTransformResponse, error) {
				b, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				gotBody = b
				gotSecret = req.CredentialSecret
				return &HTTPTransformResponse{
					Headers: []HeaderMutation{{Op: HeaderSet, Name: "X-Signed", Values: []string{"yes"}}},
					Body:    bytes.NewReader(bytes.ToUpper(b)),
				}, nil
			},
		}},
	}
	srv := newServer(p)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	pb.RegisterCredentialServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	stream, err := pb.NewCredentialClient(conn).TransformHTTP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.TransformHTTPUp{Kind: &pb.TransformHTTPUp_Init{Init: &pb.TransformHTTPInit{
		CredentialTypeName: "signer", CredentialInstance: "i", Method: "POST", CredentialSecret: []byte("sec"),
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.TransformHTTPUp{Kind: &pb.TransformHTTPUp_Body{
		Body: &pb.HTTPBodyChunk{Data: []byte("hello"), Eof: true},
	}}); err != nil {
		t.Fatal(err)
	}

	// First reply: the head.
	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	head := first.GetHead()
	if head == nil || len(head.Headers) != 1 || head.Headers[0].Name != "X-Signed" {
		t.Fatalf("head = %+v, want one X-Signed mutation", head)
	}

	// Then the transformed body until eof.
	var out bytes.Buffer
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		b := msg.GetBody()
		if b == nil {
			continue
		}
		out.Write(b.GetData())
		if b.GetEof() {
			break
		}
	}
	if out.String() != "HELLO" {
		t.Fatalf("transformed body = %q, want HELLO", out.String())
	}
	if string(gotBody) != "hello" || string(gotSecret) != "sec" {
		t.Fatalf("plugin saw body=%q secret=%q", gotBody, gotSecret)
	}
}
