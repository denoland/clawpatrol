package extplugin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// testTransformServer is a minimal streaming credential server: it reads
// the whole request body (like a body-signing credential), adds a header,
// and returns the body uppercased — exercising both header mutation and a
// full body rewrite over the real TransformHTTP stream.
type testTransformServer struct {
	pb.UnimplementedCredentialServer
	gotSecret []byte
	gotMethod string
}

func (s *testTransformServer) TransformHTTP(stream pb.Credential_TransformHTTPServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	init := first.GetInit()
	s.gotSecret = init.GetCredentialSecret()
	s.gotMethod = init.GetMethod()

	var body bytes.Buffer
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		b := msg.GetBody()
		if b == nil {
			continue
		}
		body.Write(b.GetData())
		if b.GetEof() {
			break
		}
	}

	if err := stream.Send(&pb.TransformHTTPDown{Kind: &pb.TransformHTTPDown_Head{Head: &pb.TransformHTTPHead{
		Headers:    []*pb.HeaderMutation{{Op: pb.HeaderMutation_SET, Name: "X-Signed", Values: []string{"yes"}}},
		Redactions: []string{"sig-abc"},
	}}}); err != nil {
		return err
	}
	out := bytes.ToUpper(body.Bytes())
	return stream.Send(&pb.TransformHTTPDown{Kind: &pb.TransformHTTPDown_Body{
		Body: &pb.HTTPBodyChunk{Data: out, Eof: true},
	}})
}

func transformTestClient(t *testing.T, srv pb.CredentialServer) pb.CredentialClient {
	t.Helper()
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
	return pb.NewCredentialClient(conn)
}

func TestTransformHTTPRoundTrip(t *testing.T) {
	srv := &testTransformServer{}
	cli := transformTestClient(t, srv)

	body := &dynamicCredentialBody{
		adapter:      &credentialAdapter{client: &Client{credential: cli}, typeName: "signer"},
		instanceName: "inst",
		metadata:     credentialMetadata{httpTransform: true},
	}
	u, _ := url.Parse("https://api.example.com/things")
	req := &http.Request{
		Method: "POST",
		URL:    u,
		Host:   "api.example.com",
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("hello world")),
	}

	if err := transformHTTPWithExternalCredential(context.Background(), body, req, runtime.Secret{Bytes: []byte("topsecret")}); err != nil {
		t.Fatalf("transform: %v", err)
	}

	// Header mutation applied before forwarding.
	if got := req.Header.Get("X-Signed"); got != "yes" {
		t.Fatalf("X-Signed = %q, want yes", got)
	}
	// The plugin saw the init (secret + method).
	if string(srv.gotSecret) != "topsecret" || srv.gotMethod != "POST" {
		t.Fatalf("server saw secret=%q method=%q", srv.gotSecret, srv.gotMethod)
	}
	// The forwarded body is the plugin's transformed stream.
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read transformed body: %v", err)
	}
	if string(got) != "HELLO WORLD" {
		t.Fatalf("transformed body = %q, want HELLO WORLD", got)
	}
	// Redaction recorded for audit masking.
	if r := consumeHTTPRedactions(body, req); len(r) != 1 || r[0] != "sig-abc" {
		t.Fatalf("redactions = %v, want [sig-abc]", r)
	}
}

// TestTransformHTTPPassThrough checks a credential that only rewrites the
// URL and streams the body through unchanged (no buffering of the body on
// the plugin side beyond a copy).
func TestTransformHTTPPassThrough(t *testing.T) {
	cli := transformTestClient(t, &passthroughURLServer{})
	body := &dynamicCredentialBody{
		adapter:      &credentialAdapter{client: &Client{credential: cli}, typeName: "urlcred"},
		instanceName: "inst",
		metadata:     credentialMetadata{httpTransform: true},
	}
	u, _ := url.Parse("https://api.example.com/bot-PLACEHOLDER/send")
	req := &http.Request{
		Method: "POST", URL: u, Host: "api.example.com", Header: http.Header{},
		Body: io.NopCloser(strings.NewReader("the body streams through")),
	}
	if err := transformHTTPWithExternalCredential(context.Background(), body, req, runtime.Secret{Bytes: []byte("tok")}); err != nil {
		t.Fatalf("transform: %v", err)
	}
	if req.URL.Path != "/bot-tok/send" {
		t.Fatalf("url path = %q, want /bot-tok/send", req.URL.Path)
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != "the body streams through" {
		t.Fatalf("body = %q, want unchanged", got)
	}
}

// errBeforeHeadServer reads the init then closes the stream with an error
// without ever sending a head — modeling a buggy plugin.
type errBeforeHeadServer struct {
	pb.UnimplementedCredentialServer
}

func (errBeforeHeadServer) TransformHTTP(stream pb.Credential_TransformHTTPServer) error {
	_, _ = stream.Recv()
	return fmt.Errorf("plugin boom")
}

// TestTransformHTTPErrorFailsClosed confirms a plugin error surfaces as an
// error from the transform call (so the gateway fails closed) rather than
// hanging or silently forwarding.
func TestTransformHTTPErrorFailsClosed(t *testing.T) {
	cli := transformTestClient(t, errBeforeHeadServer{})
	body := &dynamicCredentialBody{
		adapter:      &credentialAdapter{client: &Client{credential: cli}, typeName: "x"},
		instanceName: "i",
		metadata:     credentialMetadata{httpTransform: true},
	}
	u, _ := url.Parse("https://api.example.com/x")
	req := &http.Request{
		Method: "POST", URL: u, Host: "api.example.com", Header: http.Header{},
		Body: io.NopCloser(strings.NewReader("data")),
	}
	err := transformHTTPWithExternalCredential(context.Background(), body, req, runtime.Secret{})
	if err == nil {
		t.Fatal("expected an error so the caller fails closed")
	}
}

// TestRewritesHTTPRequestMarker confirms only transform credentials report
// as request rewriters (the gateway uses this to fail closed on error).
func TestRewritesHTTPRequestMarker(t *testing.T) {
	transform := &dynamicCredentialBody{metadata: credentialMetadata{httpTransform: true}}
	headerOnly := &dynamicCredentialBody{metadata: credentialMetadata{httpInject: true}}
	if !transform.RewritesHTTPRequest() {
		t.Fatal("transform credential should report RewritesHTTPRequest")
	}
	if headerOnly.RewritesHTTPRequest() {
		t.Fatal("header-only credential must not report RewritesHTTPRequest")
	}
}

// passthroughURLServer rewrites the URL (swapping a placeholder for the
// secret) and echoes body chunks straight back as it receives them.
type passthroughURLServer struct {
	pb.UnimplementedCredentialServer
}

func (passthroughURLServer) TransformHTTP(stream pb.Credential_TransformHTTPServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	init := first.GetInit()
	newURL := strings.ReplaceAll(init.GetUrl(), "PLACEHOLDER", string(init.GetCredentialSecret()))
	if err := stream.Send(&pb.TransformHTTPDown{Kind: &pb.TransformHTTPDown_Head{Head: &pb.TransformHTTPHead{
		Url: &newURL,
	}}}); err != nil {
		return err
	}
	// Echo body chunks straight through.
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		b := msg.GetBody()
		if b == nil {
			continue
		}
		if err := stream.Send(&pb.TransformHTTPDown{Kind: &pb.TransformHTTPDown_Body{Body: b}}); err != nil {
			return err
		}
		if b.GetEof() {
			return nil
		}
	}
}
