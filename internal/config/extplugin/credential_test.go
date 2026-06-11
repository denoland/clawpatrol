package extplugin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all" // register built-in plugins
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type credentialPluginTestServer struct {
	pb.UnimplementedPluginServer
	pb.UnimplementedCredentialServer

	typeName string
	metadata *pb.CredentialMetadata
	seen     chan *pb.InjectHTTPRequest
}

func (s *credentialPluginTestServer) Build(_ context.Context, req *pb.BuildRequest) (*pb.BuildResponse, error) {
	if req.Kind != "credential" || req.TypeName != s.typeName {
		return nil, fmt.Errorf("unexpected build request: %s %s", req.Kind, req.TypeName)
	}
	metadata := s.metadata
	if metadata == nil {
		metadata = &pb.CredentialMetadata{
			SecretSlots: []*pb.SecretSlotDecl{{Label: "External token", Description: "stored by gateway"}},
			EnvVars:     []*pb.EnvVarDecl{{Name: "EXTERNAL_TOKEN", Value: "PH_external", Description: "placeholder"}},
			Oauth: &pb.OAuthIntegrationDecl{
				Type:   "oauth2",
				Header: "Authorization",
				Prefix: "Bearer ",
				Flow:   "dynamic_mcp",
				Oauth: &pb.OAuthConfigDecl{
					AuthUrl:     "https://auth.example.test/authorize",
					TokenUrl:    "https://auth.example.test/token",
					RegisterUrl: "https://auth.example.test/register",
					Scopes:      []string{"mcp:read"},
				},
			},
			HttpInject: true,
		}
	}
	return &pb.BuildResponse{
		CanonicalJson:      []byte(`{"built":"yes"}`),
		CredentialMetadata: metadata,
	}, nil
}

func (s *credentialPluginTestServer) InjectHTTP(_ context.Context, req *pb.InjectHTTPRequest) (*pb.InjectHTTPResponse, error) {
	s.seen <- req
	return &pb.InjectHTTPResponse{Headers: []*pb.HeaderMutation{{
		Op:     pb.HeaderMutation_SET,
		Name:   "Authorization",
		Values: []string{"Bearer " + string(req.CredentialSecret)},
	}}}, nil
}

func TestExternalCredentialMetadataAndInjectHTTPAdapter(t *testing.T) {
	typeName := fmt.Sprintf("extplugin_test_cred_%d", time.Now().UnixNano())
	server := &credentialPluginTestServer{typeName: typeName, seen: make(chan *pb.InjectHTTPRequest, 1)}
	client, cleanup := newCredentialPluginTestClient(t, server)
	defer cleanup()

	diags := RegisterManifest(client, &pb.ManifestResponse{
		Name: "extcredtest",
		Credentials: []*pb.CredentialDecl{{
			TypeName:       typeName,
			Schema:         &pb.Schema{},
			Disambiguators: []string{"placeholder"},
			HttpInject:     true,
		}},
	})
	if diags.HasErrors() {
		t.Fatalf("RegisterManifest: %v", diags)
	}
	plug := config.Lookup(config.KindCredential, typeName)
	if plug == nil {
		t.Fatalf("credential plugin %q was not registered", typeName)
	}
	if got := plug.Disambiguators; len(got) != 1 || got[0] != "placeholder" {
		t.Fatalf("Disambiguators = %#v", got)
	}

	hcl := fmt.Sprintf(`
gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential %q "external" {
  endpoint    = https.api
  placeholder = "PH_external"
}
profile "default" { credentials = [%s.external] }
`, typeName, typeName)
	gw, diags := config.LoadBytes([]byte(hcl), "extplugin-credential-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("LoadBytes: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ent := policy.Credentials["external"]
	if ent == nil {
		t.Fatalf("compiled credential missing")
	}
	base, ok := credentialBaseOf(ent.Body)
	if !ok {
		t.Fatalf("credential body type = %T, want dynamic external body", ent.Body)
	}
	if !strings.Contains(string(base.canonicalJSON), `"built":"yes"`) {
		t.Fatalf("canonical json = %s", string(base.canonicalJSON))
	}
	if slots := ent.Body.(config.SecretSlotsProvider).SecretSlots(); len(slots) != 1 || slots[0].Label != "External token" {
		t.Fatalf("secret slots = %#v", slots)
	}
	if env := ent.Body.(config.EnvPushdownProvider).EnvVars(); len(env) != 1 || env[0].Name != "EXTERNAL_TOKEN" || env[0].Value != "PH_external" {
		t.Fatalf("env vars = %#v", env)
	}
	oauthProvider, ok := ent.Body.(config.OAuthFlowProvider)
	if !ok {
		t.Fatalf("credential body does not implement OAuthFlowProvider")
	}
	if flow := oauthProvider.OAuthFlow(); flow == nil || flow.Flow != "dynamic_mcp" || flow.OAuth.TokenURL != "https://auth.example.test/token" {
		t.Fatalf("oauth flow = %#v", flow)
	}
	injector, ok := ent.Body.(runtime.HTTPCredentialRuntime)
	if !ok {
		t.Fatalf("credential body does not implement HTTPCredentialRuntime")
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.example.test/v1", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "api.example.test"
	req.Header.Set("Authorization", "Bearer PH_external")
	if err := injector.InjectHTTP(context.Background(), req, runtime.Secret{Bytes: []byte("real-token")}); err != nil {
		t.Fatalf("InjectHTTP: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer real-token" {
		t.Fatalf("Authorization = %q", got)
	}
	select {
	case got := <-server.seen:
		if got.CredentialTypeName != typeName || got.CredentialInstance != "external" {
			t.Fatalf("InjectHTTP credential = %s/%s", got.CredentialTypeName, got.CredentialInstance)
		}
		if string(got.CredentialSecret) != "real-token" {
			t.Fatalf("CredentialSecret = %q", string(got.CredentialSecret))
		}
		if got.Headers["Authorization"].Values[0] != "Bearer PH_external" {
			t.Fatalf("headers = %#v", got.Headers)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for InjectHTTP RPC")
	}
}

func TestExternalCredentialWithoutHTTPInjectRemainsSchemaOnly(t *testing.T) {
	typeName := fmt.Sprintf("extplugin_test_schema_cred_%d", time.Now().UnixNano())
	server := &credentialPluginTestServer{typeName: typeName, metadata: &pb.CredentialMetadata{}, seen: make(chan *pb.InjectHTTPRequest, 1)}
	client, cleanup := newCredentialPluginTestClient(t, server)
	defer cleanup()

	diags := RegisterManifest(client, &pb.ManifestResponse{
		Name: "extschemaonlytest",
		Credentials: []*pb.CredentialDecl{{
			TypeName: typeName,
			Schema:   &pb.Schema{},
		}},
	})
	if diags.HasErrors() {
		t.Fatalf("RegisterManifest: %v", diags)
	}

	hcl := fmt.Sprintf(`
gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential %q "external" {
  endpoint = https.api
}
profile "default" { credentials = [%s.external] }
`, typeName, typeName)
	gw, diags := config.LoadBytes([]byte(hcl), "extplugin-schema-only-credential-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("LoadBytes: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ent := policy.Credentials["external"]
	if ent == nil {
		t.Fatalf("compiled credential missing")
	}
	if _, ok := ent.Body.(runtime.HTTPCredentialRuntime); ok {
		t.Fatalf("schema-only external credential unexpectedly implements HTTPCredentialRuntime")
	}
	if _, ok := ent.Body.(config.OAuthFlowProvider); ok {
		t.Fatalf("schema-only external credential unexpectedly implements OAuthFlowProvider")
	}
}

func newCredentialPluginTestClient(t *testing.T, srv *credentialPluginTestServer) (*Client, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	pb.RegisterPluginServer(gs, srv)
	pb.RegisterCredentialServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		gs.Stop()
		_ = lis.Close()
		t.Fatalf("NewClient: %v", err)
	}
	client := &Client{
		name:       "extcredtest",
		conn:       conn,
		pluginCli:  pb.NewPluginClient(conn),
		credential: pb.NewCredentialClient(conn),
	}
	cleanup := func() {
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	}
	return client, cleanup
}
