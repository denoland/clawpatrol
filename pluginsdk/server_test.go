package pluginsdk

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

func TestServerCredentialMetadataAndInjectHTTP(t *testing.T) {
	var sawInject bool
	srv := newServer(&Plugin{
		Name:    "testplugin",
		Version: "0.1.0",
		Credentials: []CredentialDef{{
			TypeName:       "example_bearer",
			Disambiguators: []string{"placeholder"},
			HTTPInject:     true,
			Build: func(req BuildRequest) (any, error) {
				return CredentialBuildResult{
					Canonical: map[string]string{"instance": req.InstanceName},
					Metadata: CredentialMetadata{
						SecretSlots: []SecretSlot{{Label: "Bearer token", Description: "stored by gateway"}},
						EnvVars:     []EnvVar{{Name: "EXAMPLE_TOKEN", Value: "PH_example", Description: "placeholder"}},
						OAuth: &OAuthIntegration{
							Type:   "oauth2",
							Header: "Authorization",
							Prefix: "Bearer ",
							Flow:   "dynamic_mcp",
							OAuth: OAuthConfig{
								AuthURL:     "https://auth.example.test/authorize",
								TokenURL:    "https://auth.example.test/token",
								RegisterURL: "https://auth.example.test/register",
								Scopes:      []string{"mcp:read"},
							},
						},
						HTTPInject: true,
					},
				}, nil
			},
			InjectHTTP: func(_ context.Context, req HTTPInjectRequest) (*HTTPInjectResponse, error) {
				sawInject = true
				if req.CredentialTypeName != "example_bearer" {
					t.Fatalf("CredentialTypeName = %q", req.CredentialTypeName)
				}
				if req.CredentialInstance != "example" {
					t.Fatalf("CredentialInstance = %q", req.CredentialInstance)
				}
				if string(req.CredentialSecret) != "real-token" {
					t.Fatalf("CredentialSecret = %q", string(req.CredentialSecret))
				}
				if got := req.Headers.Get("Authorization"); got != "Bearer PH_example" {
					t.Fatalf("Authorization header = %q", got)
				}
				return &HTTPInjectResponse{
					Headers:    []HeaderMutation{{Op: HeaderSet, Name: "Authorization", Values: []string{"Bearer real-token"}}},
					Redactions: []string{"real-token"},
				}, nil
			},
		}},
	})

	manifest, err := srv.Manifest(context.Background(), &pb.ManifestRequest{})
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if len(manifest.Credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(manifest.Credentials))
	}
	decl := manifest.Credentials[0]
	if !decl.HttpInject {
		t.Fatalf("HttpInject = false, want true")
	}
	if got := decl.Disambiguators; len(got) != 1 || got[0] != "placeholder" {
		t.Fatalf("Disambiguators = %#v", got)
	}

	built, err := srv.Build(context.Background(), &pb.BuildRequest{
		Kind:         "credential",
		TypeName:     "example_bearer",
		InstanceName: "example",
		ConfigJson:   []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(built.Diagnostics) > 0 {
		t.Fatalf("Build diagnostics = %#v", built.Diagnostics)
	}
	var canonical map[string]string
	if err := json.Unmarshal(built.CanonicalJson, &canonical); err != nil {
		t.Fatalf("canonical json: %v", err)
	}
	if canonical["instance"] != "example" {
		t.Fatalf("canonical = %#v", canonical)
	}
	meta := built.CredentialMetadata
	if meta == nil {
		t.Fatalf("missing credential metadata")
	}
	if !meta.HttpInject || len(meta.SecretSlots) != 1 || len(meta.EnvVars) != 1 || meta.Oauth == nil {
		t.Fatalf("metadata = %#v", meta)
	}
	if got := meta.Oauth.Flow; got != "dynamic_mcp" {
		t.Fatalf("oauth flow = %q", got)
	}

	out, err := srv.InjectHTTP(context.Background(), &pb.InjectHTTPRequest{
		CredentialTypeName:      "example_bearer",
		CredentialInstance:      "example",
		CredentialCanonicalJson: built.CanonicalJson,
		CredentialSecret:        []byte("real-token"),
		Method:                  http.MethodGet,
		Url:                     "https://api.example.test/v1",
		Host:                    "api.example.test",
		Headers: map[string]*pb.HTTPHeaderValues{
			"Authorization": {Values: []string{"Bearer PH_example"}},
		},
	})
	if err != nil {
		t.Fatalf("InjectHTTP: %v", err)
	}
	if !sawInject {
		t.Fatalf("InjectHTTP callback was not called")
	}
	if len(out.Headers) != 1 || out.Headers[0].Op != pb.HeaderMutation_SET || out.Headers[0].Values[0] != "Bearer real-token" {
		t.Fatalf("header mutations = %#v", out.Headers)
	}
	if len(out.Redactions) != 1 || out.Redactions[0] != "real-token" {
		t.Fatalf("redactions = %#v", out.Redactions)
	}
}

func TestServerCredentialBuildPlainCanonicalRemainsBackwardCompatible(t *testing.T) {
	srv := newServer(&Plugin{
		Name: "testplugin",
		Credentials: []CredentialDef{{
			TypeName: "legacy_credential",
			Build: func(BuildRequest) (any, error) {
				return map[string]string{"legacy": "ok"}, nil
			},
		}},
	})
	built, err := srv.Build(context.Background(), &pb.BuildRequest{Kind: "credential", TypeName: "legacy_credential", ConfigJson: []byte(`{}`)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built.CredentialMetadata != nil && (built.CredentialMetadata.HttpInject || len(built.CredentialMetadata.EnvVars) > 0) {
		t.Fatalf("unexpected metadata for legacy build: %#v", built.CredentialMetadata)
	}
	var canonical map[string]string
	if err := json.Unmarshal(built.CanonicalJson, &canonical); err != nil {
		t.Fatalf("canonical json: %v", err)
	}
	if canonical["legacy"] != "ok" {
		t.Fatalf("canonical = %#v", canonical)
	}
}

func TestConnCredentialsFromProto(t *testing.T) {
	if got := connCredentialsFromProto(nil); got != nil {
		t.Errorf("nil input = %v, want nil", got)
	}
	in := []*pb.BoundCredential{
		nil, // skipped
		{TypeName: "aws_account", Instance: "prod", Secret: []byte("s"), Extras: map[string]string{"access_key_id": "AKIA"}, CanonicalJson: []byte(`{"accounts":["111"]}`)},
		{TypeName: "aws_account", Instance: "fallback"},
	}
	got := connCredentialsFromProto(in)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (nil skipped)", len(got))
	}
	if got[0].TypeName != "aws_account" || got[0].Instance != "prod" ||
		string(got[0].Secret) != "s" || got[0].Extras["access_key_id"] != "AKIA" ||
		string(got[0].CanonicalConfig) != `{"accounts":["111"]}` {
		t.Errorf("first credential mapped wrong: %+v", got[0])
	}
	if got[1].Instance != "fallback" {
		t.Errorf("second credential = %+v, want instance fallback", got[1])
	}
}
