package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// magicToken is the credential type the example plugin's endpoints
// consume. The token bytes themselves live in the gateway's secret
// store (looked up by the credential's instance name); the only HCL
// attribute we accept is the header name to inject (HTTPS endpoint)
// or compare against (SMTP endpoint, echo endpoint prefix).
type magicToken struct {
	HeaderName string `json:"header_name"`
}

func magicTokenDef() pluginsdk.CredentialDef {
	return pluginsdk.CredentialDef{
		TypeName:       "example_magic_token",
		Disambiguators: []string{"placeholder"},
		HTTPInject:     true,
		Schema: pluginsdk.Schema{Fields: []pluginsdk.SchemaField{
			{Name: "header_name", TypeString: "string"},
		}},
		Build: func(req pluginsdk.BuildRequest) (any, error) {
			var c magicToken
			if err := req.Decode(&c); err != nil {
				return nil, err
			}
			if c.HeaderName == "" {
				c.HeaderName = "X-Magic"
			}
			return pluginsdk.CredentialBuildResult{
				Canonical: c,
				Metadata: pluginsdk.CredentialMetadata{
					SecretSlots: []pluginsdk.SecretSlot{{Label: "Magic token", Description: "Stored by the gateway and injected into the configured header."}},
					EnvVars:     []pluginsdk.EnvVar{{Name: "EXAMPLE_MAGIC_TOKEN", Value: "PH_example_magic", Description: "Example placeholder token for built-in HTTPS injection."}},
					HTTPInject:  true,
				},
			}, nil
		},
		InjectHTTP: func(_ context.Context, req pluginsdk.HTTPInjectRequest) (*pluginsdk.HTTPInjectResponse, error) {
			headerName := "X-Magic"
			if len(req.CredentialCanonicalConfig) > 0 {
				var c magicToken
				if err := json.Unmarshal(req.CredentialCanonicalConfig, &c); err == nil && c.HeaderName != "" {
					headerName = c.HeaderName
				}
			}
			if http.CanonicalHeaderKey(headerName) == "Authorization" {
				return &pluginsdk.HTTPInjectResponse{Headers: []pluginsdk.HeaderMutation{{
					Op:     pluginsdk.HeaderSet,
					Name:   headerName,
					Values: []string{"Bearer " + string(req.CredentialSecret)},
				}}}, nil
			}
			return &pluginsdk.HTTPInjectResponse{Headers: []pluginsdk.HeaderMutation{{
				Op:     pluginsdk.HeaderSet,
				Name:   headerName,
				Values: []string{string(req.CredentialSecret)},
			}}}, nil
		},
	}
}
