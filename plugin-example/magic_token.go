package main

import "github.com/denoland/clawpatrol/pluginsdk"

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
		TypeName: "magic_token",
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
			return c, nil
		},
	}
}
