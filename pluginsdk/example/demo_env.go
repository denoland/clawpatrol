package main

// demo_env is an example environment plugin demonstrating the v1
// EnvironmentDef shape. The plugin accepts an optional `credential
// = magic_token.<name>` ref so the operator can wire it to the
// matching example credential; the env var it emits is a simple
// literal whose value carries the resolved credential's bare name.
//
// In a real environment plugin, EnvVars would derive its values
// from the credential / endpoint at request time (e.g. derive a
// PG* var bundle from a Postgres endpoint + credential pair, like
// the built-in postgres_environment does).

import (
	"fmt"

	"github.com/denoland/clawpatrol/pluginsdk"
)

func demoEnvDef() pluginsdk.EnvironmentDef {
	return pluginsdk.EnvironmentDef{
		TypeName: "demo_env",
		Schema: pluginsdk.Schema{
			Fields: []pluginsdk.SchemaField{
				{Name: "prefix", TypeString: "string", Required: false},
			},
		},
		AcceptsCredential: true,
		EnvVars: func(req pluginsdk.EnvVarsRequest) ([]pluginsdk.EnvVar, error) {
			// The schema's `prefix` would normally be parsed from
			// req.ConfigJSON; for the demo we hardcode it so the
			// example stays focused on the env-var shape.
			name := "EXAMPLE_DEMO_TOKEN"
			value := fmt.Sprintf("demo-placeholder-for-%s", req.CredentialRef)
			if req.CredentialRef == "" {
				value = "demo-placeholder-unbound"
			}
			return []pluginsdk.EnvVar{
				{
					Name:        name,
					Value:       value,
					Description: "example env var contributed by demo_env",
				},
			}, nil
		},
	}
}
