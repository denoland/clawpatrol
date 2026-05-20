package environments

// codex_environment: the synthesized Agent Identity JWT codex-cli
// reads at startup. Mints a fresh RS256-signed JWT on each
// `clawpatrol env` invocation and stamps it into the
// CODEX_ACCESS_TOKEN / CODEX_AGENT_IDENTITY env vars; the matching
// JWKS lives on the openai_codex_https endpoint (which serves it
// at `/backend-api/wham/agent-identities/jwks` for codex to fetch
// during validation). The auth-api base URL override keeps codex's
// agent-task registration POST on a host clawpatrol terminates.
//
// Sample HCL:
//
//	credential "openai_codex_oauth" "codex" {
//	  endpoint = openai_codex_https.codex
//	}
//
//	endpoint "openai_codex_https" "codex" {
//	  hosts = ["chatgpt.com"]
//	}
//
//	environment "codex_environment" "codex-env" {}
//
//	profile "default" {
//	  credentials  = [openai_codex_oauth.codex]
//	  environments = [codex_environment.codex-env]
//	}

import (
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/endpoints"
)

// CodexEnvironment is part of the clawpatrol plugin API.
type CodexEnvironment struct{}

// EnvVars is part of the clawpatrol plugin API.
func (*CodexEnvironment) EnvVars() []config.EnvVar {
	jwt, err := endpoints.MintCodexAccessToken()
	if err != nil {
		// No JWT means CODEX_ACCESS_TOKEN isn't set; codex falls back
		// to its real ~/.codex/auth.json and clawpatrol's MITM still
		// works for users who already ran `codex login`. The auth-api
		// base URL override is still useful — emit it regardless.
		return []config.EnvVar{
			{
				Name:        "CODEX_AGENT_IDENTITY_AUTHAPI_BASE_URL",
				Value:       "https://chatgpt.com/backend-api/wham",
				Description: "keeps agent-task registration on a host clawpatrol MITMs",
			},
		}
	}
	return []config.EnvVar{
		{
			Name:        "CODEX_ACCESS_TOKEN",
			Value:       jwt,
			Description: "synthetic Agent Identity JWT — routes codex >= 0.129 to chatgpt.com",
		},
		{
			Name:        "CODEX_AGENT_IDENTITY",
			Value:       jwt,
			Description: "synthetic Agent Identity JWT — routes codex <= 0.128 to chatgpt.com",
		},
		{
			Name:        "CODEX_AGENT_IDENTITY_AUTHAPI_BASE_URL",
			Value:       "https://chatgpt.com/backend-api/wham",
			Description: "keeps agent-task registration on a host clawpatrol MITMs",
		},
	}
}

func init() {
	var _ config.EnvironmentRuntime = (*CodexEnvironment)(nil)
	config.Register(&config.Plugin{
		Kind:  config.KindEnvironment,
		Type:  "codex_environment",
		New:   newer[CodexEnvironment](),
		Build: passthrough,
		Emit:  emptyEmit,
	})
}
