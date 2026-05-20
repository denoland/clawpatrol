package environments

// gemini_environment: env vars the Gemini SDKs read. The bound
// gemini_api_key credential supplies the real key at MITM time;
// these placeholders are token-shaped enough to satisfy the SDK's
// startup validation.

import "github.com/denoland/clawpatrol/internal/config"

// GeminiEnvironment is part of the clawpatrol plugin API.
type GeminiEnvironment struct{}

// EnvVars is part of the clawpatrol plugin API.
func (*GeminiEnvironment) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "GOOGLE_API_KEY", Value: phGemini, Description: "Gemini SDKs"},
		{Name: "GEMINI_API_KEY", Value: phGemini, Description: "Gemini CLI"},
	}
}

func init() {
	var _ config.EnvironmentRuntime = (*GeminiEnvironment)(nil)
	config.Register(&config.Plugin{
		Kind:  config.KindEnvironment,
		Type:  "gemini_environment",
		New:   newer[GeminiEnvironment](),
		Build: passthrough,
		Emit:  emptyEmit,
	})
}
