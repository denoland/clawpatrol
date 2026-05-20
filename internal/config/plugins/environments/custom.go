package environments

// custom_environment: the literal-key/value environment. The
// operator types both the env-var name and its value. This is the
// escape hatch for SDK-specific settings that aren't tied to a
// credential or endpoint (base URLs, region names, feature flags)
// and the only environment plugin that lets the operator name an
// arbitrary env var directly.
//
// Sample HCL:
//
//	environment "custom_environment" "aws-region" {
//	  key   = "AWS_REGION"
//	  value = "us-east-1"
//	}
//
//	environment "custom_environment" "openai-base-url" {
//	  key         = "OPENAI_BASE_URL"
//	  value       = "https://gateway.example.test/openai/v1"
//	  description = "route the OpenAI SDK through the clawpatrol gateway"
//	}

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
)

// CustomEnvironment is part of the clawpatrol plugin API. It carries
// one operator-declared (key, value) pair plus an optional human-
// readable description shown by `clawpatrol env --list`.
type CustomEnvironment struct {
	Key         string `hcl:"key" json:"key"`
	Value       string `hcl:"value" json:"value"`
	Description string `hcl:"description,optional" json:"description,omitempty"`
}

// EnvVars is part of the clawpatrol plugin API.
func (c *CustomEnvironment) EnvVars() []config.EnvVar {
	if c == nil || c.Key == "" {
		return nil
	}
	return []config.EnvVar{
		{Name: c.Key, Value: c.Value, Description: c.Description},
	}
}

func customValidate(decoded any, name string, _ *config.BuildCtx) hcl.Diagnostics {
	c, ok := decoded.(*CustomEnvironment)
	if !ok {
		return nil
	}
	var diags hcl.Diagnostics
	if c.Key == "" {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("environment %q: `key` must be set", name),
		})
	}
	return diags
}

func customEmit(body any, _ string, b *hclwrite.Body) {
	c, ok := body.(*CustomEnvironment)
	if !ok {
		return
	}
	if c.Key != "" {
		b.SetAttributeValue("key", cty.StringVal(c.Key))
	}
	b.SetAttributeValue("value", cty.StringVal(c.Value))
	if c.Description != "" {
		b.SetAttributeValue("description", cty.StringVal(c.Description))
	}
}

func init() {
	var _ config.EnvironmentRuntime = (*CustomEnvironment)(nil)
	config.Register(&config.Plugin{
		Kind:     config.KindEnvironment,
		Type:     "custom_environment",
		New:      newer[CustomEnvironment](),
		Validate: customValidate,
		Build:    passthrough,
		Emit:     customEmit,
	})
}
