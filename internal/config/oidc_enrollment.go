package config

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// OIDCEnrollment configures an OIDC issuer and claim matcher for ephemeral enrollment.
type OIDCEnrollment struct {
	Issuer   string         `json:"issuer"`
	Profile  string         `json:"profile"`
	TTL      string         `json:"ttl"`
	MaxTTL   string         `json:"max_ttl"`
	Match    map[string]any `json:"match"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type oidcEnrollmentBody struct {
	Issuer   string    `hcl:"issuer"`
	Profile  string    `hcl:"profile"`
	TTL      string    `hcl:"ttl"`
	MaxTTL   string    `hcl:"max_ttl"`
	Match    cty.Value `hcl:"match"`
	Metadata cty.Value `hcl:"metadata,optional"`
}

func init() {
	Register(&Plugin{
		Kind:     KindEnrollment,
		Type:     "oidc",
		New:      func() any { return new(oidcEnrollmentBody) },
		Validate: validateOIDCEnrollment,
		Build:    buildOIDCEnrollment,
		Emit:     emitOIDCEnrollment,
	})
}

// NormalizePublicURLForOIDC normalizes the gateway public URL used as the expected OIDC audience.
func NormalizePublicURLForOIDC(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("public_url is required")
	}
	normalized := strings.TrimRight(trimmed, "/")
	if normalized == "" {
		return "", fmt.Errorf("public_url is required")
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("public_url must be an absolute HTTPS URL")
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("public_url must use https when OIDC enrollment is configured")
	}
	return normalized, nil
}

func validateOIDCEnrollmentsForGateway(gw *Gateway) hcl.Diagnostics {
	if gw == nil || gw.Policy == nil || len(gw.Policy.Enrollments) == 0 {
		return nil
	}
	normalized, err := NormalizePublicURLForOIDC(gw.PublicURL())
	if err != nil {
		return hcl.Diagnostics{&hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid OIDC enrollment public_url",
			Detail:   fmt.Sprintf("OIDC enrollment uses public_url as its expected audience: %v.", err),
		}}
	}
	gw.SetPublicURL(normalized)
	return nil
}

func validateOIDCEnrollment(decoded any, name string, ctx *BuildCtx) hcl.Diagnostics {
	body := decoded.(*oidcEnrollmentBody)
	var diags hcl.Diagnostics

	if body.Issuer == "" {
		diags = append(diags, oidcDiag(ctx, "Missing OIDC issuer", fmt.Sprintf("enrollment %q requires issuer.", name)))
	}
	if strings.TrimSpace(body.Profile) == "" {
		diags = append(diags, oidcDiag(ctx, "Missing OIDC enrollment profile", fmt.Sprintf("enrollment %q requires profile.", name)))
	} else {
		profSym := ctx.Symbols.Get(KindProfile, body.Profile)
		if profSym == nil {
			diags = append(diags, oidcDiag(ctx, "Unknown OIDC enrollment profile", fmt.Sprintf("enrollment %q targets profile %q which is not declared.", name, body.Profile)))
		} else if prof, ok := ctx.Policy.Profiles[body.Profile]; ok && !prof.AllowEphemeralOIDC {
			diags = append(diags, oidcDiag(ctx, "Profile does not allow OIDC enrollment", fmt.Sprintf("profile %q must set allow_ephemeral_oidc = true before OIDC enrollment can target it.", body.Profile)))
		}
	}

	ttl, ttlErr := time.ParseDuration(body.TTL)
	if body.TTL == "" || ttlErr != nil || ttl <= 0 {
		diags = append(diags, oidcDiag(ctx, "Invalid OIDC enrollment ttl", "ttl must be a positive Go duration string such as \"1h\"."))
	}
	maxTTL, maxTTLErr := time.ParseDuration(body.MaxTTL)
	if body.MaxTTL == "" || maxTTLErr != nil || maxTTL <= 0 {
		diags = append(diags, oidcDiag(ctx, "Invalid OIDC enrollment max_ttl", "max_ttl must be a positive Go duration string such as \"2h\"."))
	}
	if ttlErr == nil && maxTTLErr == nil && ttl > 0 && maxTTL > 0 && ttl > maxTTL {
		diags = append(diags, oidcDiag(ctx, "OIDC enrollment ttl exceeds max_ttl", "ttl must be less than or equal to max_ttl."))
	}

	match, err := ctyObjectToScalarMap(body.Match)
	if err != nil || len(match) == 0 {
		diags = append(diags, oidcDiag(ctx, "Invalid OIDC enrollment match", "match must contain at least one scalar or list-of-scalar claim constraint."))
	}
	if body.Metadata.IsKnown() && !body.Metadata.IsNull() {
		if _, err := ctyObjectToScalarMap(body.Metadata); err != nil {
			diags = append(diags, oidcDiag(ctx, "Invalid OIDC enrollment metadata", "metadata must be a map of scalar or list-of-scalar values."))
		}
	}
	return diags
}

func buildOIDCEnrollment(decoded any, _ string, _ *BuildCtx) (any, hcl.Diagnostics) {
	body := decoded.(*oidcEnrollmentBody)
	match, err := ctyObjectToScalarMap(body.Match)
	if err != nil {
		return nil, hcl.Diagnostics{&hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Invalid OIDC enrollment match", Detail: err.Error()}}
	}
	metadata := map[string]any(nil)
	if body.Metadata.IsKnown() && !body.Metadata.IsNull() {
		metadata, err = ctyObjectToScalarMap(body.Metadata)
		if err != nil {
			return nil, hcl.Diagnostics{&hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Invalid OIDC enrollment metadata", Detail: err.Error()}}
		}
	}
	return &OIDCEnrollment{
		Issuer:   body.Issuer,
		Profile:  body.Profile,
		TTL:      body.TTL,
		MaxTTL:   body.MaxTTL,
		Match:    match,
		Metadata: metadata,
	}, nil
}

func emitOIDCEnrollment(body any, _ string, b *hclwrite.Body) {
	oe := body.(*OIDCEnrollment)
	b.SetAttributeValue("issuer", cty.StringVal(oe.Issuer))
	b.SetAttributeValue("profile", cty.StringVal(oe.Profile))
	b.SetAttributeValue("ttl", cty.StringVal(oe.TTL))
	b.SetAttributeValue("max_ttl", cty.StringVal(oe.MaxTTL))
	b.SetAttributeValue("match", mapToCtyObject(oe.Match))
	if len(oe.Metadata) > 0 {
		b.SetAttributeValue("metadata", mapToCtyObject(oe.Metadata))
	}
}

func oidcDiag(ctx *BuildCtx, summary, detail string) *hcl.Diagnostic {
	d := &hcl.Diagnostic{Severity: hcl.DiagError, Summary: summary, Detail: detail}
	if ctx != nil && ctx.Block != nil {
		d.Subject = &ctx.Block.DefRange
	}
	return d
}

func ctyObjectToScalarMap(v cty.Value) (map[string]any, error) {
	if !v.IsKnown() || v.IsNull() || !v.Type().IsObjectType() && !v.Type().IsMapType() {
		return nil, fmt.Errorf("value must be an object")
	}
	out := map[string]any{}
	it := v.ElementIterator()
	for it.Next() {
		k, val := it.Element()
		converted, err := ctyScalarOrListToAny(val)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k.AsString(), err)
		}
		out[k.AsString()] = converted
	}
	return out, nil
}

func ctyScalarOrListToAny(v cty.Value) (any, error) {
	if !v.IsKnown() || v.IsNull() {
		return nil, fmt.Errorf("value must be known and non-null")
	}
	if v.Type() == cty.String {
		return v.AsString(), nil
	}
	if v.Type() == cty.Bool {
		return v.True(), nil
	}
	if v.Type().IsListType() || v.Type().IsTupleType() || v.Type().IsSetType() {
		var out []string
		it := v.ElementIterator()
		for it.Next() {
			_, elem := it.Element()
			if elem.Type() != cty.String {
				return nil, fmt.Errorf("list values must be strings")
			}
			out = append(out, elem.AsString())
		}
		return out, nil
	}
	return nil, fmt.Errorf("value must be a string, bool, or list of strings")
}

func mapToCtyObject(m map[string]any) cty.Value {
	vals := make(map[string]cty.Value, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			vals[k] = cty.StringVal(v)
		case bool:
			vals[k] = cty.BoolVal(v)
		case []string:
			vals[k] = StringListVal(v)
		case []any:
			strings := make([]string, 0, len(v))
			for _, elem := range v {
				strings = append(strings, fmt.Sprint(elem))
			}
			vals[k] = StringListVal(strings)
		default:
			vals[k] = cty.StringVal(fmt.Sprint(v))
		}
	}
	return cty.ObjectVal(vals)
}
