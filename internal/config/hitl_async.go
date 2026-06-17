package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
)

const (
	// HITLAsyncDefaultApprovedRetryTTL is the default lifetime of the
	// one-shot retry grant after a human approval.
	HITLAsyncDefaultApprovedRetryTTL = 5 * time.Minute
	// HITLAsyncDefaultMaxBodyBytes is the default body size limit for
	// raw-body request fingerprinting.
	HITLAsyncDefaultMaxBodyBytes int64 = 1 << 20
	// HITLAsyncHardMaxBodyBytes caps v1 raw-body fingerprinting so an
	// approver config cannot make Claw Patrol buffer unbounded bodies.
	HITLAsyncHardMaxBodyBytes int64 = 8 << 20
	// HITLAsyncFingerprintRawBody is the only v1 fingerprint mode.
	HITLAsyncFingerprintRawBody = "raw"
)

// HITLAsyncGrantConfig is the optional nested `async_grant { ... }`
// block shared by async-capable HITL approvers. It is schema-only here;
// runtime execution lives in the gateway and endpoint layers.
type HITLAsyncGrantConfig struct {
	// Enabled explicitly opts this approver into async retry-grant mode.
	// The active profile must also set hitl_async_grants = true.
	Enabled bool `hcl:"enabled,optional" json:"enabled,omitempty"`
	// Post-approval retry grant lifetime for the client to retry.
	ApprovedRetryTTL string `hcl:"approved_retry_ttl,optional" json:"approved_retry_ttl,omitempty"`
	// Request-body fingerprinting mode. V1 supports only "raw".
	FingerprintBody string `hcl:"fingerprint_body,optional" json:"fingerprint_body,omitempty"`
	// Maximum request body size eligible for async raw-body fingerprinting.
	MaxBodyBytes *int `hcl:"max_body_bytes,optional" json:"max_body_bytes,omitempty"`
}

// HITLAsyncGrantEnabler is implemented by approver bodies that expose
// whether their config enables async retry-grant behavior. Keeping this
// small avoids a config -> approvers package import cycle.
type HITLAsyncGrantEnabler interface {
	HITLAsyncGrantEnabled() bool
}

// ApprovedRetryTTLDuration parses the approved-retry TTL, falling back
// to HITLAsyncDefaultApprovedRetryTTL when unset.
func (g *HITLAsyncGrantConfig) ApprovedRetryTTLDuration() (time.Duration, error) {
	return parseOptionalPositiveDuration(g, g.approvedRetryTTLRaw(), HITLAsyncDefaultApprovedRetryTTL)
}

// FingerprintBodyValue returns the configured fingerprint body mode,
// defaulting to HITLAsyncFingerprintRawBody when unset.
func (g *HITLAsyncGrantConfig) FingerprintBodyValue() string {
	if g == nil || g.FingerprintBody == "" {
		return HITLAsyncFingerprintRawBody
	}
	return g.FingerprintBody
}

// MaxBodyBytesValue returns the configured max body cap (in bytes),
// defaulting to HITLAsyncDefaultMaxBodyBytes when unset.
func (g *HITLAsyncGrantConfig) MaxBodyBytesValue() int64 {
	if g == nil || g.MaxBodyBytes == nil {
		return HITLAsyncDefaultMaxBodyBytes
	}
	return int64(*g.MaxBodyBytes)
}

func (g *HITLAsyncGrantConfig) approvedRetryTTLRaw() string {
	if g == nil {
		return ""
	}
	return g.ApprovedRetryTTL
}

func parseOptionalPositiveDuration(_ *HITLAsyncGrantConfig, raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	return time.ParseDuration(raw)
}

func normalizePublicURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func validateHITLAsyncConfig(gw *Gateway) hcl.Diagnostics {
	if gw == nil || gw.Policy == nil {
		return nil
	}
	if !policyHasAsyncProfileOptIn(gw.Policy) || !policyHasAsyncApprover(gw.Policy) {
		return nil
	}
	pu := gw.PublicURL()
	if pu == "" {
		return hcl.Diagnostics{&hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Async HITL public_url not configured",
			Detail:   "set gateway.public_url when any profile has hitl_async_grants = true and any approver has async_grant.enabled = true; async status URLs must not be derived from request Host headers.",
		}}
	}
	if err := validateHITLAsyncPublicURL(pu); err != nil {
		return hcl.Diagnostics{&hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid async HITL public_url",
			Detail:   fmt.Sprintf("public_url must be an absolute http or https URL with a host when async HITL grants are enabled: %v", err),
		}}
	}
	return nil
}

func validateHITLAsyncPublicURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("host is empty")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("query strings and fragments are not allowed")
	}
	return nil
}

func policyHasAsyncProfileOptIn(p *Policy) bool {
	for _, profile := range p.Profiles {
		if profile != nil && profile.HITLAsyncGrants {
			return true
		}
	}
	return false
}

func policyHasAsyncApprover(p *Policy) bool {
	for _, ent := range p.Approvers {
		if ent == nil || ent.Body == nil {
			continue
		}
		if reader, ok := ent.Body.(HITLAsyncGrantEnabler); ok && reader.HITLAsyncGrantEnabled() {
			return true
		}
	}
	return false
}

// ValidateHITLAsyncGrant returns HCL diagnostics for an async-grant
// config block. It checks that, when the grant is enabled, the grant's
// TTLs are well-formed. sync_wait_timeout is optional: when set it must
// be a positive duration, but omitting it is valid — the request is then
// parked synchronously for the full approval window with no early 202
// hand-back, and the async retry-grant path simply never activates.
func ValidateHITLAsyncGrant(name string, syncWaitTimeout string, grant *HITLAsyncGrantConfig) hcl.Diagnostics {
	if grant == nil || !grant.Enabled {
		return nil
	}
	var diags hcl.Diagnostics
	if syncWaitTimeout != "" {
		if d, err := time.ParseDuration(syncWaitTimeout); err != nil {
			diags = append(diags, hitlAsyncDiagnostic(name, "invalid sync_wait_timeout", err.Error()))
		} else if d <= 0 {
			diags = append(diags, hitlAsyncDiagnostic(name, "sync_wait_timeout must be positive", "sync_wait_timeout must be greater than zero."))
		}
	}

	if grant.ApprovedRetryTTL != "" {
		if d, err := time.ParseDuration(grant.ApprovedRetryTTL); err != nil {
			diags = append(diags, hitlAsyncDiagnostic(name, "invalid async_grant.approved_retry_ttl", err.Error()))
		} else if d <= 0 {
			diags = append(diags, hitlAsyncDiagnostic(name, "async_grant.approved_retry_ttl must be positive", "approved_retry_ttl must be greater than zero."))
		}
	}
	if got := grant.FingerprintBodyValue(); got != HITLAsyncFingerprintRawBody {
		diags = append(diags, hitlAsyncDiagnostic(name, "async_grant.fingerprint_body must be raw", fmt.Sprintf("v1 supports only fingerprint_body = %q, got %q.", HITLAsyncFingerprintRawBody, got)))
	}
	if grant.MaxBodyBytes != nil {
		maxBody := int64(*grant.MaxBodyBytes)
		if maxBody <= 0 {
			diags = append(diags, hitlAsyncDiagnostic(name, "async_grant.max_body_bytes must be positive", "max_body_bytes must be greater than zero."))
		} else if maxBody > HITLAsyncHardMaxBodyBytes {
			diags = append(diags, hitlAsyncDiagnostic(name, "async_grant.max_body_bytes exceeds hard maximum", fmt.Sprintf("max_body_bytes must be <= %d in v1.", HITLAsyncHardMaxBodyBytes)))
		}
	}
	return diags
}

func hitlAsyncDiagnostic(name, summary, detail string) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  summary,
		Detail:   fmt.Sprintf("approver %q: %s", name, detail),
	}
}
