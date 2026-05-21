package config_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

func TestHITLAsyncConfigLoadsProfileApproverAndNormalizesPublicURL(t *testing.T) {
	src := `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.test/"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential "bearer_token" "pat" {
  endpoint = https.api
}
profile "agent" {
  credentials       = [bearer_token.pat]
  hitl_async_grants = true
}
approver "human_approver" "ops" {
  channel           = "#ops"
  sync_wait_timeout = "90s"
  async_grant {
    enabled            = true
    approval_ttl       = "15m"
    approved_retry_ttl = "5m"
    fingerprint_body   = "raw"
    max_body_bytes     = 1048576
  }
}
rule "writes" {
  endpoint = https.api
  approve  = [human_approver.ops]
}
`
	gw, diags := config.LoadBytes([]byte(src), "hitl_async.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if gw.PublicURL() != "https://clawpatrol.example.test" {
		t.Fatalf("PublicURL = %q, want trailing slash stripped", gw.PublicURL())
	}
	if !gw.Policy.Profiles["agent"].HITLAsyncGrants {
		t.Fatal("profile HITLAsyncGrants = false, want true")
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !cp.Profiles["agent"].HITLAsyncGrants {
		t.Fatal("compiled profile HITLAsyncGrants = false, want true")
	}

	reader, ok := gw.Policy.Approvers["ops"].Body.(interface {
		HITLAsyncGrantEnabled() bool
		HITLSyncWaitTimeout() time.Duration
		HITLAsyncApprovalTTL() time.Duration
		HITLAsyncApprovedRetryTTL() time.Duration
		HITLAsyncMaxBodyBytes() int64
		HITLAsyncFingerprintBody() string
	})
	if !ok {
		t.Fatalf("human approver body does not expose async HITL reader: %T", gw.Policy.Approvers["ops"].Body)
	}
	if !reader.HITLAsyncGrantEnabled() {
		t.Fatal("async grant disabled, want enabled")
	}
	if got := reader.HITLSyncWaitTimeout(); got != 90*time.Second {
		t.Fatalf("sync wait timeout = %v, want 90s", got)
	}
	if got := reader.HITLAsyncApprovalTTL(); got != 15*time.Minute {
		t.Fatalf("approval ttl = %v, want 15m", got)
	}
	if got := reader.HITLAsyncApprovedRetryTTL(); got != 5*time.Minute {
		t.Fatalf("approved retry ttl = %v, want 5m", got)
	}
	if got := reader.HITLAsyncMaxBodyBytes(); got != 1048576 {
		t.Fatalf("max body bytes = %d, want 1048576", got)
	}
	if got := reader.HITLAsyncFingerprintBody(); got != "raw" {
		t.Fatalf("fingerprint body = %q, want raw", got)
	}
}

func TestHITLAsyncConfigRequiresValidPublicURLWhenEffective(t *testing.T) {
	for _, tc := range []struct {
		name      string
		publicURL string
		want      string
	}{
		{name: "missing", publicURL: "", want: "Async HITL public_url not configured"},
		{name: "relative", publicURL: "not-a-url", want: "Invalid async HITL public_url"},
		{name: "hostless", publicURL: "https://", want: "Invalid async HITL public_url"},
		{name: "unsupported scheme", publicURL: "ftp://clawpatrol.example.test", want: "Invalid async HITL public_url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := hitlAsyncConfigSource(tc.publicURL, true, true, "90s", `enabled = true`)
			_, diags := config.LoadBytes([]byte(src), tc.name+".hcl")
			if !diags.HasErrors() {
				t.Fatal("load succeeded, want public_url diagnostic")
			}
			if !diagnosticsContain(diags, tc.want) {
				t.Fatalf("diagnostics did not mention %q:\n%v", tc.want, diags)
			}
		})
	}
}

func TestHITLAsyncConfigDoesNotRequirePublicURLWithoutDualOptIn(t *testing.T) {
	for _, tc := range []struct {
		name           string
		profileOptIn   bool
		approverOptIn  bool
		syncWait       string
		asyncGrantBody string
	}{
		{name: "profile only", profileOptIn: true},
		{name: "approver block disabled", profileOptIn: true, approverOptIn: true, syncWait: "90s", asyncGrantBody: `enabled = false`},
		{name: "approver only", approverOptIn: true, syncWait: "90s", asyncGrantBody: `enabled = true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := hitlAsyncConfigSource("", tc.profileOptIn, tc.approverOptIn, tc.syncWait, tc.asyncGrantBody)
			_, diags := config.LoadBytes([]byte(src), tc.name+".hcl")
			if diags.HasErrors() {
				t.Fatalf("load: %v", diags)
			}
		})
	}
}

func TestHITLAsyncConfigReaderDefaultsWithoutAsyncGrant(t *testing.T) {
	src := hitlAsyncConfigSource("", false, false, "", "")
	gw, diags := config.LoadBytes([]byte(src), "sync_only.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	reader, ok := gw.Policy.Approvers["ops"].Body.(interface {
		HITLAsyncGrantEnabled() bool
		HITLSyncWaitTimeout() time.Duration
		HITLAsyncApprovalTTL() time.Duration
		HITLAsyncApprovedRetryTTL() time.Duration
		HITLAsyncMaxBodyBytes() int64
		HITLAsyncFingerprintBody() string
	})
	if !ok {
		t.Fatalf("human approver body does not expose async HITL reader: %T", gw.Policy.Approvers["ops"].Body)
	}
	if reader.HITLAsyncGrantEnabled() {
		t.Fatal("async grant enabled, want disabled")
	}
	if got := reader.HITLSyncWaitTimeout(); got != 0 {
		t.Fatalf("sync wait timeout = %v, want 0", got)
	}
	if got := reader.HITLAsyncApprovalTTL(); got != config.HITLAsyncDefaultApprovalTTL {
		t.Fatalf("approval ttl = %v, want default", got)
	}
	if got := reader.HITLAsyncApprovedRetryTTL(); got != config.HITLAsyncDefaultApprovedRetryTTL {
		t.Fatalf("approved retry ttl = %v, want default", got)
	}
	if got := reader.HITLAsyncMaxBodyBytes(); got != config.HITLAsyncDefaultMaxBodyBytes {
		t.Fatalf("max body bytes = %d, want default", got)
	}
	if got := reader.HITLAsyncFingerprintBody(); got != config.HITLAsyncFingerprintRawBody {
		t.Fatalf("fingerprint body = %q, want raw", got)
	}
}

func TestHITLAsyncConfigRequiresSyncWaitTimeoutWhenEnabled(t *testing.T) {
	src := hitlAsyncConfigSource("https://clawpatrol.example.test", true, true, "", `enabled = true`)
	_, diags := config.LoadBytes([]byte(src), "missing_sync_wait_timeout.hcl")
	if !diags.HasErrors() {
		t.Fatal("load succeeded, want missing sync_wait_timeout diagnostic")
	}
	if !diagnosticsContain(diags, "sync_wait_timeout is required") {
		t.Fatalf("diagnostics did not mention sync_wait_timeout requirement:\n%v", diags)
	}
}

func TestHITLAsyncConfigRejectsInvalidApproverValues(t *testing.T) {
	src := `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential "bearer_token" "pat" {
  endpoint = https.api
}
profile "agent" {
  credentials       = [bearer_token.pat]
  hitl_async_grants = true
}
approver "human_approver" "ops" {
  channel           = "#ops"
  sync_wait_timeout = "0s"
  async_grant {
    enabled            = true
    approval_ttl       = "nope"
    approved_retry_ttl = "0s"
    fingerprint_body   = "json"
    max_body_bytes     = 0
  }
}
rule "writes" {
  endpoint = https.api
  approve  = [human_approver.ops]
}
`
	_, diags := config.LoadBytes([]byte(src), "invalid_async.hcl")
	if !diags.HasErrors() {
		t.Fatal("load succeeded, want invalid async HITL diagnostics")
	}
	for _, want := range []string{
		"sync_wait_timeout must be positive",
		"invalid async_grant.approval_ttl",
		"async_grant.approved_retry_ttl must be positive",
		"async_grant.fingerprint_body must be raw",
		"async_grant.max_body_bytes must be positive",
	} {
		if !diagnosticsContain(diags, want) {
			t.Fatalf("diagnostics missing %q:\n%v", want, diags)
		}
	}
}

func TestHITLAsyncConfigRejectsMaxBodyBytesAboveHardLimit(t *testing.T) {
	src := hitlAsyncConfigSource(
		"https://clawpatrol.example.test",
		true,
		true,
		"90s",
		fmt.Sprintf("enabled = true\n    max_body_bytes = %d", config.HITLAsyncHardMaxBodyBytes+1),
	)
	_, diags := config.LoadBytes([]byte(src), "oversize_body_limit.hcl")
	if !diags.HasErrors() {
		t.Fatal("load succeeded, want max_body_bytes hard limit diagnostic")
	}
	if !diagnosticsContain(diags, "async_grant.max_body_bytes exceeds hard maximum") {
		t.Fatalf("diagnostics did not mention max_body_bytes hard limit:\n%v", diags)
	}
}

func hitlAsyncConfigSource(publicURL string, profileOptIn, includeAsyncGrant bool, syncWaitTimeout, asyncGrantBody string) string {
	var b strings.Builder
	b.WriteString("gateway {\n  state_dir = \"/opt/clawpatrol\"\n")
	if publicURL != "" {
		fmt.Fprintf(&b, "  public_url = %q\n", publicURL)
	}
	// Use tailscale here so the WG dial-target requirement
	// (public_url or wireguard.endpoint) doesn't add noise to
	// publicURL-omitted test cases.
	b.WriteString("  tailscale { authkey = \"tskey-test\" }\n}\n\n")
	b.WriteString(`endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential "bearer_token" "pat" {
  endpoint = https.api
}
profile "agent" {
  credentials = [bearer_token.pat]
`)
	if profileOptIn {
		b.WriteString("  hitl_async_grants = true\n")
	}
	b.WriteString(`}
approver "human_approver" "ops" {
  channel = "#ops"
`)
	if syncWaitTimeout != "" {
		fmt.Fprintf(&b, "  sync_wait_timeout = %q\n", syncWaitTimeout)
	}
	if includeAsyncGrant {
		b.WriteString("  async_grant {\n")
		if asyncGrantBody != "" {
			for _, line := range strings.Split(asyncGrantBody, "\n") {
				if line == "" {
					b.WriteByte('\n')
					continue
				}
				b.WriteString("    ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
		b.WriteString("  }\n")
	}
	b.WriteString(`}
rule "writes" {
  endpoint = https.api
  approve  = [human_approver.ops]
}
`)
	return b.String()
}

func diagnosticsContain(diags hcl.Diagnostics, want string) bool {
	for _, diag := range diags {
		if diag == nil {
			continue
		}
		if strings.Contains(diag.Summary, want) || strings.Contains(diag.Detail, want) {
			return true
		}
	}
	return strings.Contains(diags.Error(), want)
}
