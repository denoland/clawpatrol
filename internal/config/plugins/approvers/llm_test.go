package approvers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestLLMClassifierSystemUsesGenericSummaryContract(t *testing.T) {
	for _, want := range []string{`"subject"`, `"label"`, `"confidence"`, `"summary"`} {
		if !strings.Contains(llmClassifierSystem, want) {
			t.Fatalf("llmClassifierSystem missing %s:\n%s", want, llmClassifierSystem)
		}
	}
	for _, forbidden := range []string{"ticket" + "_id", "class" + "ification", "sup" + "port", "Sp" + "am", "Leg" + "it"} {
		if strings.Contains(llmClassifierSystem, forbidden) {
			t.Fatalf("llmClassifierSystem contains coupled term %q:\n%s", forbidden, llmClassifierSystem)
		}
	}
}

func TestHITLSummaryJSONContractUsesSubjectLabelSummary(t *testing.T) {
	var summary runtime.HITLSummary
	if err := json.Unmarshal([]byte(`{"subject":"POST /v1/messages","label":"Needs review","confidence":82,"summary":"Message changes customer-visible copy."}`), &summary); err != nil {
		t.Fatalf("unmarshal generic summary: %v", err)
	}
	if summary.Subject != "POST /v1/messages" {
		t.Fatalf("Subject = %q", summary.Subject)
	}
	if summary.Label != "Needs review" {
		t.Fatalf("Label = %q", summary.Label)
	}
	if summary.Confidence != 82 {
		t.Fatalf("Confidence = %d", summary.Confidence)
	}
	if summary.Summary != "Message changes customer-visible copy." {
		t.Fatalf("Summary = %q", summary.Summary)
	}

	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal generic summary: %v", err)
	}
	for _, forbidden := range []string{"ticket" + "_id", "class" + "ification"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("marshaled summary contains legacy field %q: %s", forbidden, raw)
		}
	}
}

type failingSecrets struct{}

func (failingSecrets) Get(string) (runtime.Secret, error) {
	return runtime.Secret{}, errors.New("vault unreachable")
}

type nopHTTPCredential struct{}

func (nopHTTPCredential) InjectHTTP(context.Context, *http.Request, runtime.Secret) error {
	return nil
}

// Misconfiguration must deny outright rather than leave the decision
// to defaults.llm_fail_mode.
func TestLLMApproverUndecidedOnCallFailure(t *testing.T) {
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{
		"judge": {Body: nopHTTPCredential{}},
	}}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	v, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: failingSecrets{}})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// A declared credential whose secret cannot be fetched is the
	// gateway's misconfiguration, not a judge outage: deny, never
	// fail open.
	if v.Decision != "deny" {
		t.Fatalf("Decision = %q, want deny", v.Decision)
	}
	if !strings.HasPrefix(v.Reason, "secret fetch: ") {
		t.Fatalf("Reason = %q", v.Reason)
	}

	misconfigured := &LLMApprover{Model: "claude-test", Credential: "missing"}
	v, err = misconfigured.Approve(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: failingSecrets{}})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if v.Decision != "deny" {
		t.Fatalf("misconfigured Decision = %q, want deny", v.Decision)
	}
}

func TestLLMStatusIsOutage(t *testing.T) {
	for status, outage := range map[int]bool{
		429: true, 500: true, 502: true, 503: true,
		400: false, 401: false, 403: false, 404: false, 422: false,
	} {
		if got := llmStatusIsOutage(status); got != outage {
			t.Errorf("llmStatusIsOutage(%d) = %v, want %v", status, got, outage)
		}
	}
}
