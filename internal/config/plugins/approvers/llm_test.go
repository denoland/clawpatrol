package approvers

import (
	"encoding/json"
	"strings"
	"testing"

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
